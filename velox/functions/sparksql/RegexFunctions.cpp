/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "velox/functions/lib/Re2Functions.h"
#include "velox/functions/lib/RegistrationHelpers.h"

#include "velox/common/base/Exceptions.h"
#include "velox/expression/VectorWriters.h"

namespace facebook::velox::functions::sparksql {
namespace {

using ::re2::RE2;

template <typename T>
re2::StringPiece toStringPiece(const T& s) {
  return re2::StringPiece(s.data(), s.size());
}

// If v is a non-null constant vector, returns the constant value. Otherwise
// returns nullopt.
template <typename T>
std::optional<T> getIfConstant(const BaseVector& v) {
  if (v.isConstantEncoding() && !v.isNullAt(0)) {
    return v.as<ConstantVector<T>>()->valueAt(0);
  }
  return std::nullopt;
}

void checkForBadPattern(const RE2& re) {
  if (UNLIKELY(!re.ok())) {
    VELOX_USER_FAIL("invalid regular expression:{}", re.error());
  }
}

/// Validates the provided regex pattern to ensure its compatibility with the
/// system. The function checks if the pattern uses features like character
/// class union, intersection, or difference which are not supported in C++ RE2
/// library but are supported in Java regex.
///
/// This function should be called on the indivdual patterns of a decoded
/// vector. That way when a single pattern in a vector is invalid, we can still
/// operate on the remaining rows.
///
/// @param pattern The regex pattern string to validate.
/// @param functionName (Optional) Name of the calling function to include in
/// error messages.
///
/// @throws VELOX_USER_FAIL If the pattern is found to use unsupported features.
/// @note  Default functionName is "regex_replace" because it uses non-constant
/// patterns so it cannot be checked with "ensureRegexIsCompatible". No
/// other functions work with non-constant patterns, but they may in the future.
///
/// @note Leaving functionName as an optional parameter makes room for
/// other functions to enable non-constant patterns in the future.
void checkForCompatiblePattern(
    const std::string& pattern,
    const char* functionName = "regex_replace") {
  // If in a character class, points to the [ at the beginning of that class.
  const char* charClassStart = nullptr;
  // This minimal regex parser looks just for the class begin/end markers.
  for (const char* c = pattern.data(); c < pattern.data() + pattern.size();
       ++c) {
    if (*c == '\\') {
      ++c;
    } else if (*c == '[') {
      if (charClassStart) {
        VELOX_USER_FAIL(
            "{} does not support character class union, intersection, "
            "or difference ([a[b]], [a&&[b]], [a&&[^b]])",
            functionName);
      }
      charClassStart = c;
      // A ] immediately after a [ does not end the character class, and is
      // instead adds the character ].
    } else if (*c == ']' && charClassStart + 1 != c) {
      charClassStart = nullptr;
    }
  }
}

// Blocks patterns that contain character class union, intersection, or
// difference because these are not understood by RE2 and will be parsed as a
// different pattern than in java.util.regex.
void ensureRegexIsCompatible(
    const char* functionName,
    const VectorPtr& patternVector) {
  if (!patternVector ||
      patternVector->encoding() != VectorEncoding::Simple::CONSTANT) {
    VELOX_USER_FAIL("{} requires a constant pattern.", functionName);
  }
  if (patternVector->isNullAt(0)) {
    return;
  }
  const StringView pattern =
      patternVector->as<ConstantVector<StringView>>()->valueAt(0);
  // Call the factored out function to check the pattern.
  checkForCompatiblePattern(
      std::string(pattern.data(), pattern.size()), functionName);
}

template <typename T>
struct regexReplaceFunction {
  VELOX_DEFINE_FUNCTION_TYPES(T);

  FOLLY_ALWAYS_INLINE bool call(
      out_type<Varchar>& result,
      const arg_type<Varchar>& string,
      const arg_type<Varchar>& pattern,
      const arg_type<Varchar>& replace) {
    checkForCompatiblePattern(pattern);
    re2::RE2 patternRE(toStringPiece(pattern));
    re2::StringPiece replaceSP = toStringPiece(replace);
    std::string stringS = std::string(string.data(), string.size());
    int replacements = RE2::GlobalReplace(&stringS, patternRE, replaceSP);
    result.resize(stringS.size());
    std::memcpy(result.data(), stringS.data(), stringS.size());
    return true;
  }

  FOLLY_ALWAYS_INLINE bool call(
      out_type<Varchar>& result,
      const arg_type<Varchar>& string,
      const arg_type<Varchar>& pattern,
      const arg_type<Varchar>& replace,
      const arg_type<int64_t>& position) {
    VELOX_CHECK(!(position - 1 < 0));
    checkForCompatiblePattern(pattern);
    re2::RE2 patternRE(toStringPiece(pattern));
    re2::StringPiece replaceSP = toStringPiece(replace);
    std::string stringS = std::string(string.data(), string.size());
    std::string prefix = stringS.substr(0, position - 1);
    if (position - 1 > stringS.length()) {
      stringS = "";
    } else {
      stringS = stringS.substr(position - 1);
    }
    int replacements = RE2::GlobalReplace(&stringS, patternRE, replaceSP);
    stringS = prefix + stringS;
    result.resize(stringS.size());
    std::memcpy(result.data(), stringS.data(), stringS.size());
    return true;
  }
};

} // namespace

// These functions delegate to the RE2-based implementations in
// common/RegexFunctions.h, but check to ensure that syntax that has different
// semantics between Spark (which uses java.util.regex) and RE2 throws an
// error.
std::shared_ptr<exec::VectorFunction> makeRLike(
    const std::string& name,
    const std::vector<exec::VectorFunctionArg>& inputArgs,
    const core::QueryConfig& config) {
  // Return any errors from re2Search() first.
  auto result = makeRe2Search(name, inputArgs, config);
  ensureRegexIsCompatible("RLIKE", inputArgs[1].constantValue);
  return result;
}

std::shared_ptr<exec::VectorFunction> makeRegexExtract(
    const std::string& name,
    const std::vector<exec::VectorFunctionArg>& inputArgs,
    const core::QueryConfig& config) {
  auto result = makeRe2Extract(name, inputArgs, config, /*emptyNoMatch=*/true);
  ensureRegexIsCompatible("REGEXP_EXTRACT", inputArgs[1].constantValue);
  return result;
}

void registerRegexReplace(const std::string& prefix) {
  registerFunction<regexReplaceFunction, Varchar, Varchar, Varchar, Varchar>(
      {prefix + "regex_replace"});
  registerFunction<
      regexReplaceFunction,
      Varchar,
      Varchar,
      Varchar,
      Varchar,
      int64_t>({prefix, "regex_replace"});
}

} // namespace facebook::velox::functions::sparksql
