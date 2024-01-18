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
#include <re2/stringpiece.h>
#include <folly/container/F14Map.h>
#include "velox/common/caching/SimpleLRUCache.h"
#include "velox/functions/lib/Re2Functions.h"

namespace facebook::velox::functions::sparksql {
namespace {

using ::re2::RE2;

template <typename T>
re2::StringPiece toStringPiece(const T& string) {
  return re2::StringPiece(string.data(), string.size());
}

void checkForBadPattern(const RE2& re) {
  if (UNLIKELY(!re.ok())) {
    VELOX_USER_FAIL("invalid regular expression:{}", re.error());
  }
}

// Validates the provided regex pattern to ensure its compatibility with the
// system. The function checks if the pattern uses features like character
// class union, intersection, or difference which are not supported in C++ RE2
// library but are supported in Java regex.
//
// This function should be called on the individual patterns of a decoded
// vector. That way when a single pattern in a vector is invalid, we can still
// operate on the remaining rows.
//
// @param pattern The regex pattern string to validate.
// @param functionName (Optional) Name of the calling function to include in
// error messages.
//
// @throws VELOX_USER_FAIL If the pattern is found to use unsupported features.
// @note  Default functionName is "REGEXP_REPLACE" because it uses non-constant
// patterns so it cannot be checked with "ensureRegexIsCompatible". No
// other functions work with non-constant patterns, but they may in the future.
//
// @note Leaving functionName as an optional parameter makes room for
// other functions to enable non-constant patterns in the future.
void checkForCompatiblePattern(
    const std::string& pattern,
    const char* functionName) {
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
void ensureRegexIsConstantAndCompatible(
    const char* functionName,
    const VectorPtr& patternVector) {
  if (!patternVector || !patternVector->isConstantEncoding()) {
    VELOX_USER_FAIL("{} requires a constant pattern.", functionName);
  }
  if (patternVector->isNullAt(0)) {
    return;
  }
  const StringView pattern =
      patternVector->as<ConstantVector<StringView>>()->valueAt(0);
  checkForCompatiblePattern(
      std::string(pattern.data(), pattern.size()), functionName);
}

// REGEXP_REPLACE(string, pattern, overwrite) → string
// REGEXP_REPLACE(string, pattern, overwrite, position) → string
//
// If a string has a substring that matches the given pattern, replace
// the match in the string wither overwrite and return the string. If
// optional paramter position is provided, only make replacements
// after that positon in the string (1 indexed).
//
// If position <= 0, throw error.
// If position > length string, return string.
template <typename T>
struct RegexpReplaceFunction {
  VELOX_DEFINE_FUNCTION_TYPES(T);

  using RegexLRUCache = SimpleLRUCache<std::string, std::shared_ptr<re2::RE2>>;

  RegexpReplaceFunction() : cache_(kMaxCompiledRegexes, 1) {}

  bool call(
      out_type<Varchar>& result,
      const arg_type<Varchar>& stringInput,
      const arg_type<Varchar>& pattern,
      const arg_type<Varchar>& replace) {
    return call(result, stringInput, pattern, replace, 1);
  }

  bool call(
      out_type<Varchar>& result,
      const arg_type<Varchar>& stringInput,
      const arg_type<Varchar>& pattern,
      const arg_type<Varchar>& replace,
      const arg_type<int64_t>& position) {
    if (position > int(stringInput.size()) + 1) {
      result = stringInput;
      return true;
    }

    VELOX_USER_CHECK_GE(position, 1, "regexp_replace requires a position >= 1");
    if (stringInput.size() == 0) {
      if (pattern.size() == 0 && position == 1) {
        result = replace;
        return true;
      }
      if (pattern.size() > 0) {
        result = stringInput;
        return true;
      }
    }
    size_t utf8Position =
        getUTFLength(stringInput.data(), stringInput.size(), position);

    std::shared_ptr<re2::RE2> patternRegex = getRegex(pattern.str());
    re2::StringPiece replaceStringPiece = toStringPiece(replace);


    if (utf8Position > stringInput.size() + 1) {
      result = stringInput;
      return true;
    }

    std::string prefix(stringInput.data(), utf8Position);
    std::string targetString(
        stringInput.data() + utf8Position, stringInput.size() - utf8Position);

    RE2::GlobalReplace(&targetString, *patternRegex, replaceStringPiece);

    if (targetString.size() || prefix.size()) {
      result = prefix + targetString;
      return true;
    }
    return false;
  }

 private:
  std::shared_ptr<re2::RE2> getFromCache_(const std::string& pattern) const {
    std::optional<std::shared_ptr<re2::RE2>> cachedRegex = cache_.get(pattern);
    if (cachedRegex) {
      return *cachedRegex;
    }
    return nullptr;
  }
  void addToCache_(const std::string& pattern, std::shared_ptr<re2::RE2> regex)
      const {
    cache_.add(pattern, regex);
  }
  void addToMap_(const std::string& pattern, std::shared_ptr<re2::RE2> regex)
      const {
    regexCache_.emplace(std::make_pair(pattern, regex));
  }
  std::shared_ptr<re2::RE2> getFromMap_(const std::string& pattern) const {
    auto it = regexCache_.find(pattern);
    if (it != regexCache_.end()) {
      return it->second;
    }
    return nullptr;
  }
  std::shared_ptr<re2::RE2> getRegex(const std::string& pattern) const {
    std::shared_ptr<re2::RE2> pReg = getFromCache_(pattern);
    if (pReg != nullptr) {
      return pReg;
    }

    // VELOX_USER_CHECK_LT(
    // regexCache_.size(),
    // kMaxCompiledRegexes,
    // "regexp_replace hit the maximum number of unique regexes: {}",
    // kMaxCompiledRegexes);

    checkForCompatiblePattern(pattern, "regexp_replace");
    std::shared_ptr<re2::RE2> patternRegex =
        std::make_shared<re2::RE2>(pattern);
    checkForBadPattern(*patternRegex.get());

    addToCache_(pattern, patternRegex);
    return patternRegex;
  }

  mutable RegexLRUCache cache_;
  mutable folly::F14FastMap<std::string, std::shared_ptr<re2::RE2>> regexCache_;

  size_t getUTFLength(const char* str, size_t len, size_t max_length) {
    // Adjust the position for UTF-8 by counting the code points.
    size_t utf8Position = 0;
    size_t numCodePoints = 0;
    while (numCodePoints < max_length - 1 && utf8Position <= len) {
      int charLength = utf8proc_char_length(str + utf8Position);
      VELOX_USER_CHECK_GT(
          charLength, 0, "regexp_replace encountered invalid UTF-8 character");
      ++numCodePoints;
      utf8Position += charLength;
    }
    return utf8Position;
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
  ensureRegexIsConstantAndCompatible("RLIKE", inputArgs[1].constantValue);
  return result;
}

std::shared_ptr<exec::VectorFunction> makeRegexExtract(
    const std::string& name,
    const std::vector<exec::VectorFunctionArg>& inputArgs,
    const core::QueryConfig& config) {
  auto result = makeRe2Extract(name, inputArgs, config, /*emptyNoMatch=*/true);
  ensureRegexIsConstantAndCompatible(
      "REGEXP_EXTRACT", inputArgs[1].constantValue);
  return result;
}

void registerRegexpReplace(const std::string& prefix) {
  registerFunction<RegexpReplaceFunction, Varchar, Varchar, Varchar, Varchar>(
      {prefix + "REGEXP_REPLACE"});
  registerFunction<
      RegexpReplaceFunction,
      Varchar,
      Varchar,
      Varchar,
      Varchar,
      int64_t>({prefix + "REGEXP_REPLACE"});
}

} // namespace facebook::velox::functions::sparksql
