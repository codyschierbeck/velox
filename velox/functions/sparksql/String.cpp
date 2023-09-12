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
#include "velox/expression/VectorFunction.h"
#include "velox/functions/lib/StringEncodingUtils.h"
#include "velox/functions/lib/string/StringCore.h"
#include "velox/expression/VectorReaders.h"
#include "velox/expression/VectorWriters.h"

namespace facebook::velox::functions::sparksql {

using namespace stringCore;
namespace {

template <bool isAscii>
int32_t instr(
    const folly::StringPiece haystack,
    const folly::StringPiece needle) {
  int32_t offset = haystack.find(needle);
  if constexpr (isAscii) {
    return offset + 1;
  } else {
    // If the string is unicode, convert the byte offset to a codepoints.
    return offset == -1 ? 0 : lengthUnicode(haystack.data(), offset) + 1;
  }
}

class Instr : public exec::VectorFunction {
  bool ensureStringEncodingSetAtAllInputs() const override {
    return true;
  }

  void apply(
      const SelectivityVector& selected,
      std::vector<VectorPtr>& args,
      const TypePtr& /* outputType */,
      exec::EvalCtx& context,
      VectorPtr& result) const override {
    VELOX_CHECK_EQ(args.size(), 2);
    VELOX_CHECK_EQ(args[0]->typeKind(), TypeKind::VARCHAR);
    VELOX_CHECK_EQ(args[1]->typeKind(), TypeKind::VARCHAR);
    exec::LocalDecodedVector haystack(context, *args[0], selected);
    exec::LocalDecodedVector needle(context, *args[1], selected);
    context.ensureWritable(selected, INTEGER(), result);
    auto* output = result->as<FlatVector<int32_t>>();

    if (isAscii(args[0].get(), selected)) {
      selected.applyToSelected([&](vector_size_t row) {
        auto h = haystack->valueAt<StringView>(row);
        auto n = needle->valueAt<StringView>(row);
        output->set(row, instr<true>(h, n));
      });
    } else {
      selected.applyToSelected([&](vector_size_t row) {
        auto h = haystack->valueAt<StringView>(row);
        auto n = needle->valueAt<StringView>(row);
        output->set(row, instr<false>(h, n));
      });
    }
  }
};

enum class Charset {
  UTF_8,
  US_ASCII,
  ISO_8859_1,
  UTF_16BE,
  UTF_16LE,
  UTF_16,
  UNKNOWN
};

Charset stringToCharset(const folly::StringPiece format) {
  if (format == "utf-8") return Charset::UTF_8;
  if (format == "US-ASCII") return Charset::US_ASCII;
  if (format == "ISO-8859-1") return Charset::ISO_8859_1;
  if (format == "UTF-16BE") return Charset::UTF_16BE;
  if (format == "UTF-16LE") return Charset::UTF_16LE;
  if (format == "UTF-16") return Charset::UTF_16;
  return Charset::UNKNOWN;
}


std::string encodeBytes(
  std::vector<int64_t> bytes,
  Charset format) {
    switch (format){
      case Charset::UTF_8: {
        std::string result;
        for(int64_t byte : bytes) {
          result.push_back(static_cast<char>(byte));
        }
        return result;
      }
     case Charset::US_ASCII:
      // ... handle US-ASCII ...
      break;
    case Charset::ISO_8859_1:
      // ... handle ISO-8859-1 ...
      break;
    case Charset::UTF_16BE:
      break;
    case Charset::UTF_16LE:
      break;
    case Charset::UTF_16: {
      break;
    }
    default:
      break;
    }
    return "Fail";
  }

std::vector<int64_t> decodeString(
  std::string input,
  Charset format) {
    std::vector<int64_t> result;

    switch (format) {
      case Charset::UTF_8: {
        for(char c : input) {
          result.push_back(static_cast<int64_t>(c));
        }
        break;
      }
      case Charset::US_ASCII:
        // ... handle US-ASCII ...
        break;
      case Charset::ISO_8859_1:
        // ... handle ISO-8859-1 ...
        break;
      case Charset::UTF_16BE:
        // ... handle UTF-16BE ...
        break;
      case Charset::UTF_16LE:
        // ... handle UTF-16LE ...
        break;
      case Charset::UTF_16:
        // ... handle UTF-16 ...
        break;
      default:
        // ... handle other charsets or raise an error ...
        break;
    }

    return result;
}


template <bool encode>
class CharsetConverter : public exec::VectorFunction {
  // ... similar override methods to ensure string encoding ...

  void apply(
      const SelectivityVector& selected,
      std::vector<VectorPtr>& args,
      const TypePtr& /* outputType */,
      exec::EvalCtx& context,
      VectorPtr& result) const override {

    VELOX_CHECK_EQ(args.size(), 2);
    VELOX_CHECK(
        args[0]->typeKind() == TypeKind::VARCHAR ||
        args[0]->typeKind() == TypeKind::ARRAY);
    VELOX_CHECK_EQ(args[1]->typeKind(), TypeKind::VARCHAR);

    DecodedVector decoded;
    decoded.decode(*args[0], selected);

    exec::LocalDecodedVector input(context, *args[0], selected);
    exec::LocalDecodedVector format(context, *args[1], selected);
    auto fStr = format->valueAt<StringView>(0);
    Charset f  = stringToCharset(fStr);

    if (!encode){
      context.ensureWritable(selected, ARRAY(BIGINT()), result);
      exec::VectorWriter<Array<int64_t>> resultWriter;
      resultWriter.init(*result->as<ArrayVector>());
      selected.applyToSelected([&](vector_size_t row) {
        resultWriter.setOffset(row);
        auto& arrayWriter = resultWriter.current();
        const StringView& current = input->valueAt<StringView>(row);
        std::string strValue = current.getString();
        std::vector<int64_t> bytes = decodeString(current, f);
        for (auto byte : bytes) {
          arrayWriter.push_back(byte);
        }
        // Indicate writing for the row is done
        resultWriter.commit();
      });
      // Indicate writing for the vector is done
      resultWriter.finish();
    } else {
      context.ensureWritable(selected, VARCHAR(), result);
      // The native type of VARBINARY is also a StringView
      auto* output = result->as<FlatVector<StringView>>();
      exec::VectorReader<Array<int64_t>> reader(&decoded);
      std::vector<int64_t> bytes = {};
      selected.applyToSelected([&](vector_size_t row) {
        if (reader.isSet(row) == false){
          return;
        }
        auto arrayView = reader[row];
        for (const auto& container : arrayView) {
          if (container.has_value()){
            bytes.push_back(container.value());
          }
        }
        std::string ans = encodeBytes(bytes, f);
        const StringView& answerStringView = StringView(ans.c_str());
        output->set(row, answerStringView);
      });
    }


  }
};

class Length : public exec::VectorFunction {
  bool ensureStringEncodingSetAtAllInputs() const override {
    return true;
  }

  void apply(
      const SelectivityVector& selected,
      std::vector<VectorPtr>& args,
      const TypePtr& /* outputType */,
      exec::EvalCtx& context,
      VectorPtr& result) const override {
    VELOX_CHECK_EQ(args.size(), 1);
    VELOX_CHECK(
        args[0]->typeKind() == TypeKind::VARCHAR ||
        args[0]->typeKind() == TypeKind::VARBINARY);
    exec::LocalDecodedVector input(context, *args[0], selected);
    context.ensureWritable(selected, INTEGER(), result);
    auto* output = result->as<FlatVector<int32_t>>();

    if (args[0]->typeKind() == TypeKind::VARCHAR &&
        !isAscii(args[0].get(), selected)) {
      selected.applyToSelected([&](vector_size_t row) {
        const StringView str = input->valueAt<StringView>(row);
        output->set(row, lengthUnicode(str.data(), str.size()));
      });
    } else {
      selected.applyToSelected([&](vector_size_t row) {
        output->set(row, input->valueAt<StringView>(row).size());
      });
    }
  }
};

} // namespace

std::vector<std::shared_ptr<exec::FunctionSignature>> instrSignatures() {
  return {
      exec::FunctionSignatureBuilder()
          .returnType("INTEGER")
          .argumentType("VARCHAR")
          .argumentType("VARCHAR")
          .build(),
  };
}

std::shared_ptr<exec::VectorFunction> makeInstr(
    const std::string& name,
    const std::vector<exec::VectorFunctionArg>& inputArgs,
    const core::QueryConfig& /*config*/) {
  static const auto kInstrFunction = std::make_shared<Instr>();
  return kInstrFunction;
}

std::vector<std::shared_ptr<exec::FunctionSignature>> lengthSignatures() {
  return {
      exec::FunctionSignatureBuilder()
          .returnType("INTEGER")
          .argumentType("VARCHAR")
          .build(),
      exec::FunctionSignatureBuilder()
          .returnType("INTEGER")
          .argumentType("VARBINARY")
          .build(),
  };
}

std::shared_ptr<exec::VectorFunction> makeLength(
    const std::string& name,
    const std::vector<exec::VectorFunctionArg>& inputArgs,
    const core::QueryConfig& /*config*/) {
  static const auto kLengthFunction = std::make_shared<Length>();
  return kLengthFunction;
}

void encodeDigestToBase16(uint8_t* output, int digestSize) {
  static unsigned char const kHexCodes[] = "0123456789abcdef";
  for (int i = digestSize - 1; i >= 0; --i) {
    int digestChar = output[i];
    output[i * 2] = kHexCodes[(digestChar >> 4) & 0xf];
    output[i * 2 + 1] = kHexCodes[digestChar & 0xf];
  }
}

std::vector<std::shared_ptr<exec::FunctionSignature>> encodeSignatures() {
  return {
    exec::FunctionSignatureBuilder()
    .returnType("VARCHAR")
    .argumentType("array(bigint)")
    .argumentType("VARCHAR")
    .build(),
  };
}
std::vector<std::shared_ptr<exec::FunctionSignature>> decodeSignatures() {
  return {
      exec::FunctionSignatureBuilder()
      .returnType("array(bigint)")
      .argumentType("VARCHAR")
      .argumentType("VARCHAR")
      .build(),
  };
}

template <bool encode>
std::shared_ptr<exec::VectorFunction> makeCharsetConvert(
  const std::string& name,
  const std::vector<exec::VectorFunctionArg>& inputArgs,
  const core::QueryConfig& /*config*/){
    static const auto charsetConvertFunction = std::make_shared<CharsetConverter<encode>>();
    return charsetConvertFunction;
}

// template std::shared_ptr<exec::VectorFunction> makeCharsetConvert<true>(
//   const std::string& name,
//   const std::vector<exec::VectorFunctionArg>& inputArgs,
//   const core::QueryConfig& config);
// template std::shared_ptr<exec::VectorFunction> makeCharsetConvert<false>(
//   const std::string& name,
//   const std::vector<exec::VectorFunctionArg>& inputArgs,
//   const core::QueryConfig& config);


std::shared_ptr<exec::VectorFunction> makeEncode(
  const std::string& name,
  const std::vector<exec::VectorFunctionArg>& inputArgs,
  const core::QueryConfig& config){
    return makeCharsetConvert<true>(name, inputArgs, config);
}
std::shared_ptr<exec::VectorFunction> makeDecode(
  const std::string& name,
  const std::vector<exec::VectorFunctionArg>& inputArgs,
  const core::QueryConfig& config){
    return makeCharsetConvert<false>(name, inputArgs, config);
}

} // namespace facebook::velox::functions::sparksql
