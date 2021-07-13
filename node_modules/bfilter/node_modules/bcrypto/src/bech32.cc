#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "bech32/bech32.h"
#include "bech32.h"

void
BBech32::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "serialize", BBech32::Serialize);
  Nan::Export(obj, "deserialize", BBech32::Deserialize);
  Nan::Export(obj, "is", BBech32::Is);
  Nan::Export(obj, "convertBits", BBech32::ConvertBits);
  Nan::Export(obj, "encode", BBech32::Encode);
  Nan::Export(obj, "decode", BBech32::Decode);
  Nan::Export(obj, "test", BBech32::Test);

  Nan::Set(target, Nan::New("bech32").ToLocalChecked(), obj);
}

NAN_METHOD(BBech32::Serialize) {
  if (info.Length() < 2)
    return Nan::ThrowError("bech32.serialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String hrp_str(info[0]);

  v8::Local<v8::Object> data_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const char *hrp = (const char *)*hrp_str;
  const uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  char output[93];
  size_t output_len;

  if (!bcrypto_bech32_serialize(output, hrp, data, data_len))
    return Nan::ThrowError("Bech32 encoding failed.");

  output_len = strlen(output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>(output, output_len).ToLocalChecked());
}

NAN_METHOD(BBech32::Deserialize) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32.deserialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String input_(info[0]);
  const char *input = (const char *)*input_;

  uint8_t data[84];
  size_t data_len;
  char hrp[84];
  size_t hrp_len;

  if (!bcrypto_bech32_deserialize(hrp, data, &data_len, input))
    return Nan::ThrowError("Invalid bech32 string.");

  hrp_len = strlen(hrp);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::New<v8::String>(hrp, hrp_len).ToLocalChecked());

  Nan::Set(ret, 1,
    Nan::CopyBuffer((char *)data, data_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BBech32::Is) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32.is() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  bool result = bcrypto_bech32_is(addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BBech32::ConvertBits) {
  if (info.Length() < 4)
    return Nan::ThrowError("bech32.convertBits() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsBoolean())
    return Nan::ThrowTypeError("Fourth argument must be a boolean.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);
  int frombits = (int)Nan::To<int32_t>(info[1]).FromJust();
  int tobits = (int)Nan::To<int32_t>(info[2]).FromJust();
  int pad = (int)Nan::To<bool>(info[3]).FromJust();

  if (frombits < 0 || frombits > 0xff || frombits == 0
      || tobits < 0 || tobits > 0xff || tobits == 0) {
    return Nan::ThrowRangeError("Parameters out of range.");
  }

  size_t size = (data_len * frombits + (tobits - 1)) / tobits;

  if (pad)
    size += 1;

  uint8_t *output = (uint8_t *)malloc(size);
  size_t output_len = 0;

  if (output == NULL)
    return Nan::ThrowError("Could not allocate.");

  if (!bcrypto_bech32_convert_bits(output, &output_len, tobits,
                                   data, data_len, frombits, pad)) {
    return Nan::ThrowError("Invalid bits.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)output, output_len).ToLocalChecked());
}

NAN_METHOD(BBech32::Encode) {
  if (info.Length() < 3)
    return Nan::ThrowError("bech32.encode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String hrp_str(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> witprog_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(witprog_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *hrp = (const char *)*hrp_str;
  int witver = (int)Nan::To<int32_t>(info[1]).FromJust();

  const uint8_t *witprog = (uint8_t *)node::Buffer::Data(witprog_buf);
  size_t witprog_len = node::Buffer::Length(witprog_buf);

  char output[93];
  size_t output_len;

  if (!bcrypto_bech32_encode(output, hrp, witver, witprog, witprog_len))
    return Nan::ThrowError("Bech32 encoding failed.");

  output_len = strlen(output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>(output, output_len).ToLocalChecked());
}

NAN_METHOD(BBech32::Decode) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32.decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  uint8_t witprog[40];
  size_t witprog_len;
  int witver;
  char hrp[84];
  size_t hrp_len;

  if (!bcrypto_bech32_decode(&witver, witprog, &witprog_len, hrp, addr))
    return Nan::ThrowError("Invalid bech32 string.");

  hrp_len = strlen(hrp);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::New<v8::String>(hrp, hrp_len).ToLocalChecked());

  Nan::Set(ret, 1, Nan::New<v8::Number>(witver));

  Nan::Set(ret, 2,
    Nan::CopyBuffer((char *)witprog, witprog_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BBech32::Test) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32.test() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  bool result = bcrypto_bech32_test(addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
