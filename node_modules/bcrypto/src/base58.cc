#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "base58/base58.h"
#include "base58.h"

void
BBase58::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "encode", BBase58::Encode);
  Nan::Export(obj, "decode", BBase58::Decode);
  Nan::Export(obj, "test", BBase58::Test);

  Nan::Set(target, Nan::New("base58").ToLocalChecked(), obj);
}

NAN_METHOD(BBase58::Encode) {
  if (info.Length() < 1)
    return Nan::ThrowError("base58.encode() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  char *str;
  size_t slen;

  if (!bcrypto_base58_encode(&str, &slen, data, len))
    return Nan::ThrowError("Base58 encoding failed.");

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)str, slen).ToLocalChecked());

  free(str);
}

NAN_METHOD(BBase58::Decode) {
  if (info.Length() < 1)
    return Nan::ThrowError("base58.decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String str_(info[0]);
  const char *str = (const char *)*str_;
  size_t len = str_.length();

  uint8_t *data;
  size_t dlen;

  if (!bcrypto_base58_decode(&data, &dlen, str, len))
    return Nan::ThrowError("Invalid base58 string.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)data, dlen).ToLocalChecked());
}

NAN_METHOD(BBase58::Test) {
  if (info.Length() < 1)
    return Nan::ThrowError("base58.test() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String str_(info[0]);
  const char *str = (const char *)*str_;
  size_t len = str_.length();

  bool result = bcrypto_base58_test(str, len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
