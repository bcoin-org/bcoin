#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "cash32/cash32.h"
#include "cash32.h"

void
BCash32::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "serialize", BCash32::Serialize);
  Nan::Export(obj, "deserialize", BCash32::Deserialize);
  Nan::Export(obj, "is", BCash32::Is);
  Nan::Export(obj, "convertBits", BCash32::ConvertBits);
  Nan::Export(obj, "encode", BCash32::Encode);
  Nan::Export(obj, "_decode", BCash32::Decode);
  Nan::Export(obj, "_test", BCash32::Test);

  Nan::Set(target, Nan::New("cash32").ToLocalChecked(), obj);
}

NAN_METHOD(BCash32::Serialize) {
  if (info.Length() < 2)
    return Nan::ThrowError("cash32.serialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String prefix_str(info[0]);

  v8::Local<v8::Object> data_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const char *prefix = (const char *)*prefix_str;
  const uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  char output[197];
  size_t output_len = 0;

  memset(output, 0, sizeof(output));

  if (!bcrypto_cash32_serialize(&err, output, prefix, data, data_len))
    return Nan::ThrowError(bcrypto_cash32_strerror(err));

  output_len = strlen(output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>(output, output_len).ToLocalChecked());
}

NAN_METHOD(BCash32::Deserialize) {
  if (info.Length() < 2)
    return Nan::ThrowError("cash32.deserialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  Nan::Utf8String default_prefix_str(info[1]);
  const char *default_prefix = (const char *)*default_prefix_str;

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  char prefix[84];
  size_t prefix_len;

  uint8_t data[188];
  size_t data_len = 0;

  memset(prefix, 0, sizeof(prefix));
  memset(data, 0, sizeof(data));

  if (!bcrypto_cash32_deserialize(&err, prefix, data,
                                    &data_len, default_prefix, addr)) {
    return Nan::ThrowError(bcrypto_cash32_strerror(err));
  }

  prefix_len = strlen(prefix);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::New<v8::String>(prefix, prefix_len).ToLocalChecked());

  Nan::Set(ret, 1,
    Nan::CopyBuffer((char *)data, data_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BCash32::Is) {
  if (info.Length() < 2)
    return Nan::ThrowError("cash32.is() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  Nan::Utf8String default_prefix_str(info[1]);
  const char *default_prefix = (const char *)*default_prefix_str;

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  bool result = bcrypto_cash32_is(&err, default_prefix, addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BCash32::ConvertBits) {
  if (info.Length() < 4)
    return Nan::ThrowError("cash32.convertBits() requires arguments.");

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

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  if (!bcrypto_cash32_convert_bits(&err, output, &output_len, tobits,
                                     data, data_len, frombits, pad)) {
    return Nan::ThrowError(bcrypto_cash32_strerror(err));
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)output, output_len).ToLocalChecked());
}

NAN_METHOD(BCash32::Encode) {
  if (info.Length() < 3)
    return Nan::ThrowError("cash32.encode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String prefix_str(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Invalid cash32 type.");

  v8::Local<v8::Object> hashbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(hashbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *prefix = (const char *)*prefix_str;
  int type = (int)Nan::To<int32_t>(info[1]).FromJust();
  double dbl = (double)Nan::To<double>(info[1]).FromJust();

  if (type < 0 || type > 15 || (double)type != dbl)
    return Nan::ThrowError("Invalid cash32 type.");

  const uint8_t *hash = (uint8_t *)node::Buffer::Data(hashbuf);
  size_t hash_len = node::Buffer::Length(hashbuf);

  char output[197];
  size_t output_len = 0;

  memset(output, 0, sizeof(output));

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  if (!bcrypto_cash32_encode(&err, output, prefix, type, hash, hash_len))
    return Nan::ThrowError(bcrypto_cash32_strerror(err));

  output_len = strlen(output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>(output, output_len).ToLocalChecked());
}

NAN_METHOD(BCash32::Decode) {
  if (info.Length() < 2)
    return Nan::ThrowError("cash32.decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  Nan::Utf8String default_prefix_str(info[1]);
  const char *default_prefix = (const char *)*default_prefix_str;

  uint8_t hash[64];
  size_t hash_len;
  int type;
  char prefix[84];
  size_t prefix_len;

  memset(hash, 0, sizeof(hash));
  memset(prefix, 0, sizeof(prefix));

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  if (!bcrypto_cash32_decode(&err, &type, hash, &hash_len,
                               prefix, default_prefix, addr)) {
    return Nan::ThrowError(bcrypto_cash32_strerror(err));
  }

  prefix_len = strlen(prefix);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0,
    Nan::New<v8::String>(prefix, prefix_len).ToLocalChecked());

  Nan::Set(ret, 1, Nan::New<v8::Number>(type));

  Nan::Set(ret, 2,
    Nan::CopyBuffer((char *)hash, hash_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BCash32::Test) {
  if (info.Length() < 2)
    return Nan::ThrowError("cash32.test() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_str(info[0]);
  const char *addr = (const char *)*addr_str;

  Nan::Utf8String default_prefix_str(info[1]);
  const char *default_prefix = (const char *)*default_prefix_str;

  bcrypto_cash32_error err = BCRYPTO_CASH32_ERR_NULL;

  bool result = bcrypto_cash32_test(&err, default_prefix, addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
