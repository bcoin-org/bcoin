/**
 * bstring
 * Copyright (c) 2016, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <node.h>
#include <nan.h>

#include "base58.h"
#include "bech32.h"
#include "cashaddr.h"
#include "bstring.h"

NAN_METHOD(base58_encode) {
  if (info.Length() < 1)
    return Nan::ThrowError("base58_encode() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  uint8_t *str;
  size_t slen;

  if (!bstring_base58_encode(data, len, &str, &slen))
    return Nan::ThrowError("Base58 encoding failed.");

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)str, slen).ToLocalChecked());

  free(str);
}

NAN_METHOD(base58_decode) {
  if (info.Length() < 1)
    return Nan::ThrowError("base58_decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String str_(info[0]);
  const uint8_t *str = (const uint8_t *)*str_;
  size_t len = str_.length();

  uint8_t *data;
  size_t dlen;

  if (!bstring_base58_decode(str, len, &data, &dlen))
    return Nan::ThrowError("Invalid base58 string.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)data, dlen).ToLocalChecked());
}

NAN_METHOD(base58_test) {
  if (info.Length() < 1 || !info[0]->IsString()) {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    return;
  }

  Nan::Utf8String str_(info[0]);
  const uint8_t *str = (const uint8_t *)*str_;
  size_t len = str_.length();

  bool result = bstring_base58_test(str, len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(bech32_serialize) {
  if (info.Length() < 2)
    return Nan::ThrowError("bech32_serialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String hstr(info[0]);

  v8::Local<v8::Object> dbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const char *hrp = (const char *)*hstr;
  const uint8_t *data = (uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);

  char output[93];
  size_t olen;

  if (!bstring_bech32_serialize(output, hrp, data, data_len))
    return Nan::ThrowError("Bech32 encoding failed.");

  olen = strlen((char *)output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)output, olen).ToLocalChecked());
}

NAN_METHOD(bech32_deserialize) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32_deserialize() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String input_(info[0]);
  const char *input = (const char *)*input_;

  uint8_t data[84];
  size_t data_len;
  char hrp[84];
  size_t hlen;

  if (!bstring_bech32_deserialize(hrp, data, &data_len, input))
    return Nan::ThrowError("Invalid bech32 string.");

  hlen = strlen((char *)&hrp[0]);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::String>((char *)&hrp[0], hlen).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)&data[0], data_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(bech32_is) {
  if (info.Length() < 1 || !info[0]->IsString()) {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    return;
  }

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  bool result = bstring_bech32_is(addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(bech32_convert_bits) {
  if (info.Length() < 4)
    return Nan::ThrowError("bech32_convert_bits() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsBoolean())
    return Nan::ThrowTypeError("Fourth argument must be a boolean.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);
  int frombits = (int)Nan::To<int32_t>(info[1]).FromJust();
  int tobits = (int)Nan::To<int32_t>(info[2]).FromJust();
  int pad = (int)Nan::To<bool>(info[3]).FromJust();

  if (!(frombits == 8 && tobits == 5 && pad == 1)
      && !(frombits == 5 && tobits == 8 && pad == 0)) {
    return Nan::ThrowRangeError("Parameters out of range.");
  }

  size_t size = (data_len * frombits + (tobits - 1)) / tobits;

  if (pad)
    size += 1;

  uint8_t *out = (uint8_t *)malloc(size);
  size_t out_len = 0;
  bool ret;

  if (!out)
    return Nan::ThrowError("Could not allocate.");

  ret = bstring_bech32_convert_bits(
    out,
    &out_len,
    tobits,
    data,
    data_len,
    frombits,
    pad
  );

  if (!ret)
    return Nan::ThrowError("Invalid bits.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(bech32_encode) {
  if (info.Length() < 3)
    return Nan::ThrowError("bech32_encode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String hstr(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> wbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(wbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *hrp = (const char *)*hstr;
  int witver = (int)Nan::To<int32_t>(info[1]).FromJust();

  const uint8_t *witprog = (uint8_t *)node::Buffer::Data(wbuf);
  size_t witprog_len = node::Buffer::Length(wbuf);

  char output[93];
  size_t olen;

  if (!bstring_bech32_encode(output, hrp, witver, witprog, witprog_len))
    return Nan::ThrowError("Bech32 encoding failed.");

  olen = strlen((char *)output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)output, olen).ToLocalChecked());
}

NAN_METHOD(bech32_decode) {
  if (info.Length() < 1)
    return Nan::ThrowError("bech32_decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  uint8_t witprog[40];
  size_t witprog_len;
  int witver;
  char hrp[84];
  size_t hlen;

  if (!bstring_bech32_decode(&witver, witprog, &witprog_len, hrp, addr))
    return Nan::ThrowError("Invalid bech32 string.");

  hlen = strlen((char *)&hrp[0]);

  v8::Local<v8::Object> ret = Nan::New<v8::Object>();

  Nan::Set(ret,
    Nan::New<v8::String>("hrp").ToLocalChecked(),
    Nan::New<v8::String>((char *)&hrp[0], hlen).ToLocalChecked());

  Nan::Set(ret,
    Nan::New<v8::String>("version").ToLocalChecked(),
    Nan::New<v8::Number>(witver));

  Nan::Set(ret,
    Nan::New<v8::String>("hash").ToLocalChecked(),
    Nan::CopyBuffer((char *)&witprog[0], witprog_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(bech32_test) {
  if (info.Length() < 1 || !info[0]->IsString()) {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    return;
  }

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  bool result = bstring_bech32_test(addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(cashaddr_encode) {
  if (info.Length() < 3)
    return Nan::ThrowError("cashaddr_encode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String prefix_str(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Invalid cashaddr type.");

  v8::Local<v8::Object> hashbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(hashbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *prefix = (const char *)*prefix_str;
  int type = (int)Nan::To<int32_t>(info[1]).FromJust();

  const uint8_t *hash = (uint8_t *)node::Buffer::Data(hashbuf);
  size_t hash_len = node::Buffer::Length(hashbuf);

  char output[197];
  memset(&output, 0, 197);
  size_t olen = 0;

  bstring_cashaddr_error err = bstring_cashaddr_ERR_NULL;

  if (!bstring_cashaddr_encode(&err, output, prefix, type, hash, hash_len))
    return Nan::ThrowError(bstring_cashaddr_strerror(err));

  olen = strlen((char *)output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)output, olen).ToLocalChecked());
}

NAN_METHOD(cashaddr_decode) {
  if (info.Length() < 2)
    return Nan::ThrowError("cashaddr_decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  Nan::Utf8String default_prefix_(info[1]);
  const char *default_prefix = (const char *)*default_prefix_;

  uint8_t hash[65];
  memset(hash, 0, 65);
  size_t hash_len;
  int type;
  char prefix[84];
  memset(prefix, 0, 84);
  size_t prefix_len;

  bstring_cashaddr_error err = bstring_cashaddr_ERR_NULL;

  if (!bstring_cashaddr_decode(&err, &type, hash, &hash_len, prefix, default_prefix, addr))
    return Nan::ThrowError(bstring_cashaddr_strerror(err));

  prefix_len = strlen((char *)&prefix[0]);

  v8::Local<v8::Object> ret = Nan::New<v8::Object>();

  Nan::Set(ret,
    Nan::New<v8::String>("prefix").ToLocalChecked(),
    Nan::New<v8::String>((char *)&prefix[0], prefix_len).ToLocalChecked());

  Nan::Set(ret,
    Nan::New<v8::String>("type").ToLocalChecked(),
    Nan::New<v8::Number>(type));

  Nan::Set(ret,
    Nan::New<v8::String>("hash").ToLocalChecked(),
    Nan::CopyBuffer((char *)&hash[0], hash_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(cashaddr_test) {
  if (info.Length() < 2 || !info[0]->IsString()) {
    info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    return;
  }

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  Nan::Utf8String default_prefix_(info[1]);
  const char *default_prefix = (const char *)*default_prefix_;

  bstring_cashaddr_error err = bstring_cashaddr_ERR_NULL;

  bool result = bstring_cashaddr_test(&err, default_prefix, addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "base58_encode", base58_encode);
  Nan::Export(target, "base58_decode", base58_decode);
  Nan::Export(target, "base58_test", base58_test);
  Nan::Export(target, "bech32_serialize", bech32_serialize);
  Nan::Export(target, "bech32_deserialize", bech32_deserialize);
  Nan::Export(target, "bech32_is", bech32_is);
  Nan::Export(target, "bech32_convert_bits", bech32_convert_bits);
  Nan::Export(target, "bech32_encode", bech32_encode);
  Nan::Export(target, "bech32_decode", bech32_decode);
  Nan::Export(target, "bech32_test", bech32_test);
  Nan::Export(target, "cashaddr_encode", cashaddr_encode);
  Nan::Export(target, "cashaddr_decode", cashaddr_decode);
  Nan::Export(target, "cashaddr_test", cashaddr_test);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(bstring, init)
#else
NODE_MODULE(bstring, init)
#endif
