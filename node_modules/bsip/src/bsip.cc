/**
 * bsip.cc
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <node.h>
#include <nan.h>

#include "siphash.h"

NAN_METHOD(siphash) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  uint64_t result = bsip_siphash(data, len, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(siphash32) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash32() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  uint32_t num = Nan::To<uint32_t>(info[0]).FromJust();

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  uint32_t result = bsip_siphash32(num, kdata);

  info.GetReturnValue().Set(Nan::New<v8::Int32>(result));
}

NAN_METHOD(siphash64) {
  if (info.Length() < 3)
    return Nan::ThrowError("siphash64() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  uint32_t hi = Nan::To<uint32_t>(info[0]).FromJust();
  uint32_t lo = Nan::To<uint32_t>(info[1]).FromJust();
  uint64_t num = ((uint64_t)hi << 32) | lo;

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  uint64_t result = bsip_siphash64(num, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(siphash32k256) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash32k256() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  uint32_t num = Nan::To<uint32_t>(info[0]).FromJust();

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 32)
    return Nan::ThrowError("Bad key size for siphash.");

  uint32_t result = bsip_siphash32k256(num, kdata);

  info.GetReturnValue().Set(Nan::New<v8::Int32>(result));
}

NAN_METHOD(siphash64k256) {
  if (info.Length() < 3)
    return Nan::ThrowError("siphash64k256() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  uint32_t hi = Nan::To<uint32_t>(info[0]).FromJust();
  uint32_t lo = Nan::To<uint32_t>(info[1]).FromJust();
  uint64_t num = ((uint64_t)hi << 32) | lo;

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 32)
    return Nan::ThrowError("Bad key size for siphash.");

  uint64_t result = bsip_siphash64k256(num, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(sipmod) {
  if (info.Length() < 4)
    return Nan::ThrowError("sipmod() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowError("Bad key size for siphash.");

  const uint32_t mhi = Nan::To<uint32_t>(info[2]).FromJust();
  const uint32_t mlo = Nan::To<uint32_t>(info[3]).FromJust();
  const uint64_t m = ((uint64_t)mhi << 32) | mlo;

  uint64_t result = bsip_sipmod(data, len, kdata, m);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((int32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((int32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "siphash", siphash);
  Nan::Export(target, "siphash256", siphash); // compat
  Nan::Export(target, "siphash32", siphash32);
  Nan::Export(target, "siphash64", siphash64);
  Nan::Export(target, "siphash32k256", siphash32k256);
  Nan::Export(target, "siphash64k256", siphash64k256);
  Nan::Export(target, "sipmod", sipmod);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(bsip, init)
#else
NODE_MODULE(bsip, init)
#endif
