#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/siphash.h>

#include "common.h"
#include "siphash.h"

void
BSiphash::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "siphash", BSiphash::Siphash);
  Nan::Export(obj, "siphash32", BSiphash::Siphash32);
  Nan::Export(obj, "siphash64", BSiphash::Siphash64);
  Nan::Export(obj, "siphash32k256", BSiphash::Siphash32k256);
  Nan::Export(obj, "siphash64k256", BSiphash::Siphash64k256);
  Nan::Export(obj, "sipmod", BSiphash::Sipmod);

  Nan::Set(target, Nan::New("siphash").ToLocalChecked(), obj);
}

NAN_METHOD(BSiphash::Siphash) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash.siphash() requires arguments.");

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
    return Nan::ThrowRangeError("Bad key size for siphash.");

  uint64_t result = siphash(data, len, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((uint32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((uint32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSiphash::Siphash32) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash.siphash32() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  uint32_t num = Nan::To<uint32_t>(info[0]).FromJust();

  const uint8_t *kdata = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen < 16)
    return Nan::ThrowRangeError("Bad key size for siphash.");

  uint32_t result = siphash32(num, kdata);

  info.GetReturnValue().Set(Nan::New<v8::Int32>(result));
}

NAN_METHOD(BSiphash::Siphash64) {
  if (info.Length() < 3)
    return Nan::ThrowError("siphash.siphash64() requires arguments.");

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
    return Nan::ThrowRangeError("Bad key size for siphash.");

  uint64_t result = siphash64(num, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((uint32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((uint32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSiphash::Siphash32k256) {
  if (info.Length() < 2)
    return Nan::ThrowError("siphash.siphash32k256() requires arguments.");

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

  uint32_t result = siphash32k256(num, kdata);

  info.GetReturnValue().Set(Nan::New<v8::Int32>(result));
}

NAN_METHOD(BSiphash::Siphash64k256) {
  if (info.Length() < 3)
    return Nan::ThrowError("siphash.siphash64k256() requires arguments.");

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
    return Nan::ThrowRangeError("Bad key size for siphash.");

  uint64_t result = siphash64k256(num, kdata);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((uint32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((uint32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSiphash::Sipmod) {
  if (info.Length() < 4)
    return Nan::ThrowError("siphash.sipmod() requires arguments.");

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
    return Nan::ThrowRangeError("Bad key size for siphash.");

  const uint32_t mhi = Nan::To<uint32_t>(info[2]).FromJust();
  const uint32_t mlo = Nan::To<uint32_t>(info[3]).FromJust();
  const uint64_t m = ((uint64_t)mhi << 32) | mlo;

  uint64_t result = sipmod(data, len, kdata, m);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::New<v8::Int32>((uint32_t)(result >> 32)));
  Nan::Set(ret, 1, Nan::New<v8::Int32>((uint32_t)(result & 0xffffffff)));

  info.GetReturnValue().Set(ret);
}
