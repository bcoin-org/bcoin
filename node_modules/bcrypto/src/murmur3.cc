#include <stdint.h>
#include <stdlib.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "murmur3/murmur3.h"
#include "murmur3.h"

void
BMurmur3::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "sum", BMurmur3::Sum);
  Nan::Export(obj, "tweak", BMurmur3::Tweak);

  Nan::Set(target, Nan::New("murmur3").ToLocalChecked(), obj);
}

NAN_METHOD(BMurmur3::Sum) {
  if (info.Length() < 2)
    return Nan::ThrowError("murmur3.sum() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);
  uint32_t seed = Nan::To<uint32_t>(info[1]).FromJust();

  info.GetReturnValue().Set(
    Nan::New<v8::Uint32>(bcrypto_murmur3_sum(data, len, seed)));
}

NAN_METHOD(BMurmur3::Tweak) {
  if (info.Length() < 3)
    return Nan::ThrowError("murmur3.tweak() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);
  uint32_t n = Nan::To<uint32_t>(info[1]).FromJust();
  uint32_t tweak = Nan::To<uint32_t>(info[2]).FromJust();

  info.GetReturnValue().Set(
    Nan::New<v8::Uint32>(bcrypto_murmur3_tweak(data, len, n, tweak)));
}
