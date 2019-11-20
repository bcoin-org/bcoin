/**
 * mrmr.cc
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <node.h>
#include <nan.h>

#include "murmur3.h"
#include "mrmr.h"

NAN_METHOD(murmur3_sum) {
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
    Nan::New<v8::Uint32>(mrmr_murmur3_sum(data, len, seed)));
}

NAN_METHOD(murmur3_tweak) {
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
    Nan::New<v8::Uint32>(mrmr_murmur3_tweak(data, len, n, tweak)));
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "murmur3_sum", murmur3_sum);
  Nan::Export(target, "murmur3_tweak", murmur3_tweak);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(mrmr, init)
#else
NODE_MODULE(mrmr, init)
#endif
