#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "random/random.h"
#include "random.h"

void
BRandom::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "randomFill", BRandom::RandomFill);

  Nan::Set(target, Nan::New("random").ToLocalChecked(), obj);
}

NAN_METHOD(BRandom::RandomFill) {
  if (info.Length() < 3)
    return Nan::ThrowError("random.randomFill() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t len = node::Buffer::Length(bdata);

  size_t pos = (size_t)Nan::To<int64_t>(info[1]).FromJust();
  size_t size = (size_t)Nan::To<int64_t>(info[2]).FromJust();

  if (((int32_t)len) < 0 || ((int32_t)pos) < 0 || ((int32_t)size) < 0)
    return Nan::ThrowRangeError("Invalid range.");

  if (pos + size > len)
    return Nan::ThrowError("Size exceeds length.");

  if (!bcrypto_random(&data[pos], size))
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(bdata);
}
