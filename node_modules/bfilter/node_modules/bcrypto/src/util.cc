#include <assert.h>
#include <node.h>
#include <nan.h>
#include <torsion/util.h>

#include "common.h"
#include "util.h"

void
BUtil::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "cleanse", BUtil::Cleanse);

  Nan::Set(target, Nan::New("util").ToLocalChecked(), obj);
}

NAN_METHOD(BUtil::Cleanse) {
  if (info.Length() < 1)
    return Nan::ThrowError("cleanse() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  cleanse((void *)data, len);
}
