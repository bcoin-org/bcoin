#include "common.h"
#include "poly1305.h"
#include <torsion/util.h>

static Nan::Persistent<v8::FunctionTemplate> poly1305_constructor;

BPoly1305::BPoly1305() {
  memset(&ctx, 0, sizeof(poly1305_t));
  started = false;
}

BPoly1305::~BPoly1305() {
  cleanse(&ctx, sizeof(poly1305_t));
}

void
BPoly1305::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BPoly1305::New);

  poly1305_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Poly1305").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BPoly1305::Init);
  Nan::SetPrototypeMethod(tpl, "update", BPoly1305::Update);
  Nan::SetPrototypeMethod(tpl, "final", BPoly1305::Final);
  Nan::SetPrototypeMethod(tpl, "destroy", BPoly1305::Destroy);
  Nan::SetPrototypeMethod(tpl, "verify", BPoly1305::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(poly1305_constructor);

  Nan::Set(target, Nan::New("Poly1305").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BPoly1305::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Poly1305 instance.");

  BPoly1305 *poly = new BPoly1305();
  poly->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BPoly1305::Init) {
  BPoly1305 *poly = ObjectWrap::Unwrap<BPoly1305>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("poly1305.init() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (len != 32)
    return Nan::ThrowRangeError("Invalid key size.");

  poly1305_init(&poly->ctx, data);
  poly->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BPoly1305::Update) {
  BPoly1305 *poly = ObjectWrap::Unwrap<BPoly1305>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("poly1305.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!poly->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  poly1305_update(&poly->ctx, data, len);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BPoly1305::Final) {
  BPoly1305 *poly = ObjectWrap::Unwrap<BPoly1305>(info.Holder());

  if (!poly->started)
    return Nan::ThrowError("Context is not initialized.");

  uint8_t mac[16];

  poly1305_final(&poly->ctx, &mac[0]);
  poly->started = false;

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&mac[0], 16).ToLocalChecked());
}

NAN_METHOD(BPoly1305::Destroy) {
  BPoly1305 *poly = ObjectWrap::Unwrap<BPoly1305>(info.Holder());

  poly->started = false;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BPoly1305::Verify) {
  BPoly1305 *poly = ObjectWrap::Unwrap<BPoly1305>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("poly1305.verify() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!poly->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *tag = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (len != 16)
    return Nan::ThrowRangeError("Invalid tag size.");

  uint8_t mac[16];

  poly1305_final(&poly->ctx, &mac[0]);
  poly->started = false;

  int result = poly1305_verify(&mac[0], tag);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>((bool)result));
}
