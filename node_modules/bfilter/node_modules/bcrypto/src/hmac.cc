#include <torsion/util.h>

#include "common.h"
#include "hmac.h"

static Nan::Persistent<v8::FunctionTemplate> hmac_constructor;

BHMAC::BHMAC() {
  type = -1;
  started = false;
}

BHMAC::~BHMAC() {}

void
BHMAC::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHMAC::New);

  hmac_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("HMAC").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHMAC::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHMAC::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHMAC::Final);
  Nan::SetMethod(tpl, "digest", BHMAC::Digest);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hmac_constructor);

  Nan::Set(target, Nan::New("HMAC").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BHMAC::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create HMAC instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("HMAC() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  BHMAC *hmac = new BHMAC();
  hmac->type = type;
  hmac->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHMAC::Init) {
  BHMAC *hmac = ObjectWrap::Unwrap<BHMAC>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hmac.init() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(buf);
  size_t keylen = node::Buffer::Length(buf);

  hmac_init(&hmac->ctx, hmac->type, key, keylen);
  hmac->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHMAC::Update) {
  BHMAC *hmac = ObjectWrap::Unwrap<BHMAC>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hmac.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!hmac->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  hmac_update(&hmac->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHMAC::Final) {
  BHMAC *hmac = ObjectWrap::Unwrap<BHMAC>(info.Holder());

  if (!hmac->started)
    return Nan::ThrowError("Context is not initialized.");

  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(hmac->type);

  hmac_final(&hmac->ctx, out);
  hmac->started = false;

  cleanse(&hmac->ctx, sizeof(hmac->ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}

NAN_METHOD(BHMAC::Digest) {
  if (info.Length() < 3)
    return Nan::ThrowError("HMAC.digest() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> data_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(type);
  hmac_t ctx;

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  hmac_init(&ctx, type, key, key_len);
  hmac_update(&ctx, data, data_len);
  hmac_final(&ctx, out);

  cleanse(&ctx, sizeof(ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}
