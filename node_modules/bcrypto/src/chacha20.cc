#include "common.h"
#include "chacha20.h"
#include <torsion/util.h>

static Nan::Persistent<v8::FunctionTemplate> chacha20_constructor;

BChaCha20::BChaCha20() {
  memset(&ctx, 0, sizeof(chacha20_t));
  started = false;
}

BChaCha20::~BChaCha20() {
  cleanse(&ctx, sizeof(chacha20_t));
}

void
BChaCha20::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BChaCha20::New);

  chacha20_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ChaCha20").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BChaCha20::Init);
  Nan::SetPrototypeMethod(tpl, "encrypt", BChaCha20::Encrypt);
  Nan::SetPrototypeMethod(tpl, "destroy", BChaCha20::Destroy);
  Nan::SetMethod(tpl, "derive", BChaCha20::Derive);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(chacha20_constructor);

  Nan::Set(target, Nan::New("ChaCha20").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BChaCha20::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create ChaCha20 instance.");

  BChaCha20 *chacha = new BChaCha20();
  chacha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Init) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> nonce_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(nonce_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len != 16 && key_len != 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *nonce = (const uint8_t *)node::Buffer::Data(nonce_buf);
  size_t nonce_len = node::Buffer::Length(nonce_buf);

  if (nonce_len != 8 && nonce_len != 12 && nonce_len != 16
      && nonce_len != 24 && nonce_len != 28 && nonce_len != 32) {
    return Nan::ThrowRangeError("Invalid nonce size.");
  }

  uint64_t ctr = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    ctr = (uint64_t)Nan::To<int64_t>(info[2]).FromJust();
  }

  chacha20_init(&chacha->ctx, key, key_len, nonce, nonce_len, ctr);
  chacha->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Encrypt) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.encrypt() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!chacha->started)
    return Nan::ThrowError("Context is not initialized.");

  uint8_t *data = (uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  chacha20_encrypt(&chacha->ctx, data, data, data_len);

  info.GetReturnValue().Set(data_buf);
}

NAN_METHOD(BChaCha20::Destroy) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  chacha->started = false;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("ChaCha20.derive() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nonce_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(nonce_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  uint8_t *nonce = (uint8_t *)node::Buffer::Data(nonce_buf);
  size_t nonce_len = node::Buffer::Length(nonce_buf);

  if (key_len != 16 && key_len != 32)
    return Nan::ThrowRangeError("Invalid key size.");

  if (nonce_len != 16)
    return Nan::ThrowRangeError("Invalid nonce size.");

  uint8_t out[32];

  chacha20_derive(&out[0], key, key_len, nonce);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
