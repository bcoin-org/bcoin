#include "common.h"
#include "chacha20.h"

static Nan::Persistent<v8::FunctionTemplate> chacha20_constructor;

BChaCha20::BChaCha20() {
  memset(&ctx, 0, sizeof(bcrypto_chacha20_ctx));
  ctx.nonce_size = 8;
}

BChaCha20::~BChaCha20() {}

void
BChaCha20::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BChaCha20::New);

  chacha20_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ChaCha20").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BChaCha20::Init);
  Nan::SetPrototypeMethod(tpl, "initIV", BChaCha20::InitIV);
  Nan::SetPrototypeMethod(tpl, "initKey", BChaCha20::InitKey);
  Nan::SetPrototypeMethod(tpl, "encrypt", BChaCha20::Encrypt);
  Nan::SetPrototypeMethod(tpl, "crypt", BChaCha20::Crypt);
  Nan::SetPrototypeMethod(tpl, "setCounter", BChaCha20::SetCounter);
  Nan::SetPrototypeMethod(tpl, "getCounter", BChaCha20::GetCounter);

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

  v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16)
    return Nan::ThrowRangeError("Invalid IV size.");

  uint64_t ctr = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    ctr = (uint64_t)Nan::To<int64_t>(info[2]).FromJust();
  }

  bcrypto_chacha20_keysetup(&chacha->ctx, key, 32);
  bcrypto_chacha20_ivsetup(&chacha->ctx, iv, iv_len);
  bcrypto_chacha20_counter_set(&chacha->ctx, ctr);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::InitKey) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initKey() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  if (key_len < 32)
    return Nan::ThrowRangeError("Invalid key size.");

  bcrypto_chacha20_keysetup(&chacha->ctx, key, 32);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::InitIV) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.initIV() requires arguments.");

  v8::Local<v8::Object> iv_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(iv_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(iv_buf);
  size_t iv_len = node::Buffer::Length(iv_buf);

  if (iv_len != 8 && iv_len != 12 && iv_len != 16)
    return Nan::ThrowRangeError("Invalid IV size.");

  uint64_t ctr = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    ctr = (uint64_t)Nan::To<int64_t>(info[1]).FromJust();
  }

  bcrypto_chacha20_ivsetup(&chacha->ctx, iv, iv_len);
  bcrypto_chacha20_counter_set(&chacha->ctx, ctr);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::Encrypt) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.encrypt() requires arguments.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  bcrypto_chacha20_encrypt(&chacha->ctx, data, (uint8_t *)data, data_len);

  info.GetReturnValue().Set(data_buf);
}

NAN_METHOD(BChaCha20::Crypt) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("chacha20.crypt() requires arguments.");

  v8::Local<v8::Object> input_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> output_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(input_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(output_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *input = (const uint8_t *)node::Buffer::Data(input_buf);
  size_t input_len = node::Buffer::Length(input_buf);

  const uint8_t *output = (const uint8_t *)node::Buffer::Data(output_buf);
  size_t output_len = node::Buffer::Length(output_buf);

  if (output_len < input_len)
    return Nan::ThrowRangeError("Invalid output size.");

  bcrypto_chacha20_encrypt(&chacha->ctx, input, (uint8_t *)output, input_len);

  info.GetReturnValue().Set(output_buf);
}

NAN_METHOD(BChaCha20::SetCounter) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("chacha20.setCounter() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowError("First argument must be a number.");

  bcrypto_chacha20_counter_set(&chacha->ctx, (uint64_t)Nan::To<int64_t>(info[0]).FromJust());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BChaCha20::GetCounter) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());
  info.GetReturnValue().Set(
    Nan::New<v8::Number>((double)bcrypto_chacha20_counter_get(&chacha->ctx)));
}

NAN_METHOD(BChaCha20::Destroy) {
  BChaCha20 *chacha = ObjectWrap::Unwrap<BChaCha20>(info.Holder());

  memset(&chacha->ctx, 0, sizeof(bcrypto_chacha20_ctx));
  chacha->ctx.nonce_size = 8;

  info.GetReturnValue().Set(info.This());
}
