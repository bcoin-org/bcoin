#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>
#include <torsion/util.h>

#include "common.h"
#include "schnorr.h"

static Nan::Persistent<v8::FunctionTemplate> schnorr_constructor;

BSchnorr::BSchnorr() {
  ctx = NULL;
  scratch = NULL;
}

BSchnorr::~BSchnorr() {
  if (scratch != NULL) {
    assert(ctx != NULL);
    schnorr_scratch_destroy(ctx, scratch);
    scratch = NULL;
  }

  if (ctx != NULL) {
    schnorr_context_destroy(ctx);
    ctx = NULL;
  }
}

void
BSchnorr::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSchnorr::New);

  schnorr_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Schnorr").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "_size", BSchnorr::Size);
  Nan::SetPrototypeMethod(tpl, "_bits", BSchnorr::Bits);
  Nan::SetPrototypeMethod(tpl, "_randomize", BSchnorr::Randomize);
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BSchnorr::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BSchnorr::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "privateKeyExport", BSchnorr::PrivateKeyExport);
  Nan::SetPrototypeMethod(tpl, "privateKeyImport", BSchnorr::PrivateKeyImport);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakAdd", BSchnorr::PrivateKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakMul", BSchnorr::PrivateKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "privateKeyReduce", BSchnorr::PrivateKeyReduce);
  Nan::SetPrototypeMethod(tpl, "privateKeyInvert", BSchnorr::PrivateKeyInvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BSchnorr::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromUniform", BSchnorr::PublicKeyFromUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyToUniform", BSchnorr::PublicKeyToUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromHash", BSchnorr::PublicKeyFromHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyToHash", BSchnorr::PublicKeyToHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BSchnorr::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyExport", BSchnorr::PublicKeyExport);
  Nan::SetPrototypeMethod(tpl, "publicKeyImport", BSchnorr::PublicKeyImport);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakAdd", BSchnorr::PublicKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakMul", BSchnorr::PublicKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "publicKeyCombine", BSchnorr::PublicKeyCombine);
  Nan::SetPrototypeMethod(tpl, "sign", BSchnorr::Sign);
  Nan::SetPrototypeMethod(tpl, "verify", BSchnorr::Verify);
  Nan::SetPrototypeMethod(tpl, "derive", BSchnorr::Derive);
  Nan::SetPrototypeMethod(tpl, "verifyBatch", BSchnorr::VerifyBatch);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(schnorr_constructor);

  Nan::Set(target, Nan::New("Schnorr").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSchnorr::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Schnorr instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("Schnorr() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();

  BSchnorr *ec = new BSchnorr();

  ec->ctx = schnorr_context_create(type);

  if (ec->ctx == NULL)
    return Nan::ThrowTypeError("Curve not available.");

  ec->scratch = schnorr_scratch_create(ec->ctx);

  if (ec->scratch == NULL)
    return Nan::ThrowTypeError("Allocation failed.");

  ec->scalar_size = schnorr_scalar_size(ec->ctx);
  ec->scalar_bits = schnorr_scalar_bits(ec->ctx);
  ec->field_size = schnorr_field_size(ec->ctx);
  ec->field_bits = schnorr_field_bits(ec->ctx);
  ec->sig_size = schnorr_sig_size(ec->ctx);

  ec->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSchnorr::Size) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_size));
}

NAN_METHOD(BSchnorr::Bits) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_bits));
}

NAN_METHOD(BSchnorr::Randomize) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr._randomize() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  schnorr_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BSchnorr::PrivateKeyGenerate) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyGenerate() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t priv[SCHNORR_MAX_PRIV_SIZE];

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  schnorr_privkey_generate(ec->ctx, priv, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)priv, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PrivateKeyVerify) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->scalar_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = schnorr_privkey_verify(ec->ctx, priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSchnorr::PrivateKeyExport) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];
  uint8_t x[SCHNORR_MAX_FIELD_SIZE];
  uint8_t y[SCHNORR_MAX_FIELD_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_privkey_export(ec->ctx, out, x, y, priv))
    return Nan::ThrowError("Could not export private key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)x, ec->field_size).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)y, ec->field_size).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSchnorr::PrivateKeyImport) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];

  if (!schnorr_privkey_import(ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not import private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PrivateKeyTweakAdd) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.privateKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size || tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_privkey_tweak_add(ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PrivateKeyTweakMul) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.privateKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size || tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_privkey_tweak_mul(ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PrivateKeyReduce) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyReduce() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];

  if (!schnorr_privkey_reduce(ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PrivateKeyInvert) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.privateKeyInvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_privkey_invert(ec->ctx, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyCreate) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_create(ec->ctx, out, priv))
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyFromUniform) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t data_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (data_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  schnorr_pubkey_from_uniform(ec->ctx, out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyToUniform) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();
  uint8_t out[SCHNORR_MAX_FIELD_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_to_uniform(ec->ctx, out, pub, hint))
    return Nan::ThrowError("Invalid point.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyFromHash) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t data_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (data_len != ec->field_size * 2)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_from_hash(ec->ctx, out, data))
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyToHash) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.publicKeyToHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("First argument must be a buffer.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t out[SCHNORR_MAX_FIELD_SIZE * 2];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  if (!schnorr_pubkey_to_hash(ec->ctx, out, pub, entropy))
    return Nan::ThrowError("Invalid point.");

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size * 2).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyVerify) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->field_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = schnorr_pubkey_verify(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSchnorr::PublicKeyExport) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t x[SCHNORR_MAX_FIELD_SIZE];
  uint8_t y[SCHNORR_MAX_FIELD_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_export(ec->ctx, x, y, pub))
    return Nan::ThrowError("Could not export public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)x, ec->field_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)y, ec->field_size).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSchnorr::PublicKeyImport) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  const uint8_t *x = NULL;
  size_t x_len = 0;

  if (info.Length() > 0 && !IsNull(info[0])) {
    v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();

    if (!node::Buffer::HasInstance(xbuf))
      return Nan::ThrowTypeError("First argument must be a buffer.");

    x = (const uint8_t *)node::Buffer::Data(xbuf);
    x_len = node::Buffer::Length(xbuf);
  }

  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (!schnorr_pubkey_import(ec->ctx, out, x, x_len))
    return Nan::ThrowError("Could not import public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyTweakAdd) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.publicKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_tweak_add(ec->ctx, out, pub, tweak))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyTweakMul) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.publicKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_pubkey_tweak_mul(ec->ctx, out, pub, tweak))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::PublicKeyCombine) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.publicKeyCombine() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();
  size_t len = (size_t)batch->Length();

  if (len == 0)
    return Nan::ThrowError("Invalid point.");

  const uint8_t **pubs = (const uint8_t **)malloc(len * sizeof(uint8_t *));

#define FREE_BATCH do {                 \
  if (pubs != NULL) free(pubs);         \
} while (0)

  if (pubs == NULL) {
    FREE_BATCH;
    return Nan::ThrowError("Allocation failed.");
  }

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Object> pbuf = Nan::Get(batch, i).ToLocalChecked()
                                                   .As<v8::Object>();

    if (!node::Buffer::HasInstance(pbuf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError("Public key must be a buffer.");
    }

    size_t pub_len = node::Buffer::Length(pbuf);

    if (pub_len != ec->field_size) {
      FREE_BATCH;
      return Nan::ThrowRangeError("Invalid length.");
    }

    pubs[i] = (const uint8_t *)node::Buffer::Data(pbuf);
  }

  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (!schnorr_pubkey_combine(ec->ctx, out, pubs, len)) {
    FREE_BATCH;
    return Nan::ThrowError("Invalid point.");
  }

  FREE_BATCH;

#undef FREE_BATCH

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::Derive) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.derive() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t pub_len = node::Buffer::Length(kbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[SCHNORR_MAX_PUB_SIZE];

  if (pub_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_derive(ec->ctx, out, pub, priv))
    return Nan::ThrowError("Could not perform ECDH.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::Sign) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("schnorr.schnorrSign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  const uint8_t *aux = NULL;
  size_t aux_len = 0;
  uint8_t out[SCHNORR_MAX_SIG_SIZE];

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> abuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(abuf))
      return Nan::ThrowTypeError("Arguments must be buffers.");

    aux = (const uint8_t *)node::Buffer::Data(abuf);
    aux_len = node::Buffer::Length(abuf);
  }

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!schnorr_sign(ec->ctx, out, msg, msg_len, priv, aux, aux_len))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BSchnorr::Verify) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("schnorr.schnorrVerify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (sig_len != ec->sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  if (pub_len != ec->field_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = schnorr_verify(ec->ctx, msg, msg_len, sig, pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSchnorr::VerifyBatch) {
  BSchnorr *ec = ObjectWrap::Unwrap<BSchnorr>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("schnorr.schnorrVerifyBatch() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  if (len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));

  const uint8_t **ptrs = (const uint8_t **)malloc(3 * len * sizeof(uint8_t *));
  size_t *lens = (size_t *)malloc(len * sizeof(size_t));

#define FREE_BATCH do {         \
  if (ptrs != NULL) free(ptrs); \
  if (lens != NULL) free(lens); \
} while (0)

  if (ptrs == NULL || lens == NULL) {
    FREE_BATCH;
    return Nan::ThrowError("Allocation failed.");
  }

  const uint8_t **msgs = ptrs + len * 0;
  const uint8_t **pubs = ptrs + len * 1;
  const uint8_t **sigs = ptrs + len * 2;
  size_t *msg_lens = lens;

  for (size_t i = 0; i < len; i++) {
    if (!Nan::Get(batch, i).ToLocalChecked()->IsArray()) {
      FREE_BATCH;
      return Nan::ThrowTypeError("Batch item must be an array.");
    }

    v8::Local<v8::Array> item = Nan::Get(batch, i).ToLocalChecked()
                                                  .As<v8::Array>();

    if (item->Length() != 3) {
      FREE_BATCH;
      return Nan::ThrowError("Batch item must consist of 3 members.");
    }

    v8::Local<v8::Object> mbuf = Nan::Get(item, 0).ToLocalChecked()
                                                  .As<v8::Object>();
    v8::Local<v8::Object> sbuf = Nan::Get(item, 1).ToLocalChecked()
                                                  .As<v8::Object>();
    v8::Local<v8::Object> pbuf = Nan::Get(item, 2).ToLocalChecked()
                                                  .As<v8::Object>();

    if (!node::Buffer::HasInstance(mbuf)
        || !node::Buffer::HasInstance(sbuf)
        || !node::Buffer::HasInstance(pbuf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError("Batch item values must be buffers.");
    }

    const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
    size_t msg_len = node::Buffer::Length(mbuf);

    const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
    size_t sig_len = node::Buffer::Length(sbuf);

    const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
    size_t pub_len = node::Buffer::Length(pbuf);

    if (sig_len != ec->sig_size) {
      FREE_BATCH;
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    }

    if (pub_len != ec->field_size) {
      FREE_BATCH;
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    }

    msgs[i] = msg;
    msg_lens[i] = msg_len;
    sigs[i] = sig;
    pubs[i] = pub;
  }

  int result = schnorr_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                                    pubs, len, ec->scratch);

  FREE_BATCH;

#undef FREE_BATCH

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
