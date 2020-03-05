#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>
#include <torsion/util.h>

#include "common.h"
#include "ecdsa.h"

static Nan::Persistent<v8::FunctionTemplate> ecdsa_constructor;

BECDSA::BECDSA() {
  ctx = NULL;
  scratch = NULL;
}

BECDSA::~BECDSA() {
  if (scratch != NULL) {
    assert(ctx != NULL);
    ecdsa_scratch_destroy(ctx, scratch);
    scratch = NULL;
  }

  if (ctx != NULL) {
    ecdsa_context_destroy(ctx);
    ctx = NULL;
  }
}

void
BECDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BECDSA::New);

  ecdsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("ECDSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "_size", BECDSA::Size);
  Nan::SetPrototypeMethod(tpl, "_bits", BECDSA::Bits);
  Nan::SetPrototypeMethod(tpl, "_randomize", BECDSA::Randomize);
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BECDSA::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BECDSA::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "privateKeyExport", BECDSA::PrivateKeyExport);
  Nan::SetPrototypeMethod(tpl, "privateKeyImport", BECDSA::PrivateKeyImport);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakAdd", BECDSA::PrivateKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakMul", BECDSA::PrivateKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "privateKeyReduce", BECDSA::PrivateKeyReduce);
  Nan::SetPrototypeMethod(tpl, "privateKeyNegate", BECDSA::PrivateKeyNegate);
  Nan::SetPrototypeMethod(tpl, "privateKeyInvert", BECDSA::PrivateKeyInvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BECDSA::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyConvert", BECDSA::PublicKeyConvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromUniform", BECDSA::PublicKeyFromUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyToUniform", BECDSA::PublicKeyToUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromHash", BECDSA::PublicKeyFromHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyToHash", BECDSA::PublicKeyToHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BECDSA::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyExport", BECDSA::PublicKeyExport);
  Nan::SetPrototypeMethod(tpl, "publicKeyImport", BECDSA::PublicKeyImport);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakAdd", BECDSA::PublicKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakMul", BECDSA::PublicKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "publicKeyCombine", BECDSA::PublicKeyCombine);
  Nan::SetPrototypeMethod(tpl, "publicKeyNegate", BECDSA::PublicKeyNegate);
  Nan::SetPrototypeMethod(tpl, "signatureNormalize", BECDSA::SignatureNormalize);
  Nan::SetPrototypeMethod(tpl, "signatureNormalizeDER", BECDSA::SignatureNormalizeDER);
  Nan::SetPrototypeMethod(tpl, "signatureExport", BECDSA::SignatureExport);
  Nan::SetPrototypeMethod(tpl, "signatureImport", BECDSA::SignatureImport);
  Nan::SetPrototypeMethod(tpl, "isLowS", BECDSA::IsLowS);
  Nan::SetPrototypeMethod(tpl, "isLowDER", BECDSA::IsLowDER);
  Nan::SetPrototypeMethod(tpl, "sign", BECDSA::Sign);
  Nan::SetPrototypeMethod(tpl, "signRecoverable", BECDSA::SignRecoverable);
  Nan::SetPrototypeMethod(tpl, "signDER", BECDSA::SignDER);
  Nan::SetPrototypeMethod(tpl, "signRecoverableDER", BECDSA::SignRecoverableDER);
  Nan::SetPrototypeMethod(tpl, "verify", BECDSA::Verify);
  Nan::SetPrototypeMethod(tpl, "verifyDER", BECDSA::VerifyDER);
  Nan::SetPrototypeMethod(tpl, "recover", BECDSA::Recover);
  Nan::SetPrototypeMethod(tpl, "recoverDER", BECDSA::RecoverDER);
  Nan::SetPrototypeMethod(tpl, "derive", BECDSA::Derive);
  Nan::SetPrototypeMethod(tpl, "schnorrSign", BECDSA::SchnorrSign);
  Nan::SetPrototypeMethod(tpl, "schnorrVerify", BECDSA::SchnorrVerify);
  Nan::SetPrototypeMethod(tpl, "schnorrVerifyBatch", BECDSA::SchnorrVerifyBatch);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(ecdsa_constructor);

  Nan::Set(target, Nan::New("ECDSA").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BECDSA::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create ECDSA instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("ECDSA() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();

  BECDSA *ec = new BECDSA();

  ec->ctx = ecdsa_context_create(type);

  if (ec->ctx == NULL)
    return Nan::ThrowTypeError("Curve not available.");

  ec->scratch = ecdsa_scratch_create(ec->ctx);

  if (ec->scratch == NULL)
    return Nan::ThrowTypeError("Allocation failed.");

  ec->scalar_size = ecdsa_scalar_size(ec->ctx);
  ec->scalar_bits = ecdsa_scalar_bits(ec->ctx);
  ec->field_size = ecdsa_field_size(ec->ctx);
  ec->field_bits = ecdsa_field_bits(ec->ctx);
  ec->sig_size = ecdsa_sig_size(ec->ctx);
  ec->schnorr_size = ecdsa_schnorr_size(ec->ctx);

  ec->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BECDSA::Size) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_size));
}

NAN_METHOD(BECDSA::Bits) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_bits));
}

NAN_METHOD(BECDSA::Randomize) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa._randomize() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  ecdsa_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BECDSA::PrivateKeyGenerate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyGenerate() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t priv[ECDSA_MAX_PRIV_SIZE];

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  ecdsa_privkey_generate(ec->ctx, priv, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)priv, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyVerify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);

  if (priv_len != ec->scalar_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_privkey_verify(ec->ctx, priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::PrivateKeyExport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_privkey_export(ec->ctx, out, priv))
    return Nan::ThrowError("Could not export private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyImport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (!ecdsa_privkey_import(ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not import private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakAdd) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyTweakAdd() requires arguments.");

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
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size || tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_privkey_tweak_add(ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyTweakMul) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.privateKeyTweakMul() requires arguments.");

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
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size || tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_privkey_tweak_mul(ec->ctx, out, priv, tweak))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyReduce) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyReduce() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (!ecdsa_privkey_reduce(ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyNegate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_privkey_negate(ec->ctx, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PrivateKeyInvert) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.privateKeyInvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_privkey_invert(ec->ctx, out, priv))
    return Nan::ThrowError("Could not tweak private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCreate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_pubkey_create(ec->ctx, out, &out_len, priv, compress))
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyConvert) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (!ecdsa_pubkey_convert(ec->ctx, out, &out_len, pub, pub_len, compress))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyFromUniform) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t data_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (data_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid length.");

  ecdsa_pubkey_from_uniform(ec->ctx, out, &out_len, data, compress);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyToUniform) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();
  uint8_t out[ECDSA_MAX_FIELD_SIZE];
  size_t out_len = ec->field_size;

  if (!ecdsa_pubkey_to_uniform(ec->ctx, out, pub, pub_len, hint))
    return Nan::ThrowError("Invalid point.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyFromHash) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t data_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (data_len != ec->field_size * 2)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_pubkey_from_hash(ec->ctx, out, &out_len, data, compress))
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyToHash) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyToHash() requires arguments.");

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
  uint8_t out[ECDSA_MAX_FIELD_SIZE * 2];
  size_t out_len = ec->field_size * 2;

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  if (!ecdsa_pubkey_to_hash(ec->ctx, out, pub, pub_len, entropy))
    return Nan::ThrowError("Invalid point.");

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyVerify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  int result = ecdsa_pubkey_verify(ec->ctx, pub, pub_len);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::PublicKeyExport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t x[ECDSA_MAX_FIELD_SIZE];
  uint8_t y[ECDSA_MAX_FIELD_SIZE];

  if (!ecdsa_pubkey_export(ec->ctx, x, y, pub, pub_len))
    return Nan::ThrowError("Could not export public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)x, ec->field_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)y, ec->field_size).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::PublicKeyImport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  const uint8_t *x = NULL;
  size_t x_len = 0;
  const uint8_t *y = NULL;
  size_t y_len = 0;
  int sign = -1;
  int compress = 1;

  if (info.Length() > 0 && !IsNull(info[0])) {
    v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();

    if (!node::Buffer::HasInstance(xbuf))
      return Nan::ThrowTypeError("First argument must be a buffer.");

    x = (const uint8_t *)node::Buffer::Data(xbuf);
    x_len = node::Buffer::Length(xbuf);
  }

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(ybuf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    y = (const uint8_t *)node::Buffer::Data(ybuf);
    y_len = node::Buffer::Length(ybuf);
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    sign = (int)Nan::To<bool>(info[2]).FromJust();
  }

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (!ecdsa_pubkey_import(ec->ctx, out, &out_len, x, x_len, y, y_len, sign, compress))
    return Nan::ThrowError("Could not import public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakAdd) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyTweakAdd() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_pubkey_tweak_add(ec->ctx, out, &out_len, pub, pub_len, tweak, compress))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyTweakMul) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.publicKeyTweakMul() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_pubkey_tweak_mul(ec->ctx, out, &out_len, pub, pub_len, tweak, compress))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyCombine) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyCombine() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();
  size_t len = (size_t)batch->Length();

  if (len == 0)
    return Nan::ThrowError("Invalid point.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t **pubs = (const uint8_t **)malloc(len * sizeof(uint8_t *));
  size_t *pub_lens = (size_t *)malloc(len * sizeof(size_t));

#define FREE_BATCH do {                 \
  if (pubs != NULL) free(pubs);         \
  if (pub_lens != NULL) free(pub_lens); \
} while (0)

  if (pubs == NULL || pub_lens == NULL) {
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

    pubs[i] = (const uint8_t *)node::Buffer::Data(pbuf);
    pub_lens[i] = node::Buffer::Length(pbuf);
  }

  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (!ecdsa_pubkey_combine(ec->ctx, out, &out_len, pubs, pub_lens, len, compress)) {
    FREE_BATCH;
    return Nan::ThrowError("Invalid point.");
  }

  FREE_BATCH;

#undef FREE_BATCH

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::PublicKeyNegate) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.publicKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int compress = 1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[1]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (!ecdsa_pubkey_negate(ec->ctx, out, &out_len, pub, pub_len, compress))
    return Nan::ThrowError("Could not tweak public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureNormalize) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureNormalize() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t out[ECDSA_MAX_SIG_SIZE];

  if (sig_len != ec->sig_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sig_normalize(ec->ctx, out, sig))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureNormalizeDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureNormalizeDER() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;

  if (!ecdsa_sig_import_lax(ec->ctx, out, sig, sig_len))
    return Nan::ThrowError("Invalid signature.");

  if (!ecdsa_sig_normalize(ec->ctx, out, out))
    return Nan::ThrowError("Invalid signature.");

  if (!ecdsa_sig_export(ec->ctx, out, &out_len, out))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureExport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureExport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;

  if (sig_len != ec->sig_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sig_export(ec->ctx, out, &out_len, sig))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignatureImport) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.signatureImport() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t out[ECDSA_MAX_SIG_SIZE];

  if (!ecdsa_sig_import_lax(ec->ctx, out, sig, sig_len))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BECDSA::IsLowS) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.isLowS() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);

  if (sig_len != ec->sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_is_low_s(ec->ctx, sig);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::IsLowDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.isLowDER() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];

  if (!ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_is_low_s(ec->ctx, tmp);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Sign) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.sign() requires arguments.");

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
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  size_t out_len = ec->sig_size;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sign(ec->ctx, out, NULL, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignRecoverable) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signRecoverable() requires arguments.");

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
  uint8_t out[ECDSA_MAX_SIG_SIZE];
  size_t out_len = ec->sig_size;
  unsigned int param = 0;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sign(ec->ctx, out, &param, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Number>(param));

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::SignDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signDER() requires arguments.");

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
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sign(ec->ctx, out, NULL, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  if (!ecdsa_sig_export(ec->ctx, out, &out_len, out))
    return Nan::ThrowError("Invalid signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SignRecoverableDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.signRecoverableDER() requires arguments.");

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
  uint8_t out[ECDSA_MAX_DER_SIZE];
  size_t out_len = ECDSA_MAX_DER_SIZE;
  unsigned int param = 0;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_sign(ec->ctx, out, &param, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  if (!ecdsa_sig_export(ec->ctx, out, &out_len, out))
    return Nan::ThrowError("Invalid signature.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
  Nan::Set(ret, 1, Nan::New<v8::Number>(param));

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BECDSA::Verify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

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
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];

  if (sig_len != ec->sig_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  if (!ecdsa_sig_normalize(ec->ctx, tmp, sig))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_verify(ec->ctx, msg, msg_len, tmp, pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::VerifyDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.verify() requires arguments.");

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
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];

  if (!ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  if (!ecdsa_sig_normalize(ec->ctx, tmp, tmp))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_verify(ec->ctx, msg, msg_len, tmp, pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::Recover) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[2]).FromJust();

  if (param < 0 || (param & 3) != param)
    return Nan::ThrowTypeError("Invalid recovery parameter.");

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (sig_len != ec->sig_size)
    return info.GetReturnValue().Set(Nan::Null());

  if (!ecdsa_sig_normalize(ec->ctx, tmp, sig))
    return info.GetReturnValue().Set(Nan::Null());

  if (!ecdsa_recover(ec->ctx, out, &out_len, msg, msg_len, tmp, param, compress))
    return info.GetReturnValue().Set(Nan::Null());

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::RecoverDER) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.recover() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  int param = (int)Nan::To<uint32_t>(info[2]).FromJust();

  if (param < 0 || (param & 3) != param)
    return Nan::ThrowTypeError("Invalid recovery parameter.");

  int compress = 1;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[3]).FromJust();
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sig_len = node::Buffer::Length(sbuf);
  uint8_t tmp[ECDSA_MAX_SIG_SIZE];
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len = ECDSA_MAX_PUB_SIZE;

  if (!ecdsa_sig_import_lax(ec->ctx, tmp, sig, sig_len))
    return info.GetReturnValue().Set(Nan::Null());

  if (!ecdsa_sig_normalize(ec->ctx, tmp, tmp))
    return info.GetReturnValue().Set(Nan::Null());

  if (!ecdsa_recover(ec->ctx, out, &out_len, msg, msg_len, tmp, param, compress))
    return info.GetReturnValue().Set(Nan::Null());

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::Derive) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.derive() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(pbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int compress = 1;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean.");

    compress = (int)Nan::To<bool>(info[2]).FromJust();
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t pub_len = node::Buffer::Length(kbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDSA_MAX_PUB_SIZE];
  size_t out_len;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_derive(ec->ctx, out, &out_len, pub, pub_len, priv, compress))
    return Nan::ThrowError("Could not perform ECDH.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SchnorrSign) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (!ecdsa_schnorr_support(ec->ctx))
    return Nan::ThrowError("Schnorr is not suppported.");

  if (info.Length() < 2)
    return Nan::ThrowError("ecdsa.schnorrSign() requires arguments.");

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
  uint8_t out[ECDSA_MAX_SCHNORR_SIZE];
  size_t out_len = ec->schnorr_size;

  if (priv_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!ecdsa_schnorr_sign(ec->ctx, out, msg, msg_len, priv))
    return Nan::ThrowError("Could not sign.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BECDSA::SchnorrVerify) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (!ecdsa_schnorr_support(ec->ctx))
    return Nan::ThrowError("Schnorr is not suppported.");

  if (info.Length() < 3)
    return Nan::ThrowError("ecdsa.schnorrVerify() requires arguments.");

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

  if (sig_len != ec->schnorr_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = ecdsa_schnorr_verify(ec->ctx, msg, msg_len, sig, pub, pub_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BECDSA::SchnorrVerifyBatch) {
  BECDSA *ec = ObjectWrap::Unwrap<BECDSA>(info.Holder());

  if (!ecdsa_schnorr_support(ec->ctx))
    return Nan::ThrowError("Schnorr is not suppported.");

  if (info.Length() < 1)
    return Nan::ThrowError("ecdsa.schnorrVerifyBatch() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  if (len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));

  const uint8_t **ptrs = (const uint8_t **)malloc(3 * len * sizeof(uint8_t *));
  size_t *lens = (size_t *)malloc(2 * len * sizeof(size_t));

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
  size_t *msg_lens = lens + len * 0;
  size_t *pub_lens = lens + len * 1;

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

    if (sig_len != ec->schnorr_size) {
      FREE_BATCH;
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    }

    msgs[i] = msg;
    msg_lens[i] = msg_len;
    sigs[i] = sig;
    pubs[i] = pub;
    pub_lens[i] = pub_len;
  }

  int result = ecdsa_schnorr_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                                          pubs, pub_lens, len, ec->scratch);

  FREE_BATCH;

#undef FREE_BATCH

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
