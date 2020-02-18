#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>
#include <torsion/util.h>

#include "common.h"
#include "eddsa.h"

static Nan::Persistent<v8::FunctionTemplate> eddsa_constructor;

BEDDSA::BEDDSA() {
  ctx = NULL;
  scratch = NULL;
}

BEDDSA::~BEDDSA() {
  if (scratch != NULL) {
    assert(ctx != NULL);
    eddsa_scratch_destroy(ctx, scratch);
    scratch = NULL;
  }

  if (ctx != NULL) {
    eddsa_context_destroy(ctx);
    ctx = NULL;
  }
}

void
BEDDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BEDDSA::New);

  eddsa_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("EDDSA").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "_size", BEDDSA::Size);
  Nan::SetPrototypeMethod(tpl, "_bits", BEDDSA::Bits);
  Nan::SetPrototypeMethod(tpl, "_randomize", BEDDSA::Randomize);
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BEDDSA::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BEDDSA::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "privateKeyExport", BEDDSA::PrivateKeyExport);
  Nan::SetPrototypeMethod(tpl, "privateKeyImport", BEDDSA::PrivateKeyImport);
  Nan::SetPrototypeMethod(tpl, "privateKeyExpand", BEDDSA::PrivateKeyExpand);
  Nan::SetPrototypeMethod(tpl, "privateKeyExpand", BEDDSA::PrivateKeyExpand);
  Nan::SetPrototypeMethod(tpl, "privateKeyConvert", BEDDSA::PrivateKeyConvert);
  Nan::SetPrototypeMethod(tpl, "scalarGenerate", BEDDSA::ScalarGenerate);
  Nan::SetPrototypeMethod(tpl, "scalarVerify", BEDDSA::ScalarVerify);
  Nan::SetPrototypeMethod(tpl, "scalarClamp", BEDDSA::ScalarClamp);
  Nan::SetPrototypeMethod(tpl, "scalarIsZero", BEDDSA::ScalarIsZero);
  Nan::SetPrototypeMethod(tpl, "scalarTweakAdd", BEDDSA::ScalarTweakAdd);
  Nan::SetPrototypeMethod(tpl, "scalarTweakMul", BEDDSA::ScalarTweakMul);
  Nan::SetPrototypeMethod(tpl, "scalarReduce", BEDDSA::ScalarReduce);
  Nan::SetPrototypeMethod(tpl, "scalarNegate", BEDDSA::ScalarNegate);
  Nan::SetPrototypeMethod(tpl, "scalarInvert", BEDDSA::ScalarInvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BEDDSA::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromScalar", BEDDSA::PublicKeyFromScalar);
  Nan::SetPrototypeMethod(tpl, "publicKeyConvert", BEDDSA::PublicKeyConvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromUniform", BEDDSA::PublicKeyFromUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyToUniform", BEDDSA::PublicKeyToUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromHash", BEDDSA::PublicKeyFromHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyToHash", BEDDSA::PublicKeyToHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BEDDSA::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyExport", BEDDSA::PublicKeyExport);
  Nan::SetPrototypeMethod(tpl, "publicKeyImport", BEDDSA::PublicKeyImport);
  Nan::SetPrototypeMethod(tpl, "publicKeyIsInfinity", BEDDSA::PublicKeyIsInfinity);
  Nan::SetPrototypeMethod(tpl, "publicKeyIsSmall", BEDDSA::PublicKeyIsSmall);
  Nan::SetPrototypeMethod(tpl, "publicKeyHasTorsion", BEDDSA::PublicKeyHasTorsion);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakAdd", BEDDSA::PublicKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakMul", BEDDSA::PublicKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "publicKeyCombine", BEDDSA::PublicKeyCombine);
  Nan::SetPrototypeMethod(tpl, "publicKeyNegate", BEDDSA::PublicKeyNegate);
  Nan::SetPrototypeMethod(tpl, "sign", BEDDSA::Sign);
  Nan::SetPrototypeMethod(tpl, "signWithScalar", BEDDSA::SignWithScalar);
  Nan::SetPrototypeMethod(tpl, "signTweakAdd", BEDDSA::SignTweakAdd);
  Nan::SetPrototypeMethod(tpl, "signTweakMul", BEDDSA::SignTweakMul);
  Nan::SetPrototypeMethod(tpl, "verify", BEDDSA::Verify);
  Nan::SetPrototypeMethod(tpl, "verifySingle", BEDDSA::VerifySingle);
  Nan::SetPrototypeMethod(tpl, "verifyBatch", BEDDSA::VerifyBatch);
  Nan::SetPrototypeMethod(tpl, "derive", BEDDSA::Derive);
  Nan::SetPrototypeMethod(tpl, "deriveWithScalar", BEDDSA::DeriveWithScalar);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(eddsa_constructor);

  Nan::Set(target, Nan::New("EDDSA").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BEDDSA::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create EDDSA instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("EDDSA() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  BEDDSA *ec = new BEDDSA();

  ec->ctx = eddsa_context_create(name);

  if (ec->ctx == NULL)
    return Nan::ThrowTypeError("Curve not available.");

  ec->scratch = eddsa_scratch_create(ec->ctx);

  if (ec->scratch == NULL)
    return Nan::ThrowTypeError("Allocation failed.");

  ec->scalar_size = eddsa_scalar_size(ec->ctx);
  ec->scalar_bits = eddsa_scalar_bits(ec->ctx);
  ec->field_size = eddsa_field_size(ec->ctx);
  ec->field_bits = eddsa_field_bits(ec->ctx);
  ec->priv_size = eddsa_privkey_size(ec->ctx);
  ec->pub_size = eddsa_pubkey_size(ec->ctx);
  ec->sig_size = eddsa_sig_size(ec->ctx);

  ec->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BEDDSA::Size) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->pub_size));
}

NAN_METHOD(BEDDSA::Bits) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());
  return info.GetReturnValue()
    .Set(Nan::New<v8::Number>((uint32_t)ec->field_bits));
}

NAN_METHOD(BEDDSA::Randomize) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa._randomize() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  eddsa_context_randomize(ec->ctx, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BEDDSA::PrivateKeyGenerate) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyGenerate() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t priv[EDDSA_MAX_PRIV_SIZE];

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  eddsa_privkey_generate(ec->ctx, priv, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)priv, ec->priv_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PrivateKeyVerify) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  size_t priv_len = node::Buffer::Length(pbuf);
  int result = priv_len == ec->priv_size;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::PrivateKeyExport) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[EDDSA_MAX_PRIV_SIZE];

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid length.");

  if (!eddsa_privkey_export(ec->ctx, out, priv))
    return Nan::ThrowError("Could not export private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->priv_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PrivateKeyImport) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t out[EDDSA_MAX_PRIV_SIZE];

  if (!eddsa_privkey_import(ec->ctx, out, priv, priv_len))
    return Nan::ThrowError("Could not import private key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->priv_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PrivateKeyExpand) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyExpand() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t scalar[EDDSA_MAX_SCALAR_SIZE];
  uint8_t prefix[EDDSA_MAX_PREFIX_SIZE];

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  eddsa_privkey_expand(ec->ctx, scalar, prefix, priv);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)scalar, ec->scalar_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)prefix, ec->pub_size).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BEDDSA::PrivateKeyConvert) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.privateKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t priv_len = node::Buffer::Length(pbuf);
  uint8_t scalar[EDDSA_MAX_SCALAR_SIZE];

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  eddsa_privkey_convert(ec->ctx, scalar, priv);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)scalar, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarGenerate) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarGenerate() requires arguments.");

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t scalar[EDDSA_MAX_SCALAR_SIZE];

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  eddsa_scalar_generate(ec->ctx, scalar, entropy);

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)scalar, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarVerify) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  size_t scalar_len = node::Buffer::Length(pbuf);
  int result = scalar_len == ec->scalar_size;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::ScalarClamp) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarClamp() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  eddsa_scalar_clamp(ec->ctx, out, scalar);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarIsZero) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarIsZero() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);

  if (scalar_len != ec->scalar_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_scalar_is_zero(ec->ctx, scalar);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::ScalarTweakAdd) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.scalarTweakAdd() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  eddsa_scalar_tweak_add(ec->ctx, out, scalar, tweak);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarTweakMul) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.scalarTweakMul() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  eddsa_scalar_tweak_mul(ec->ctx, out, scalar, tweak);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarReduce) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarReduce() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  eddsa_scalar_reduce(ec->ctx, out, scalar, scalar_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarNegate) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarNegate() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  eddsa_scalar_negate(ec->ctx, out, scalar);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::ScalarInvert) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.scalarInvert() requires arguments.");

  v8::Local<v8::Object> kbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t scalar_len = node::Buffer::Length(kbuf);
  uint8_t out[EDDSA_MAX_SCALAR_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  eddsa_scalar_invert(ec->ctx, out, scalar);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->scalar_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyCreate) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);
  uint8_t pub[EDDSA_MAX_PUB_SIZE];

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  eddsa_pubkey_create(ec->ctx, pub, priv);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)pub, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyFromScalar) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyFromScalar() requires arguments.");

  v8::Local<v8::Object> sbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);
  uint8_t pub[EDDSA_MAX_PUB_SIZE];

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  eddsa_pubkey_from_scalar(ec->ctx, pub, scalar);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)pub, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyConvert) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyConvert() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t out[ECDH_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!eddsa_pubkey_convert(ec->ctx, out, pub))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyFromUniform) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyFromUniform() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (data_len != ec->field_size)
    return Nan::ThrowRangeError("Invalid field element size.");

  eddsa_pubkey_from_uniform(ec->ctx, out, data);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyToUniform) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.publicKeyToUniform() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  unsigned int hint = (unsigned int)Nan::To<uint32_t>(info[1]).FromJust();
  uint8_t out[EDDSA_MAX_FIELD_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!eddsa_pubkey_to_uniform(ec->ctx, out, pub, hint))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyFromHash) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyFromHash() requires arguments.");

  v8::Local<v8::Object> dbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (info.Length() > 1 && !info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t data_len = node::Buffer::Length(dbuf);
  int pake = 0;
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (info.Length() > 1)
    pake = (int)Nan::To<bool>(info[1]).FromJust();

  if (data_len != ec->field_size * 2)
    return Nan::ThrowRangeError("Invalid hash size.");

  eddsa_pubkey_from_hash(ec->ctx, out, data, pake);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyToHash) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.publicKeyToHash() requires arguments.");

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
  uint8_t out[EDDSA_MAX_FIELD_SIZE * 2];

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!eddsa_pubkey_to_hash(ec->ctx, out, pub, entropy))
    return Nan::ThrowError("Invalid public key.");

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->field_size * 2).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyVerify) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_pubkey_verify(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::PublicKeyExport) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t x[EDDSA_MAX_FIELD_SIZE];
  uint8_t y[EDDSA_MAX_FIELD_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!eddsa_pubkey_export(ec->ctx, x, y, pub))
    return Nan::ThrowError("Could not export public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, Nan::CopyBuffer((char *)x, ec->field_size).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)y, ec->field_size).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BEDDSA::PublicKeyImport) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  const uint8_t *x = NULL;
  size_t x_len = 0;
  const uint8_t *y = NULL;
  size_t y_len = 0;
  int sign = -1;

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

  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (!eddsa_pubkey_import(ec->ctx, out, x, x_len, y, y_len, sign))
    return Nan::ThrowError("Could not import public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyIsInfinity) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyIsInfinity() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_pubkey_is_infinity(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::PublicKeyIsSmall) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyIsSmall() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_pubkey_is_small(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::PublicKeyHasTorsion) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyHasTorsion() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);

  if (pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_pubkey_has_torsion(ec->ctx, pub);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::PublicKeyTweakAdd) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.publicKeyTweakAdd() requires arguments.");

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
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  if (!eddsa_pubkey_tweak_add(ec->ctx, out, pub, tweak))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyTweakMul) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.publicKeyTweakMul() requires arguments.");

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
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  if (!eddsa_pubkey_tweak_mul(ec->ctx, out, pub, tweak))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyCombine) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyCombine() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();
  size_t len = (size_t)batch->Length();
  const uint8_t **pubs =
    (const uint8_t **)malloc((len == 0 ? 1 : len) * sizeof(uint8_t *));
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pubs == NULL)
    return Nan::ThrowError("Allocation failed.");

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Object> pbuf = Nan::Get(batch, i).ToLocalChecked()
                                                   .As<v8::Object>();

    if (!node::Buffer::HasInstance(pbuf)) {
      free(pubs);
      return Nan::ThrowTypeError("Public key must be a buffer.");
    }

    const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
    size_t pub_len = node::Buffer::Length(pbuf);

    if (pub_len != ec->pub_size) {
      free(pubs);
      return Nan::ThrowError("Invalid point.");
    }

    pubs[i] = pub;
  }

  if (!eddsa_pubkey_combine(ec->ctx, out, pubs, len)) {
    free(pubs);
    return Nan::ThrowError("Invalid point.");
  }

  free(pubs);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::PublicKeyNegate) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.publicKeyNegate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (!eddsa_pubkey_negate(ec->ctx, out, pub))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::Sign) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;
  uint8_t sig[EDDSA_MAX_SIG_SIZE];

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[2]).FromJust();
  }

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> cbuf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  eddsa_sign(ec->ctx, sig, msg, msg_len, priv, ph, ctx, ctx_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::SignWithScalar) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("eddsa.signWithScalar() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);
  const uint8_t *prefix = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t prefix_len = node::Buffer::Length(pbuf);
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;
  uint8_t sig[EDDSA_MAX_SIG_SIZE];

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Fourth argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (prefix_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid prefix size.");

  eddsa_sign_with_scalar(ec->ctx, sig, msg, msg_len,
                         scalar, prefix, ph, ctx, ctx_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::SignTweakAdd) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.signTweakAdd() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;
  uint8_t sig[EDDSA_MAX_SIG_SIZE];

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  eddsa_sign_tweak_add(ec->ctx, sig, msg, msg_len,
                       priv, tweak, ph, ctx, ctx_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::SignTweakMul) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.signTweakMul() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> tbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(tbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t msg_len = node::Buffer::Length(mbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);
  const uint8_t *tweak = (const uint8_t *)node::Buffer::Data(tbuf);
  size_t tweak_len = node::Buffer::Length(tbuf);
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;
  uint8_t sig[EDDSA_MAX_SIG_SIZE];

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  if (tweak_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid tweak size.");

  eddsa_sign_tweak_mul(ec->ctx, sig, msg, msg_len,
                       priv, tweak, ph, ctx, ctx_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, ec->sig_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::Verify) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("eddsa.verify() requires arguments.");

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
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (sig_len != ec->sig_size || pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_verify(ec->ctx, msg, msg_len, sig, pub, ph, ctx, ctx_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::VerifySingle) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("eddsa.verifySingle() requires arguments.");

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
  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsBoolean())
      return Nan::ThrowTypeError("Third argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[3]).FromJust();
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> cbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

  if (sig_len != ec->sig_size || pub_len != ec->pub_size)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = eddsa_verify_single(ec->ctx, msg, msg_len,
                                   sig, pub, ph, ctx, ctx_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::VerifyBatch) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("eddsa.verifyBatch() requires arguments.");

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError("First argument must be an array.");

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();

  int ph = -1;
  const uint8_t *ctx = NULL;
  size_t ctx_len = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsBoolean())
      return Nan::ThrowTypeError("Second argument must be a boolean or null.");

    ph = (int)Nan::To<bool>(info[1]).FromJust();
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> cbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(cbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer or null.");

    if (ph == -1)
      return Nan::ThrowError("Must pass pre-hash flag with context.");

    ctx = (const uint8_t *)node::Buffer::Data(cbuf);
    ctx_len = node::Buffer::Length(cbuf);

    if (ctx_len > 255)
      return Nan::ThrowRangeError("Invalid context length.");
  }

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

    if (sig_len != ec->sig_size || pub_len != ec->pub_size) {
      FREE_BATCH;
      return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));
    }

    msgs[i] = msg;
    msg_lens[i] = msg_len;
    sigs[i] = sig;
    pubs[i] = pub;
  }

  int result = eddsa_verify_batch(ec->ctx, msgs, msg_lens, sigs,
                                           pubs, len, ph, ctx,
                                           ctx_len, ec->scratch);

  FREE_BATCH;

#undef FREE_BATCH

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BEDDSA::Derive) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t priv_len = node::Buffer::Length(sbuf);
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (priv_len != ec->priv_size)
    return Nan::ThrowRangeError("Invalid key size.");

  if (!eddsa_derive(ec->ctx, out, pub, priv))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}

NAN_METHOD(BEDDSA::DeriveWithScalar) {
  BEDDSA *ec = ObjectWrap::Unwrap<BEDDSA>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("eddsa.deriveWithScalar() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(sbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t pub_len = node::Buffer::Length(pbuf);
  const uint8_t *scalar = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t scalar_len = node::Buffer::Length(sbuf);
  uint8_t out[EDDSA_MAX_PUB_SIZE];

  if (pub_len != ec->pub_size)
    return Nan::ThrowRangeError("Invalid public key size.");

  if (scalar_len != ec->scalar_size)
    return Nan::ThrowRangeError("Invalid scalar size.");

  if (!eddsa_derive_with_scalar(ec->ctx, out, pub, scalar))
    return Nan::ThrowError("Invalid public key.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, ec->pub_size).ToLocalChecked());
}
