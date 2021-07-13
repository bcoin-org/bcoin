/*!
 * Parts of this software are based on cryptocoinjs/secp256k1-node:
 *
 * https://github.com/cryptocoinjs/secp256k1-node
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 secp256k1-node contributors
 *
 * Parts of this software are based on bn.js, elliptic, hash.js
 * Copyright (c) 2014-2016 Fedor Indutny
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *
 * https://github.com/bitcoin-core/secp256k1
 *
 * Copyright (c) 2013 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <node.h>
#include <nan.h>
#include <memory>

#include "secp256k1.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_schnorrleg.h"
#include "secp256k1/include/secp256k1_elligator.h"
#include "secp256k1/include/secp256k1_extra.h"
#include "secp256k1/contrib/lax_der_privatekey_parsing.h"
#include "secp256k1/contrib/lax_der_parsing.h"

#define ALLOCATION_FAILURE "allocation failed"
#define RANDOMIZATION_FAILURE "randomization failed"

#define COMPRESSED_TYPE_INVALID "compressed must be a boolean"

#define EC_PRIVATE_KEY_TYPE_INVALID "private key must be a Buffer"
#define EC_PRIVATE_KEY_LENGTH_INVALID "private key length is invalid"
#define EC_PRIVATE_KEY_RANGE_INVALID "private key range is invalid"
#define EC_PRIVATE_KEY_TWEAK_ADD_FAIL \
  "tweak out of range or resulting private key is invalid"
#define EC_PRIVATE_KEY_TWEAK_MUL_FAIL "tweak out of range"
#define EC_PRIVATE_KEY_EXPORT_FAIL "couldn't export private key"
#define EC_PRIVATE_KEY_IMPORT_FAIL "couldn't import private key"

#define EC_PUBLIC_KEYS_TYPE_INVALID "public keys must be an Array"
#define EC_PUBLIC_KEYS_LENGTH_INVALID \
  "public keys Array must have at least 1 element"
#define EC_PUBLIC_KEY_TYPE_INVALID "public key must be a Buffer"
#define EC_PUBLIC_KEY_LENGTH_INVALID "public key length is invalid"
#define EC_PUBLIC_KEY_PARSE_FAIL \
  "the public key could not be parsed or is invalid"
#define EC_PUBLIC_KEY_CREATE_FAIL "private was invalid, try again"
#define EC_PUBLIC_KEY_TWEAK_ADD_FAIL \
  "tweak out of range or resulting public key is invalid"
#define EC_PUBLIC_KEY_TWEAK_MUL_FAIL "tweak out of range"
#define EC_PUBLIC_KEY_COMBINE_FAIL "the sum of the public keys is not valid"
#define EC_PUBLIC_KEY_NEGATE_FAIL "public key negation failed"
#define EC_PUBLIC_KEY_INVERT_FAIL "public key inversion failed"
#define EC_PUBLIC_KEY_EXPORT_FAIL "couldn't export public key"
#define EC_PUBLIC_KEY_IMPORT_FAIL "couldn't import public key"

#define ECDH_FAIL "scalar was invalid (zero or overflow)"

#define EC_SIGNATURE_TYPE_INVALID "signature must be a Buffer"
#define EC_SIGNATURE_LENGTH_INVALID "signature length is invalid"
#define EC_SIGNATURE_PARSE_FAIL "couldn't parse signature"
#define EC_SIGNATURE_PARSE_DER_FAIL "couldn't parse DER signature"
#define EC_SIGNATURE_SERIALIZE_DER_FAIL \
  "couldn't serialize signature to DER format"

#define EC_SIGN_FAIL \
  "nonce generation function failed or private key is invalid"
#define EC_RECOVER_FAIL "couldn't recover public key from signature"

#define MSG_TYPE_INVALID "message must be a Buffer"
#define MSG_LENGTH_INVALID "message length is invalid"

#define RECOVERY_ID_TYPE_INVALID "recovery must be a Number"
#define RECOVERY_ID_VALUE_INVALID "recovery value must be in [0,3]"

#define SIGN_TYPE_INVALID "sign must be a Boolean"

#define COORD_TYPE_INVALID "coordinate must be a Buffer"

#define HINT_TYPE_INVALID "hint must be a Number"

#define TWEAK_TYPE_INVALID "tweak must be a Buffer"
#define TWEAK_LENGTH_INVALID "tweak length is invalid"

#define ENTROPY_TYPE_INVALID "entropy must be a Buffer"
#define ENTROPY_LENGTH_INVALID "entropy length is invalid"

#define BATCH_TYPE_INVALID "batch must be an Array"
#define BATCH_ITEM_TYPE_INVALID "batch item must be an Array"
#define BATCH_ITEM_LENGTH_INVALID "batch item must consist of 3 members"

#define COPY_BUFFER(data, datalen) \
  Nan::CopyBuffer((const char *)data, (uint32_t)datalen).ToLocalChecked()

#define UPDATE_COMPRESSED_VALUE(compressed, value, v_true, v_false) {          \
  if (!value->IsUndefined() && !value->IsNull()) {                             \
    CHECK_TYPE_BOOLEAN(value, COMPRESSED_TYPE_INVALID);                        \
    compressed = Nan::To<bool>(value).FromJust() ? v_true : v_false;           \
  }                                                                            \
}

// TypeError
#define CHECK_TYPE_ARRAY(value, message) do {                                  \
  if (!value->IsArray())                                                       \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

#define CHECK_TYPE_BOOLEAN(value, message) do {                                \
  if (!value->IsBoolean() && !value->IsBooleanObject())                        \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

#define CHECK_TYPE_BUFFER(value, message) do {                                 \
  if (!node::Buffer::HasInstance(value))                                       \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

#define CHECK_TYPE_FUNCTION(value, message) do {                               \
  if (!value->IsFunction())                                                    \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

#define CHECK_TYPE_NUMBER(value, message) do {                                 \
  if (!value->IsNumber() && !value->IsNumberObject())                          \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

#define CHECK_TYPE_OBJECT(value, message) do {                                 \
  if (!value->IsObject())                                                      \
    return Nan::ThrowTypeError(message);                                       \
} while (0)

// RangeError
#define CHECK_BUFFER_LENGTH(buffer, length, message) do {                      \
  if (node::Buffer::Length(buffer) != length)                                  \
    return Nan::ThrowRangeError(message);                                      \
} while (0)

#define CHECK_BUFFER_LENGTH2(buffer, length1, length2, message) do {           \
  if (node::Buffer::Length(buffer) != length1 &&                               \
      node::Buffer::Length(buffer) != length2) {                               \
    return Nan::ThrowRangeError(message);                                      \
  }                                                                            \
} while (0)

#define CHECK_BUFFER_LENGTH_GT_ZERO(buffer, message) do {                      \
  if (node::Buffer::Length(buffer) == 0)                                       \
    return Nan::ThrowRangeError(message);                                      \
} while (0)

#define CHECK_LENGTH_GT_ZERO(value, message) do {                              \
  if (value->Length() == 0)                                                    \
    return Nan::ThrowRangeError(message);                                      \
} while (0)

#define CHECK_NUMBER_IN_INTERVAL(number, x, y, message) do {                   \
  if (Nan::To<int64_t>(number).FromJust() <= x ||                              \
      Nan::To<int64_t>(number).FromJust() >= y) {                              \
    return Nan::ThrowRangeError(message);                                      \
  }                                                                            \
} while (0)

static Nan::Persistent<v8::FunctionTemplate> secp256k1_constructor;

BSecp256k1::BSecp256k1() {
  ctx = NULL;
  scratch = NULL;
}

BSecp256k1::~BSecp256k1() {
  if (ctx != NULL) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
  }
  if (scratch != NULL) {
    secp256k1_scratch_space_destroy(scratch);
    scratch = NULL;
  }
}

void
BSecp256k1::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSecp256k1::New);

  secp256k1_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Secp256k1").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  // internal
  Nan::SetPrototypeMethod(tpl, "_randomize", BSecp256k1::Randomize);

  // secret key
  Nan::SetPrototypeMethod(tpl, "privateKeyGenerate", BSecp256k1::PrivateKeyGenerate);
  Nan::SetPrototypeMethod(tpl, "privateKeyVerify", BSecp256k1::PrivateKeyVerify);
  Nan::SetPrototypeMethod(tpl, "privateKeyExport", BSecp256k1::PrivateKeyExport);
  Nan::SetPrototypeMethod(tpl, "privateKeyImport", BSecp256k1::PrivateKeyImport);
  Nan::SetPrototypeMethod(tpl, "privateKeyReduce", BSecp256k1::PrivateKeyReduce);
  Nan::SetPrototypeMethod(tpl, "privateKeyNegate", BSecp256k1::PrivateKeyNegate);
  Nan::SetPrototypeMethod(tpl, "privateKeyInvert", BSecp256k1::PrivateKeyInvert);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakAdd", BSecp256k1::PrivateKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "privateKeyTweakMul", BSecp256k1::PrivateKeyTweakMul);

  // public key
  Nan::SetPrototypeMethod(tpl, "publicKeyCreate", BSecp256k1::PublicKeyCreate);
  Nan::SetPrototypeMethod(tpl, "publicKeyConvert", BSecp256k1::PublicKeyConvert);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromUniform", BSecp256k1::PublicKeyFromUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyToUniform", BSecp256k1::PublicKeyToUniform);
  Nan::SetPrototypeMethod(tpl, "publicKeyFromHash", BSecp256k1::PublicKeyFromHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyToHash", BSecp256k1::PublicKeyToHash);
  Nan::SetPrototypeMethod(tpl, "publicKeyVerify", BSecp256k1::PublicKeyVerify);
  Nan::SetPrototypeMethod(tpl, "publicKeyExport", BSecp256k1::PublicKeyExport);
  Nan::SetPrototypeMethod(tpl, "publicKeyImport", BSecp256k1::PublicKeyImport);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakAdd", BSecp256k1::PublicKeyTweakAdd);
  Nan::SetPrototypeMethod(tpl, "publicKeyTweakMul", BSecp256k1::PublicKeyTweakMul);
  Nan::SetPrototypeMethod(tpl, "publicKeyCombine", BSecp256k1::PublicKeyCombine);
  Nan::SetPrototypeMethod(tpl, "publicKeyNegate", BSecp256k1::PublicKeyNegate);

  // signature
  Nan::SetPrototypeMethod(tpl, "signatureNormalize", BSecp256k1::SignatureNormalize);
  Nan::SetPrototypeMethod(tpl, "signatureNormalizeDER", BSecp256k1::SignatureNormalizeDER);
  Nan::SetPrototypeMethod(tpl, "signatureExport", BSecp256k1::SignatureExport);
  Nan::SetPrototypeMethod(tpl, "signatureImport", BSecp256k1::SignatureImport);
  Nan::SetPrototypeMethod(tpl, "isLowS", BSecp256k1::IsLowS);
  Nan::SetPrototypeMethod(tpl, "isLowDER", BSecp256k1::IsLowDER);

  // ecdsa
  Nan::SetPrototypeMethod(tpl, "sign", BSecp256k1::Sign);
  Nan::SetPrototypeMethod(tpl, "signRecoverable", BSecp256k1::SignRecoverable);
  Nan::SetPrototypeMethod(tpl, "signDER", BSecp256k1::SignDER);
  Nan::SetPrototypeMethod(tpl, "signRecoverableDER", BSecp256k1::SignRecoverableDER);
  Nan::SetPrototypeMethod(tpl, "verify", BSecp256k1::Verify);
  Nan::SetPrototypeMethod(tpl, "verifyDER", BSecp256k1::VerifyDER);
  Nan::SetPrototypeMethod(tpl, "recover", BSecp256k1::Recover);
  Nan::SetPrototypeMethod(tpl, "recoverDER", BSecp256k1::RecoverDER);

  // ecdh
  Nan::SetPrototypeMethod(tpl, "derive", BSecp256k1::Derive);

  // schnorr
  Nan::SetPrototypeMethod(tpl, "schnorrSign", BSecp256k1::SchnorrSign);
  Nan::SetPrototypeMethod(tpl, "schnorrVerify", BSecp256k1::SchnorrVerify);
  Nan::SetPrototypeMethod(tpl, "schnorrVerifyBatch", BSecp256k1::SchnorrVerifyBatch);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(secp256k1_constructor);

  Nan::Set(target, Nan::New("Secp256k1").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSecp256k1::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Secp256k1 instance.");

  secp256k1_context *ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  if (ctx == NULL)
    return Nan::ThrowError("Could not create Secp256k1 instance.");

  BSecp256k1 *secp = new BSecp256k1();
  secp->ctx = ctx;
  secp->scratch = NULL;
  secp->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSecp256k1::Randomize) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(entropy_buf, ENTROPY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(entropy_buf, 32, ENTROPY_LENGTH_INVALID);

  const unsigned char *entropy =
    (const unsigned char *)node::Buffer::Data(entropy_buf);

  if (!secp256k1_context_randomize(secp->ctx, entropy))
    return Nan::ThrowError(RANDOMIZATION_FAILURE);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BSecp256k1::PrivateKeyGenerate) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> entropy_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(entropy_buf, ENTROPY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(entropy_buf, 32, ENTROPY_LENGTH_INVALID);

  const unsigned char *entropy =
    (const unsigned char *)node::Buffer::Data(entropy_buf);

  unsigned char out[32];

  assert(secp256k1_ec_privkey_generate(secp->ctx, out, entropy));

  info.GetReturnValue().Set(COPY_BUFFER(out, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyVerify) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  if (node::Buffer::Length(priv_buf) != 32)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = secp256k1_ec_seckey_verify(secp->ctx, priv);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::PrivateKeyExport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned char out[32];

  if (!secp256k1_ec_privkey_export(secp->ctx, out, priv))
    return Nan::ThrowError(EC_PRIVATE_KEY_EXPORT_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(out, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyImport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PRIVATE_KEY_TYPE_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);
  unsigned char priv[32];

  if (!secp256k1_ec_privkey_import(secp->ctx, priv, inp, inp_len))
    return Nan::ThrowError(EC_PRIVATE_KEY_IMPORT_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(priv, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyReduce) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);

  unsigned char out[32];

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  size_t priv_len = (size_t)node::Buffer::Length(priv_buf);

  if (!secp256k1_ec_privkey_reduce(secp->ctx, out, priv, priv_len))
    return Nan::ThrowError(EC_PRIVATE_KEY_RANGE_INVALID);

  info.GetReturnValue().Set(COPY_BUFFER(out, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyNegate) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  unsigned char priv[32];
  memcpy(priv, node::Buffer::Data(priv_buf), 32);

  if (!secp256k1_ec_privkey_negate_safe(secp->ctx, priv))
    return Nan::ThrowError(EC_PRIVATE_KEY_RANGE_INVALID);

  info.GetReturnValue().Set(COPY_BUFFER(priv, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyInvert) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  unsigned char priv[32];
  memcpy(priv, node::Buffer::Data(priv_buf), 32);

  if (!secp256k1_ec_privkey_invert(secp->ctx, priv))
    return Nan::ThrowError(EC_PRIVATE_KEY_RANGE_INVALID);

  info.GetReturnValue().Set(COPY_BUFFER(priv, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyTweakAdd) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  unsigned char priv[32];
  memcpy(priv, node::Buffer::Data(priv_buf), 32);

  v8::Local<v8::Object> tweak_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buf, 32, TWEAK_LENGTH_INVALID);

  const unsigned char *tweak =
    (const unsigned char *)node::Buffer::Data(tweak_buf);

  if (!secp256k1_ec_privkey_tweak_add(secp->ctx, priv, tweak))
    return Nan::ThrowError(EC_PRIVATE_KEY_TWEAK_ADD_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(priv, 32));
}

NAN_METHOD(BSecp256k1::PrivateKeyTweakMul) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  unsigned char priv[32];
  memcpy(priv, node::Buffer::Data(priv_buf), 32);

  v8::Local<v8::Object> tweak_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buf, 32, TWEAK_LENGTH_INVALID);

  const unsigned char *tweak =
    (const unsigned char *)node::Buffer::Data(tweak_buf);

  if (!secp256k1_ec_privkey_tweak_mul(secp->ctx, priv, tweak))
    return Nan::ThrowError(EC_PRIVATE_KEY_TWEAK_MUL_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(priv, 32));
}

NAN_METHOD(BSecp256k1::PublicKeyCreate) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> priv_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_create(secp->ctx, &pub, priv))
    return Nan::ThrowError(EC_PUBLIC_KEY_CREATE_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyConvert) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyFromUniform) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(data_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(data_buf, 32, TWEAK_LENGTH_INVALID);

  const unsigned char *data =
    (const unsigned char *)node::Buffer::Data(data_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  assert(secp256k1_pubkey_from_uniform(secp->ctx, &pub, data) == 1);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyToUniform) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  v8::Local<v8::Object> hint_object = info[1].As<v8::Object>();
  CHECK_TYPE_NUMBER(hint_object, HINT_TYPE_INVALID);

  unsigned int hint = (unsigned int)Nan::To<uint32_t>(hint_object).FromJust();

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  unsigned char out[32];

  if (!secp256k1_pubkey_to_uniform(secp->ctx, out, &pub, hint))
    return Nan::ThrowError(EC_PUBLIC_KEY_INVERT_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(out, 32));
}

NAN_METHOD(BSecp256k1::PublicKeyFromHash) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(data_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(data_buf, 64, TWEAK_LENGTH_INVALID);

  const unsigned char *data =
    (const unsigned char *)node::Buffer::Data(data_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_pubkey_from_hash(secp->ctx, &pub, data))
    return Nan::ThrowError(EC_PUBLIC_KEY_COMBINE_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyToHash) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(entropy_buf, ENTROPY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(entropy_buf, 32, ENTROPY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  const unsigned char *entropy =
    (const unsigned char *)node::Buffer::Data(entropy_buf);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  unsigned char out[64];

  if (!secp256k1_pubkey_to_hash(secp->ctx, out, &pub, entropy))
    return Nan::ThrowError(EC_PUBLIC_KEY_INVERT_FAIL);

  info.GetReturnValue().Set(COPY_BUFFER(out, 64));
}

NAN_METHOD(BSecp256k1::PublicKeyVerify) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  secp256k1_pubkey pub;

  int result = secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::PublicKeyExport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const uint8_t *inp = (const uint8_t *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);
  secp256k1_pubkey pub;
  uint8_t x[32];
  uint8_t y[32];

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  if (!secp256k1_ec_pubkey_export(secp->ctx, x, y, &pub))
    return Nan::ThrowError(EC_PUBLIC_KEY_EXPORT_FAIL);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, COPY_BUFFER(x, 32));
  Nan::Set(ret, 1, COPY_BUFFER(y, 32));

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSecp256k1::PublicKeyImport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  const uint8_t *x = NULL;
  size_t x_len = 0;
  const uint8_t *y = NULL;
  size_t y_len = 0;
  int sign = -1;

  if (!info[0]->IsUndefined() && !info[0]->IsNull()) {
    v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();

    if (!node::Buffer::HasInstance(xbuf))
      return Nan::ThrowTypeError(COORD_TYPE_INVALID);

    x = (const uint8_t *)node::Buffer::Data(xbuf);
    x_len = node::Buffer::Length(xbuf);
  }

  if (!info[1]->IsUndefined() && !info[1]->IsNull()) {
    v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(ybuf))
      return Nan::ThrowTypeError(COORD_TYPE_INVALID);

    y = (const uint8_t *)node::Buffer::Data(ybuf);
    y_len = node::Buffer::Length(ybuf);
  }

  if (!info[2]->IsUndefined() && !info[2]->IsNull()) {
    if (!info[2]->IsBoolean())
      return Nan::ThrowTypeError(SIGN_TYPE_INVALID);

    sign = (int)Nan::To<bool>(info[2]).FromJust();
  }

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[3], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_import(secp->ctx, &pub, x, x_len, y, y_len, sign))
    return Nan::ThrowError(EC_PUBLIC_KEY_IMPORT_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyTweakAdd) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  v8::Local<v8::Object> tweak_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buf, 32, TWEAK_LENGTH_INVALID);

  const unsigned char *tweak =
    (const unsigned char *)node::Buffer::Data(tweak_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[2], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  if (!secp256k1_ec_pubkey_tweak_add(secp->ctx, &pub, tweak))
    return Nan::ThrowError(EC_PUBLIC_KEY_TWEAK_ADD_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyTweakMul) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  v8::Local<v8::Object> tweak_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(tweak_buf, TWEAK_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(tweak_buf, 32, TWEAK_LENGTH_INVALID);

  const unsigned char *tweak =
    (const unsigned char *)node::Buffer::Data(tweak_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[2], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  if (!secp256k1_ec_pubkey_tweak_mul(secp->ctx, &pub, tweak))
    return Nan::ThrowError(EC_PUBLIC_KEY_TWEAK_MUL_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyCombine) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Array> inp_buffers = info[0].As<v8::Array>();
  CHECK_TYPE_ARRAY(inp_buffers, EC_PUBLIC_KEYS_TYPE_INVALID);
  CHECK_LENGTH_GT_ZERO(inp_buffers, EC_PUBLIC_KEYS_LENGTH_INVALID);

  size_t len = (size_t)inp_buffers->Length();

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey **pubs =
    (secp256k1_pubkey **)malloc(len * sizeof(secp256k1_pubkey *));

  secp256k1_pubkey *pub_data =
    (secp256k1_pubkey *)malloc(len * sizeof(secp256k1_pubkey));

#define FREE_BATCH do {                 \
  if (pubs != NULL) free(pubs);         \
  if (pub_data != NULL) free(pub_data); \
} while (0)

  if (pubs == NULL || pub_data == NULL) {
    FREE_BATCH;
    return Nan::ThrowError(ALLOCATION_FAILURE);
  }

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Object> pub_buf =
      Nan::Get(inp_buffers, i).ToLocalChecked().As<v8::Object>();

    CHECK_TYPE_BUFFER(pub_buf, EC_PUBLIC_KEY_TYPE_INVALID);
    CHECK_BUFFER_LENGTH2(pub_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

    const unsigned char *inp =
      (const unsigned char *)node::Buffer::Data(pub_buf);
    size_t inp_len = node::Buffer::Length(pub_buf);

    if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub_data[i], inp, inp_len)) {
      FREE_BATCH;
      return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
    }

    pubs[i] = &pub_data[i];
  }

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_combine(secp->ctx, &pub, pubs, len)) {
    FREE_BATCH;
    return Nan::ThrowError(EC_PUBLIC_KEY_COMBINE_FAIL);
  }

  FREE_BATCH;

#undef FREE_BATCH

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::PublicKeyNegate) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(inp_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[1], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, inp, inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  if (!secp256k1_ec_pubkey_negate(secp->ctx, &pub))
    return Nan::ThrowError(EC_PUBLIC_KEY_NEGATE_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::SignatureNormalize) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(inp_buf, 64, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);

  secp256k1_ecdsa_signature sigin;

  if (!secp256k1_ecdsa_signature_parse_compact(secp->ctx, &sigin, inp))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);

  secp256k1_ecdsa_signature sigout;
  secp256k1_ecdsa_signature_normalize(secp->ctx, &sigout, &sigin);

  unsigned char out[64];

  secp256k1_ecdsa_signature_serialize_compact(secp->ctx, out, &sigout);

  info.GetReturnValue().Set(COPY_BUFFER(out, 64));
}

NAN_METHOD(BSecp256k1::SignatureNormalizeDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH_GT_ZERO(inp_buf, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  secp256k1_ecdsa_signature sigin;

  if (!ecdsa_signature_parse_der_lax(secp->ctx, &sigin, inp, inp_len))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_DER_FAIL);

  secp256k1_ecdsa_signature sigout;
  secp256k1_ecdsa_signature_normalize(secp->ctx, &sigout, &sigin);

  unsigned char out[72];
  size_t out_len = 72;

  if (!secp256k1_ecdsa_signature_serialize_der(secp->ctx, out,
                                               &out_len, &sigout)) {
    return Nan::ThrowError(EC_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::SignatureExport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(inp_buf, 64, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);

  secp256k1_ecdsa_signature sig;

  if (!secp256k1_ecdsa_signature_parse_compact(secp->ctx, &sig, inp))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);

  unsigned char out[72];
  size_t out_len = 72;

  if (!secp256k1_ecdsa_signature_serialize_der(secp->ctx, out,
                                               &out_len, &sig)) {
    return Nan::ThrowError(EC_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::SignatureImport) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH_GT_ZERO(inp_buf, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  secp256k1_ecdsa_signature sig;

  if (!ecdsa_signature_parse_der_lax(secp->ctx, &sig, inp, inp_len))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_DER_FAIL);

  unsigned char out[64];

  secp256k1_ecdsa_signature_serialize_compact(secp->ctx, out, &sig);

  info.GetReturnValue().Set(COPY_BUFFER(out, 64));
}

NAN_METHOD(BSecp256k1::IsLowS) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  if (inp_len != 64)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  secp256k1_ecdsa_signature sig;

  if (!secp256k1_ecdsa_signature_parse_compact(secp->ctx, &sig, inp))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = !secp256k1_ecdsa_signature_normalize(secp->ctx, NULL, &sig);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::IsLowDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> inp_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(inp_buf, EC_SIGNATURE_TYPE_INVALID);

  const unsigned char *inp = (const unsigned char *)node::Buffer::Data(inp_buf);
  size_t inp_len = node::Buffer::Length(inp_buf);

  secp256k1_ecdsa_signature sig;

  if (!ecdsa_signature_parse_der_lax(secp->ctx, &sig, inp, inp_len))
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(false));

  int result = !secp256k1_ecdsa_signature_normalize(secp->ctx, NULL, &sig);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::Sign) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned char msg32[32];
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  secp256k1_ecdsa_signature sig;

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_sign(secp->ctx, &sig, msg32, priv, noncefn, NULL))
    return Nan::ThrowError(EC_SIGN_FAIL);

  unsigned char out[64];

  secp256k1_ecdsa_signature_serialize_compact(secp->ctx, out, &sig);

  info.GetReturnValue().Set(COPY_BUFFER(out, 64));
}

NAN_METHOD(BSecp256k1::SignRecoverable) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned char msg32[32];
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  secp256k1_ecdsa_recoverable_signature sig;

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_sign_recoverable(secp->ctx, &sig, msg32,
                                        priv, noncefn, NULL)) {
    return Nan::ThrowError(EC_SIGN_FAIL);
  }

  int recid;
  unsigned char out[64];

  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp->ctx, out,
                                                          &recid, &sig);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, COPY_BUFFER(out, 64));
  Nan::Set(ret, 1, Nan::New<v8::Number>(recid));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSecp256k1::SignDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned char msg32[32];
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  secp256k1_ecdsa_signature sig;

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_sign(secp->ctx, &sig, msg32, priv, noncefn, NULL))
    return Nan::ThrowError(EC_SIGN_FAIL);

  unsigned char out[72];
  size_t out_len = 72;

  if (!secp256k1_ecdsa_signature_serialize_der(secp->ctx, out,
                                               &out_len, &sig)) {
    return Nan::ThrowError(EC_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::SignRecoverableDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  unsigned char msg32[32];
  secp256k1_nonce_function noncefn = secp256k1_nonce_function_rfc6979;
  secp256k1_ecdsa_recoverable_signature sig;

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  if (!secp256k1_ecdsa_sign_recoverable(secp->ctx, &sig, msg32,
                                        priv, noncefn, NULL)) {
    return Nan::ThrowError(EC_SIGN_FAIL);
  }

  int recid;
  unsigned char out[72];
  size_t out_len = 72;

  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp->ctx, out,
                                                          &recid, &sig);

  secp256k1_ecdsa_signature sig_;

  if (!secp256k1_ecdsa_signature_parse_compact(secp->ctx, &sig_, out))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);

  if (!secp256k1_ecdsa_signature_serialize_der(secp->ctx, out,
                                               &out_len, &sig_)) {
    return Nan::ThrowError(EC_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();

  Nan::Set(ret, 0, COPY_BUFFER(out, out_len));
  Nan::Set(ret, 1, Nan::New<v8::Number>(recid));

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BSecp256k1::Verify) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> sig_inp_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_inp_buf, 64, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *sig_inp =
    (const unsigned char *)node::Buffer::Data(sig_inp_buf);

  v8::Local<v8::Object> pub_buf = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(pub_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pub_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *pub_inp =
    (const unsigned char *)node::Buffer::Data(pub_buf);
  size_t pub_inp_len = node::Buffer::Length(pub_buf);

  secp256k1_ecdsa_signature sig;

  if (!secp256k1_ecdsa_signature_parse_compact(secp->ctx, &sig, sig_inp))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);

  unsigned char msg32[32];

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, pub_inp, pub_inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  secp256k1_ecdsa_signature_normalize(secp->ctx, &sig, &sig);

  int result = secp256k1_ecdsa_verify(secp->ctx, &sig, msg32, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::VerifyDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> sig_inp_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH_GT_ZERO(sig_inp_buf, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *sig_inp =
    (const unsigned char *)node::Buffer::Data(sig_inp_buf);
  size_t sig_inp_len = node::Buffer::Length(sig_inp_buf);

  v8::Local<v8::Object> pub_buf = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(pub_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pub_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *pub_inp =
    (const unsigned char *)node::Buffer::Data(pub_buf);
  size_t pub_inp_len = node::Buffer::Length(pub_buf);

  secp256k1_ecdsa_signature sig;

  if (!ecdsa_signature_parse_der_lax(secp->ctx, &sig, sig_inp, sig_inp_len))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_DER_FAIL);

  unsigned char msg32[32];

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, pub_inp, pub_inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  secp256k1_ecdsa_signature_normalize(secp->ctx, &sig, &sig);

  int result = secp256k1_ecdsa_verify(secp->ctx, &sig, msg32, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::Recover) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> sig_inp_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_inp_buf, 64, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *sig_inp =
    (const unsigned char *)node::Buffer::Data(sig_inp_buf);

  v8::Local<v8::Object> recid_object = info[2].As<v8::Object>();
  CHECK_TYPE_NUMBER(recid_object, RECOVERY_ID_TYPE_INVALID);
  CHECK_NUMBER_IN_INTERVAL(recid_object, -1, 4, RECOVERY_ID_VALUE_INVALID);

  int recid = (int)Nan::To<int64_t>(recid_object).FromJust();

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[3], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_ecdsa_recoverable_signature sig;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp->ctx,
                                                           &sig,
                                                           sig_inp,
                                                           recid)) {
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);
  }

  unsigned char msg32[32];

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  secp256k1_pubkey pub;

  if (!secp256k1_ecdsa_recover(secp->ctx, &pub, &sig, msg32))
    return Nan::ThrowError(EC_RECOVER_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len,
                                &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::RecoverDER) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg = (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> sig_inp_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH_GT_ZERO(sig_inp_buf, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *sig_inp =
    (const unsigned char *)node::Buffer::Data(sig_inp_buf);
  size_t sig_inp_len = node::Buffer::Length(sig_inp_buf);

  v8::Local<v8::Object> recid_object = info[2].As<v8::Object>();
  CHECK_TYPE_NUMBER(recid_object, RECOVERY_ID_TYPE_INVALID);
  CHECK_NUMBER_IN_INTERVAL(recid_object, -1, 4, RECOVERY_ID_VALUE_INVALID);

  int recid = (int)Nan::To<int64_t>(recid_object).FromJust();

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[3], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  secp256k1_ecdsa_signature orig;

  if (!ecdsa_signature_parse_der_lax(secp->ctx, &orig, sig_inp, sig_inp_len))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_DER_FAIL);

  unsigned char compact[64];

  secp256k1_ecdsa_signature_serialize_compact(secp->ctx, compact, &orig);

  secp256k1_ecdsa_recoverable_signature sig;

  if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp->ctx,
                                                           &sig,
                                                           compact,
                                                           recid)) {
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);
  }

  unsigned char msg32[32];

  secp256k1_ecdsa_reduce(secp->ctx, msg32, msg, msg_len);

  secp256k1_pubkey pub;

  if (!secp256k1_ecdsa_recover(secp->ctx, &pub, &sig, msg32))
    return Nan::ThrowError(EC_RECOVER_FAIL);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ec_pubkey_serialize(secp->ctx, out, &out_len, &pub, flags);

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

static int
ecdh_hash_function_raw(unsigned char *out,
                       const unsigned char *x,
                       const unsigned char *y,
                       void *data) {
  unsigned int flags = *((unsigned int *)data);

  if (flags == SECP256K1_EC_COMPRESSED) {
    out[0] = 0x02 | (y[31] & 1);
    memcpy(out + 1, x, 32);
  } else {
    out[0] = 0x04;
    memcpy(out + 1, x, 32);
    memcpy(out + 33, y, 32);
  }

  return 1;
}

NAN_METHOD(BSecp256k1::Derive) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> pub_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(pub_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pub_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *pub_inp =
    (const unsigned char *)node::Buffer::Data(pub_buf);
  size_t pub_inp_len = node::Buffer::Length(pub_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, pub_inp, pub_inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  unsigned int flags = SECP256K1_EC_COMPRESSED;
  UPDATE_COMPRESSED_VALUE(flags, info[2], SECP256K1_EC_COMPRESSED,
                                          SECP256K1_EC_UNCOMPRESSED);

  unsigned char out[65];
  size_t out_len = 65;

  secp256k1_ecdh_hash_function hashfp = ecdh_hash_function_raw;

  if (!secp256k1_ecdh(secp->ctx, out, &pub, priv, hashfp, &flags))
    return Nan::ThrowError(ECDH_FAIL);

  if (flags == SECP256K1_EC_COMPRESSED)
    out_len = 33;

  info.GetReturnValue().Set(COPY_BUFFER(out, out_len));
}

NAN_METHOD(BSecp256k1::SchnorrSign) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg =
    (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(priv_buf, EC_PRIVATE_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(priv_buf, 32, EC_PRIVATE_KEY_LENGTH_INVALID);

  const unsigned char *priv =
    (const unsigned char *)node::Buffer::Data(priv_buf);

  secp256k1_schnorrleg sig;

  if (!secp256k1_schnorrleg_sign(secp->ctx, &sig, msg, msg_len, priv))
    return Nan::ThrowError(EC_SIGN_FAIL);

  unsigned char out[64];

  secp256k1_schnorrleg_serialize(secp->ctx, out, &sig);

  info.GetReturnValue().Set(COPY_BUFFER(out, 64));
}

NAN_METHOD(BSecp256k1::SchnorrVerify) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  CHECK_TYPE_BUFFER(msg_buf, MSG_TYPE_INVALID);

  const unsigned char *msg =
    (const unsigned char *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  v8::Local<v8::Object> sig_inp_buf = info[1].As<v8::Object>();
  CHECK_TYPE_BUFFER(sig_inp_buf, EC_SIGNATURE_TYPE_INVALID);
  CHECK_BUFFER_LENGTH(sig_inp_buf, 64, EC_SIGNATURE_LENGTH_INVALID);

  const unsigned char *sig_inp =
    (const unsigned char *)node::Buffer::Data(sig_inp_buf);

  v8::Local<v8::Object> pub_buf = info[2].As<v8::Object>();
  CHECK_TYPE_BUFFER(pub_buf, EC_PUBLIC_KEY_TYPE_INVALID);
  CHECK_BUFFER_LENGTH2(pub_buf, 33, 65, EC_PUBLIC_KEY_LENGTH_INVALID);

  const unsigned char *pub_inp =
    (const unsigned char *)node::Buffer::Data(pub_buf);
  size_t pub_inp_len = node::Buffer::Length(pub_buf);

  secp256k1_schnorrleg sig;

  if (!secp256k1_schnorrleg_parse(secp->ctx, &sig, sig_inp))
    return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);

  secp256k1_pubkey pub;

  if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub, pub_inp, pub_inp_len))
    return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);

  int result = secp256k1_schnorrleg_verify(secp->ctx, &sig, msg, msg_len, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BSecp256k1::SchnorrVerifyBatch) {
  BSecp256k1 *secp = ObjectWrap::Unwrap<BSecp256k1>(info.Holder());

  if (!info[0]->IsArray())
    return Nan::ThrowTypeError(BATCH_TYPE_INVALID);

  v8::Local<v8::Array> batch = info[0].As<v8::Array>();

  size_t len = (size_t)batch->Length();

  if (len == 0)
    return info.GetReturnValue().Set(Nan::New<v8::Boolean>(true));

  const unsigned char **msgs =
    (const unsigned char **)malloc(len * sizeof(unsigned char *));

  size_t *msg_lens = (size_t *)malloc(len * sizeof(size_t));

  secp256k1_schnorrleg **sigs =
    (secp256k1_schnorrleg **)malloc(len * sizeof(secp256k1_schnorrleg *));

  secp256k1_pubkey **pubs =
    (secp256k1_pubkey **)malloc(len * sizeof(secp256k1_pubkey *));

  secp256k1_schnorrleg *sig_data =
    (secp256k1_schnorrleg *)malloc(len * sizeof(secp256k1_schnorrleg));

  secp256k1_pubkey *pub_data =
    (secp256k1_pubkey *)malloc(len * sizeof(secp256k1_pubkey));

#define FREE_BATCH do {                 \
  if (msgs != NULL) free(msgs);         \
  if (msg_lens != NULL) free(msg_lens); \
  if (sigs != NULL) free(sigs);         \
  if (pubs != NULL) free(pubs);         \
  if (sig_data != NULL) free(sig_data); \
  if (pub_data != NULL) free(pub_data); \
} while (0)

  if (msgs == NULL || msg_lens == NULL || sigs == NULL
      || pubs == NULL || sig_data == NULL || pub_data == NULL) {
    FREE_BATCH;
    return Nan::ThrowError(ALLOCATION_FAILURE);
  }

  for (size_t i = 0; i < len; i++) {
    v8::Local<v8::Value> val = Nan::Get(batch, i).ToLocalChecked();

    if (!val->IsArray()) {
      FREE_BATCH;
      return Nan::ThrowTypeError(BATCH_ITEM_TYPE_INVALID);
    }

    v8::Local<v8::Array> item = val.As<v8::Array>();

    if (item->Length() != 3) {
      FREE_BATCH;
      return Nan::ThrowTypeError(BATCH_ITEM_LENGTH_INVALID);
    }

    v8::Local<v8::Object> msg_buf = Nan::Get(item, 0).ToLocalChecked()
                                                     .As<v8::Object>();
    v8::Local<v8::Object> sig_buf = Nan::Get(item, 1).ToLocalChecked()
                                                     .As<v8::Object>();
    v8::Local<v8::Object> pub_buf = Nan::Get(item, 2).ToLocalChecked()
                                                     .As<v8::Object>();

    if (!node::Buffer::HasInstance(msg_buf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError(MSG_TYPE_INVALID);
    }

    if (!node::Buffer::HasInstance(sig_buf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError(EC_SIGNATURE_TYPE_INVALID);
    }

    if (!node::Buffer::HasInstance(pub_buf)) {
      FREE_BATCH;
      return Nan::ThrowTypeError(EC_PUBLIC_KEY_TYPE_INVALID);
    }

    const unsigned char *msg =
      (const unsigned char *)node::Buffer::Data(msg_buf);
    size_t msg_len = node::Buffer::Length(msg_buf);

    const unsigned char *sig =
      (const unsigned char *)node::Buffer::Data(sig_buf);
    size_t sig_len = node::Buffer::Length(sig_buf);

    const unsigned char *pub =
      (const unsigned char *)node::Buffer::Data(pub_buf);
    size_t pub_len = node::Buffer::Length(pub_buf);

    if (sig_len != 64) {
      FREE_BATCH;
      return Nan::ThrowRangeError(EC_SIGNATURE_LENGTH_INVALID);
    }

    if (pub_len != 33 && pub_len != 65) {
      FREE_BATCH;
      return Nan::ThrowRangeError(EC_PUBLIC_KEY_LENGTH_INVALID);
    }

    if (!secp256k1_schnorrleg_parse(secp->ctx, &sig_data[i], sig)) {
      FREE_BATCH;
      return Nan::ThrowError(EC_SIGNATURE_PARSE_FAIL);
    }

    if (!secp256k1_ec_pubkey_parse(secp->ctx, &pub_data[i], pub, pub_len)) {
      FREE_BATCH;
      return Nan::ThrowError(EC_PUBLIC_KEY_PARSE_FAIL);
    }

    msgs[i] = msg;
    msg_lens[i] = msg_len;
    sigs[i] = &sig_data[i];
    pubs[i] = &pub_data[i];
  }

  // Lazy allocation for scratch space. See:
  //   https://github.com/ElementsProject/secp256k1-zkp/issues/69
  //   https://github.com/bitcoin-core/secp256k1/pull/638
  if (secp->scratch == NULL) {
    secp256k1_scratch_space *scratch =
      secp256k1_scratch_space_create(secp->ctx, 1024 * 1024);

    if (scratch == NULL) {
      FREE_BATCH;
      return Nan::ThrowError(ALLOCATION_FAILURE);
    }

    secp->scratch = scratch;
  }

  int result = secp256k1_schnorrleg_verify_batch(secp->ctx, secp->scratch,
                                                 sigs, msgs, msg_lens, pubs,
                                                 len);

  FREE_BATCH;

#undef FREE_BATCH

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
