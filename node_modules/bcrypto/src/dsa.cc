#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/dsa.h>
#include <torsion/util.h>

#include "common.h"
#include "dsa.h"
#include "dsa_async.h"

void
BDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "paramsCreate", BDSA::ParamsCreate);
  Nan::Export(obj, "paramsGenerate", BDSA::ParamsGenerate);
  Nan::Export(obj, "paramsGenerateAsync", BDSA::ParamsGenerateAsync);
  Nan::Export(obj, "paramsBits", BDSA::ParamsBits);
  Nan::Export(obj, "paramsVerify", BDSA::ParamsVerify);
  Nan::Export(obj, "paramsImport", BDSA::ParamsImport);
  Nan::Export(obj, "paramsExport", BDSA::ParamsExport);
  Nan::Export(obj, "privateKeyCreate", BDSA::PrivateKeyCreate);
  Nan::Export(obj, "privateKeyBits", BDSA::PrivateKeyBits);
  Nan::Export(obj, "privateKeyVerify", BDSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyImport", BDSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExport", BDSA::PrivateKeyExport);
  Nan::Export(obj, "publicKeyCreate", BDSA::PublicKeyCreate);
  Nan::Export(obj, "publicKeyBits", BDSA::PublicKeyBits);
  Nan::Export(obj, "publicKeyVerify", BDSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyImport", BDSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExport", BDSA::PublicKeyExport);
  Nan::Export(obj, "signatureExport", BDSA::SignatureExport);
  Nan::Export(obj, "signatureImport", BDSA::SignatureImport);
  Nan::Export(obj, "sign", BDSA::Sign);
  Nan::Export(obj, "signDER", BDSA::SignDER);
  Nan::Export(obj, "verify", BDSA::Verify);
  Nan::Export(obj, "verifyDER", BDSA::VerifyDER);
  Nan::Export(obj, "derive", BDSA::Derive);

  Nan::Set(target, Nan::New("dsa").ToLocalChecked(), obj);
}

NAN_METHOD(BDSA::ParamsCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsCreate() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PARAMS_SIZE);
  size_t out_len = DSA_MAX_PARAMS_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not create params.");

  if (!dsa_params_create(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not create params.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not create params.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::ParamsGenerate) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.paramsGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *params = (uint8_t *)malloc(DSA_MAX_PARAMS_SIZE);
  size_t params_len = DSA_MAX_PARAMS_SIZE;

  if (params == NULL)
    return Nan::ThrowError("Could not generate params.");

  if (!dsa_params_generate(params, &params_len, bits, entropy)) {
    free(params);
    return Nan::ThrowError("Could not generate params.");
  }

  cleanse(entropy, entropy_len);

  params = (uint8_t *)realloc(params, params_len);

  if (params == NULL)
    return Nan::ThrowError("Could not generate params.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)params, params_len).ToLocalChecked());
}

NAN_METHOD(BDSA::ParamsGenerateAsync) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.paramsGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  if (!info[2]->IsFunction())
    return Nan::ThrowTypeError("Second argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  v8::Local<v8::Function> callback = info[2].As<v8::Function>();

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  BDSAWorker *worker = new BDSAWorker(bits, entropy,
                                      new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BDSA::ParamsBits) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsBits() requires arguments.");

  v8::Local<v8::Object> params_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(params_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *params = (const uint8_t *)node::Buffer::Data(params_buf);
  size_t params_len = node::Buffer::Length(params_buf);
  size_t bits = dsa_params_bits(params, params_len);

  if (bits == 0)
    return Nan::ThrowTypeError("Invalid params.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)bits));
}

NAN_METHOD(BDSA::ParamsVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsVerify() requires arguments.");

  v8::Local<v8::Object> params_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(params_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *params = (uint8_t *)node::Buffer::Data(params_buf);
  size_t params_len = node::Buffer::Length(params_buf);
  int result = dsa_params_verify(params, params_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::ParamsImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsImport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PARAMS_SIZE);
  size_t out_len = DSA_MAX_PARAMS_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_params_import(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::ParamsExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsExport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PARAMS_SIZE);
  size_t out_len = DSA_MAX_PARAMS_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_params_export(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyCreate) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.privateKeyCreate() requires arguments.");

  v8::Local<v8::Object> params_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(params_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  uint8_t *params = (uint8_t *)node::Buffer::Data(params_buf);
  size_t params_len = node::Buffer::Length(params_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *key = (uint8_t *)malloc(DSA_MAX_PRIV_SIZE);
  size_t key_len = DSA_MAX_PRIV_SIZE;

  if (key == NULL)
    return Nan::ThrowError("Could not generate key.");

  if (!dsa_privkey_create(key, &key_len, params, params_len, entropy)) {
    free(key);
    return Nan::ThrowError("Could not generate key.");
  }

  cleanse(entropy, entropy_len);

  key = (uint8_t *)realloc(key, key_len);

  if (key == NULL)
    return Nan::ThrowError("Could not generate key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, key_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyBits) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyBits() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  size_t bits = dsa_privkey_bits(key, key_len);

  if (bits == 0)
    return Nan::ThrowTypeError("Invalid private key.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)bits));
}

NAN_METHOD(BDSA::PrivateKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = dsa_privkey_verify(key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PrivateKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PRIV_SIZE);
  size_t out_len = DSA_MAX_PRIV_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_privkey_import(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PRIV_SIZE);
  size_t out_len = DSA_MAX_PRIV_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_privkey_export(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PUB_SIZE);
  size_t out_len = DSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_pubkey_create(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PublicKeyBits) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyBits() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  size_t bits = dsa_pubkey_bits(key, key_len);

  if (bits == 0)
    return Nan::ThrowTypeError("Invalid private key.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)bits));
}

NAN_METHOD(BDSA::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = dsa_pubkey_verify(key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PublicKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyImport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PUB_SIZE);
  size_t out_len = DSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_pubkey_import(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PublicKeyExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_PUB_SIZE);
  size_t out_len = DSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  if (!dsa_pubkey_export(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not compute key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not compute key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::SignatureExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.signatureExport() requires arguments.");

  v8::Local<v8::Object> sig_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sig_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);
  size_t size = 0;
  uint8_t out[DSA_MAX_DER_SIZE];
  size_t out_len = DSA_MAX_DER_SIZE;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    size = Nan::To<uint32_t>(info[1]).FromJust();
  }

  if (!dsa_sig_export(out, &out_len, sig, sig_len, size))
    return Nan::ThrowError("Could not export signature.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::SignatureImport) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.signatureImport() requires arguments.");

  v8::Local<v8::Object> sig_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(sig_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);
  uint32_t size = Nan::To<uint32_t>(info[1]).FromJust();
  uint8_t out[DSA_MAX_SIG_SIZE];
  size_t out_len = DSA_MAX_SIG_SIZE;

  if (!dsa_sig_import(out, &out_len, sig, sig_len, size))
    return Nan::ThrowError("Could not import signature.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::Sign) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.sign() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t sig[DSA_MAX_SIG_SIZE];
  size_t sig_len = DSA_MAX_SIG_SIZE;

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  if (!dsa_sign(sig, &sig_len, msg, msg_len, key, key_len, entropy))
    return Nan::ThrowError("Could not sign.");

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BDSA::SignDER) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.signDER() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  uint8_t sig[DSA_MAX_DER_SIZE];
  size_t sig_len = DSA_MAX_DER_SIZE;

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  if (!dsa_sign(sig, &sig_len, msg, msg_len, key, key_len, entropy))
    return Nan::ThrowError("Could not sign.");

  assert(dsa_sig_export(sig, &sig_len, sig, sig_len, 0));

  cleanse(entropy, entropy_len);

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BDSA::Verify) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.verify() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sig_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(sig_buf)
      || !node::Buffer::HasInstance(key_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);
  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = dsa_verify(msg, msg_len, sig, sig_len, key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::VerifyDER) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.verify() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> sig_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(sig_buf)
      || !node::Buffer::HasInstance(key_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *der = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t der_len = node::Buffer::Length(sig_buf);
  uint8_t *key = (uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t sig[DSA_MAX_SIG_SIZE];
  size_t sig_len = DSA_MAX_SIG_SIZE;
  size_t size = (dsa_pubkey_qbits(key, key_len) + 7) / 8;
  int result = size > 0
    && dsa_sig_import(sig, &sig_len, der, der_len, size)
    && dsa_verify(msg, msg_len, sig, sig_len, key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::Derive) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.derive() requires arguments.");

  v8::Local<v8::Object> pub_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> priv_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pub_buf)
      || !node::Buffer::HasInstance(priv_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *pub = (const uint8_t *)node::Buffer::Data(pub_buf);
  size_t pub_len = node::Buffer::Length(pub_buf);
  const uint8_t *priv = (const uint8_t *)node::Buffer::Data(priv_buf);
  size_t priv_len = node::Buffer::Length(priv_buf);
  uint8_t *out = (uint8_t *)malloc(DSA_MAX_SIZE);
  size_t out_len = DSA_MAX_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not derive key.");

  if (!dsa_derive(out, &out_len, pub, pub_len, priv, priv_len)) {
    free(out);
    return Nan::ThrowError("Could not derive key.");
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}
