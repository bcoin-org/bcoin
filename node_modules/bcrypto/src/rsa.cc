#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/rsa.h>
#include <torsion/util.h>

#include "common.h"
#include "rsa.h"
#include "rsa_async.h"

void
BRSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyGenerate", BRSA::PrivateKeyGenerate);
  Nan::Export(obj, "privateKeyGenerateAsync", BRSA::PrivateKeyGenerateAsync);
  Nan::Export(obj, "privateKeyBits", BRSA::PrivateKeyBits);
  Nan::Export(obj, "privateKeyVerify", BRSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyImport", BRSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExport", BRSA::PrivateKeyExport);
  Nan::Export(obj, "publicKeyCreate", BRSA::PublicKeyCreate);
  Nan::Export(obj, "publicKeyBits", BRSA::PublicKeyBits);
  Nan::Export(obj, "publicKeyVerify", BRSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyImport", BRSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExport", BRSA::PublicKeyExport);
  Nan::Export(obj, "sign", BRSA::Sign);
  Nan::Export(obj, "verify", BRSA::Verify);
  Nan::Export(obj, "encrypt", BRSA::Encrypt);
  Nan::Export(obj, "decrypt", BRSA::Decrypt);
  Nan::Export(obj, "signPSS", BRSA::SignPSS);
  Nan::Export(obj, "verifyPSS", BRSA::VerifyPSS);
  Nan::Export(obj, "encryptOAEP", BRSA::EncryptOAEP);
  Nan::Export(obj, "decryptOAEP", BRSA::DecryptOAEP);
  Nan::Export(obj, "veil", BRSA::Veil);
  Nan::Export(obj, "unveil", BRSA::Unveil);

  Nan::Set(target, Nan::New("rsa").ToLocalChecked(), obj);
}

NAN_METHOD(BRSA::PrivateKeyGenerate) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.privateKeyGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> entropy_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exp = (uint64_t)Nan::To<int64_t>(info[1]).FromJust();
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *key = (uint8_t *)malloc(RSA_MAX_PRIV_SIZE);
  size_t key_len = RSA_MAX_PRIV_SIZE;

  if (key == NULL)
    return Nan::ThrowError("Could not generate key.");

  if (!rsa_privkey_generate(key, &key_len, bits, exp, entropy)) {
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

NAN_METHOD(BRSA::PrivateKeyGenerateAsync) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.privateKeyGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> entropy_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(entropy_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  if (!info[3]->IsFunction())
    return Nan::ThrowTypeError("Third argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exp = (uint64_t)Nan::To<int64_t>(info[1]).FromJust();
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);
  v8::Local<v8::Function> callback = info[3].As<v8::Function>();

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  BRSAWorker *worker = new BRSAWorker(bits, exp, entropy,
                                      new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BRSA::PrivateKeyBits) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyBits() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  size_t bits = rsa_privkey_bits(key, key_len);

  if (bits == 0)
    return Nan::ThrowTypeError("Invalid private key.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)bits));
}

NAN_METHOD(BRSA::PrivateKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = rsa_privkey_verify(key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PrivateKeyImport) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *out = (uint8_t *)malloc(RSA_MAX_PRIV_SIZE);
  size_t out_len = RSA_MAX_PRIV_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not import key.");

  if (!rsa_privkey_import(out, &out_len, key, key_len, entropy)) {
    free(out);
    return Nan::ThrowError("Could not import key.");
  }

  cleanse(entropy, entropy_len);

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not import key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PrivateKeyExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(RSA_MAX_PRIV_SIZE);
  size_t out_len = RSA_MAX_PRIV_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not export key.");

  if (!rsa_privkey_export(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not export key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not export key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PublicKeyCreate) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyCreate() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(RSA_MAX_PUB_SIZE);
  size_t out_len = RSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not create key.");

  if (!rsa_pubkey_create(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not create key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not create key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PublicKeyBits) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyBits() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  size_t bits = rsa_pubkey_bits(key, key_len);

  if (bits == 0)
    return Nan::ThrowTypeError("Invalid public key.");

  info.GetReturnValue().Set(Nan::New<v8::Uint32>((uint32_t)bits));
}

NAN_METHOD(BRSA::PublicKeyVerify) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = rsa_pubkey_verify(key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PublicKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyImport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(RSA_MAX_PUB_SIZE);
  size_t out_len = RSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not import key.");

  if (!rsa_pubkey_import(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not import key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not import key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PublicKeyExport) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("Arguments must be buffers.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(RSA_MAX_PUB_SIZE);
  size_t out_len = RSA_MAX_PUB_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not export key.");

  if (!rsa_pubkey_export(out, &out_len, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not export key.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not export key.");

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Sign) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.sign() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *sig = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t sig_len = RSA_MAX_MOD_SIZE;

  if (sig == NULL)
    return Nan::ThrowError("Could not sign message.");

  if (!rsa_sign(sig, &sig_len, type, msg, msg_len, key, key_len, entropy)) {
    free(sig);
    return Nan::ThrowError("Could not sign message.");
  }

  cleanse(entropy, entropy_len);

  sig = (uint8_t *)realloc(sig, sig_len);

  if (sig == NULL)
    return Nan::ThrowError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Verify) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.verify() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sig_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(sig_buf)
      || !node::Buffer::HasInstance(key_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int result = rsa_verify(type, msg, msg_len, sig, sig_len, key, key_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::Encrypt) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.encrypt() requires arguments.");

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

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *ct = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t ct_len = RSA_MAX_MOD_SIZE;

  if (ct == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  if (!rsa_encrypt(ct, &ct_len, msg, msg_len, key, key_len, entropy)) {
    free(ct);
    return Nan::ThrowError("Could not encrypt message.");
  }

  cleanse(entropy, entropy_len);

  ct = (uint8_t *)realloc(ct, ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Decrypt) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.decrypt() requires arguments.");

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

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *pt = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t pt_len = RSA_MAX_MOD_SIZE;

  if (pt == NULL)
    return Nan::ThrowError("Could not decrypt message.");

  if (!rsa_decrypt(pt, &pt_len, msg, msg_len, key, key_len, entropy)) {
    free(pt);
    return Nan::ThrowError("Could not decrypt message.");
  }

  cleanse(entropy, entropy_len);

  pt = (uint8_t *)realloc(pt, pt_len);

  if (pt_len != 0 && pt == NULL)
    return Nan::ThrowError("Could not decrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::SignPSS) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.signPSS() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int salt_len = -1;
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    salt_len = (int)Nan::To<int32_t>(info[4]).FromJust();
  }

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *sig = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t sig_len = RSA_MAX_MOD_SIZE;

  if (sig == NULL)
    return Nan::ThrowError("Could not sign message.");

  if (!rsa_sign_pss(sig, &sig_len, type, msg, msg_len, key, key_len, salt_len, entropy)) {
    free(sig);
    return Nan::ThrowError("Could not sign message.");
  }

  cleanse(entropy, entropy_len);

  sig = (uint8_t *)realloc(sig, sig_len);

  if (sig == NULL)
    return Nan::ThrowError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::VerifyPSS) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.verifyPSS() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sig_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(sig_buf)
      || !node::Buffer::HasInstance(key_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  int salt_len = -1;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    salt_len = (int)Nan::To<int32_t>(info[4]).FromJust();
  }

  int result = rsa_verify_pss(type, msg, msg_len, sig, sig_len, key, key_len, salt_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::EncryptOAEP) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.encryptOAEP() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  const uint8_t *label = NULL;
  size_t label_len = 0;
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> label_buf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(label_buf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer.");

    label = (const uint8_t *)node::Buffer::Data(label_buf);
    label_len = node::Buffer::Length(label_buf);
  }

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *ct = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t ct_len = RSA_MAX_MOD_SIZE;

  if (ct == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  if (!rsa_encrypt_oaep(ct, &ct_len, type, msg, msg_len, key, key_len, label, label_len, entropy)) {
    free(ct);
    return Nan::ThrowError("Could not encrypt message.");
  }

  cleanse(entropy, entropy_len);

  ct = (uint8_t *)realloc(ct, ct_len);

  if (ct == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::DecryptOAEP) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.decryptOAEP() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> msg_buf = info[1].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  const uint8_t *label = NULL;
  size_t label_len = 0;
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> label_buf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(label_buf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer.");

    label = (const uint8_t *)node::Buffer::Data(label_buf);
    label_len = node::Buffer::Length(label_buf);
  }

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  uint8_t *pt = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t pt_len = RSA_MAX_MOD_SIZE;

  if (pt == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  if (!rsa_decrypt_oaep(pt, &pt_len, type, msg, msg_len, key, key_len, label, label_len, entropy)) {
    free(pt);
    return Nan::ThrowError("Could not encrypt message.");
  }

  cleanse(entropy, entropy_len);

  pt = (uint8_t *)realloc(pt, pt_len);

  if (pt_len != 0 && pt == NULL)
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Veil) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.veil() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();
  v8::Local<v8::Object> entropy_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)
      || !node::Buffer::HasInstance(entropy_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *entropy = (uint8_t *)node::Buffer::Data(entropy_buf);
  size_t entropy_len = node::Buffer::Length(entropy_buf);

  if (entropy_len != 32)
    return Nan::ThrowRangeError("Entropy must be 32 bytes.");

  size_t out_len = (bits + 7) / 8;
  uint8_t *out = (uint8_t *)malloc(out_len);

  if (out == NULL)
    return Nan::ThrowError("Could not veil message.");

  if (!rsa_veil(out, &out_len, msg, msg_len, bits, key, key_len, entropy)) {
    free(out);
    return Nan::ThrowError("Could not veil message.");
  }

  cleanse(entropy, entropy_len);

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Unveil) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.veil() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();
  v8::Local<v8::Object> key_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf)
      || !node::Buffer::HasInstance(key_buf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);
  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();
  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);
  uint8_t *out = (uint8_t *)malloc(RSA_MAX_MOD_SIZE);
  size_t out_len = RSA_MAX_MOD_SIZE;

  if (out == NULL)
    return Nan::ThrowError("Could not unveil message.");

  if (!rsa_unveil(out, &out_len, msg, msg_len, bits, key, key_len)) {
    free(out);
    return Nan::ThrowError("Could not unveil message.");
  }

  out = (uint8_t *)realloc(out, out_len);

  if (out_len != 0 && out == NULL)
    return Nan::ThrowError("Could not unveil message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}
