#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "common.h"
#include "rsa/rsa.h"
#include "rsa.h"
#include "rsa_async.h"

void
BRSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "privateKeyGenerate", BRSA::PrivateKeyGenerate);
  Nan::Export(obj, "privateKeyGenerateAsync", BRSA::PrivateKeyGenerateAsync);
  Nan::Export(obj, "privateKeyCompute", BRSA::PrivateKeyCompute);
  Nan::Export(obj, "privateKeyVerify", BRSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyExport", BRSA::PrivateKeyExport);
  Nan::Export(obj, "privateKeyImport", BRSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExportPKCS8", BRSA::PrivateKeyExportPKCS8);
  Nan::Export(obj, "privateKeyImportPKCS8", BRSA::PrivateKeyImportPKCS8);
  Nan::Export(obj, "publicKeyVerify", BRSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyExport", BRSA::PublicKeyExport);
  Nan::Export(obj, "publicKeyImport", BRSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExportSPKI", BRSA::PublicKeyExportSPKI);
  Nan::Export(obj, "publicKeyImportSPKI", BRSA::PublicKeyImportSPKI);
  Nan::Export(obj, "sign", BRSA::Sign);
  Nan::Export(obj, "verify", BRSA::Verify);
  Nan::Export(obj, "encrypt", BRSA::Encrypt);
  Nan::Export(obj, "decrypt", BRSA::Decrypt);
  Nan::Export(obj, "encryptOAEP", BRSA::EncryptOAEP);
  Nan::Export(obj, "decryptOAEP", BRSA::DecryptOAEP);
  Nan::Export(obj, "signPSS", BRSA::SignPSS);
  Nan::Export(obj, "verifyPSS", BRSA::VerifyPSS);
  Nan::Export(obj, "encryptRaw", BRSA::EncryptRaw);
  Nan::Export(obj, "decryptRaw", BRSA::DecryptRaw);
  Nan::Export(obj, "veil", BRSA::Veil);
  Nan::Export(obj, "unveil", BRSA::Unveil);
  Nan::Export(obj, "hasHash", BRSA::HasHash);

  Nan::Set(target, Nan::New("rsa").ToLocalChecked(), obj);
}

NAN_METHOD(BRSA::PrivateKeyGenerate) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.privateKeyGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exp = Nan::To<int64_t>(info[1]).FromJust();

  bcrypto_rsa_key_t *k = bcrypto_rsa_privkey_generate(
    (int)bits, (unsigned long long)exp);

  if (!k)
    return Nan::ThrowError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PrivateKeyGenerateAsync) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.privateKeyGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsFunction())
    return Nan::ThrowTypeError("Third argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();
  uint64_t exp = Nan::To<int64_t>(info[1]).FromJust();

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();

  BRSAWorker *worker = new BRSAWorker(
    (int)bits,
    (unsigned long long)exp,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BRSA::PrivateKeyCompute) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyCompute() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[7].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  bcrypto_rsa_key_t *k;

  if (!bcrypto_rsa_privkey_compute(&priv, &k))
    return Nan::ThrowError("Could not compute private key.");

  if (!k)
    return info.GetReturnValue().Set(Nan::Null());

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PrivateKeyVerify) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[7].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  bool result = bcrypto_rsa_privkey_verify(&priv);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PrivateKeyExport) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[7].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_rsa_privkey_export(&priv, &out, &out_len))
    return Nan::ThrowError("Could not export private key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PrivateKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_rsa_key_t *k = bcrypto_rsa_privkey_import(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import private key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PrivateKeyExportPKCS8) {
  if (info.Length() < 8)
    return Nan::ThrowError("rsa.privateKeyExportPKCS8() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[7].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_rsa_privkey_export_pkcs8(&priv, &out, &out_len))
    return Nan::ThrowError("Could not export private key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PrivateKeyImportPKCS8) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.privateKeyImportPKCS8() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_rsa_key_t *k = bcrypto_rsa_privkey_import_pkcs8(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import private key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PublicKeyVerify) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  bool result = bcrypto_rsa_pubkey_verify(&pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::PublicKeyExport) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_rsa_pubkey_export(&pub, &out, &out_len))
    return Nan::ThrowError("Could not export public key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PublicKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_rsa_key_t *k = bcrypto_rsa_pubkey_import(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::PublicKeyExportSPKI) {
  if (info.Length() < 2)
    return Nan::ThrowError("rsa.publicKeyExportSPKI() requires arguments.");

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_rsa_pubkey_export_spki(&pub, &out, &out_len))
    return Nan::ThrowError("Could not export public key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BRSA::PublicKeyImportSPKI) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.publicKeyImportSPKI() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_rsa_key_t *k = bcrypto_rsa_pubkey_import_spki(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BRSA::Sign) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.sign() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[8].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[9].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *sig;
  size_t sig_len;

  if (!bcrypto_rsa_sign(alg, md, ml, &priv, &sig, &sig_len))
    return Nan::ThrowError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Verify) {
  if (info.Length() < 5)
    return Nan::ThrowError("rsa.verify() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  bool result = bcrypto_rsa_verify(alg, md, ml, sd, sl, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::Encrypt) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.encrypt() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *ct;
  size_t ct_len;

  if (!bcrypto_rsa_encrypt(md, ml, &pub, &ct, &ct_len))
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Decrypt) {
  if (info.Length() < 9)
    return Nan::ThrowError("rsa.decrypt() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *pt;
  size_t pt_len;

  if (!bcrypto_rsa_decrypt(md, ml, &priv, &pt, &pt_len))
    return Nan::ThrowError("Could not decrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::EncryptOAEP) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.encryptOAEP() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  const uint8_t *ld = NULL;
  size_t ll = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> lbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(lbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    ld = (const uint8_t *)node::Buffer::Data(lbuf);
    ll = node::Buffer::Length(lbuf);
  }

  uint8_t *ct;
  size_t ct_len;

  if (!bcrypto_rsa_encrypt_oaep(alg, md, ml, &pub, ld, ll, &ct, &ct_len))
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::DecryptOAEP) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.decryptOAEP() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[8].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[9].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  const uint8_t *ld = NULL;
  size_t ll = 0;

  if (info.Length() > 10 && !IsNull(info[10])) {
    v8::Local<v8::Object> lbuf = info[10].As<v8::Object>();

    if (!node::Buffer::HasInstance(lbuf))
      return Nan::ThrowTypeError("Eleventh argument must be a buffer.");

    ld = (const uint8_t *)node::Buffer::Data(lbuf);
    ll = node::Buffer::Length(lbuf);
  }

  uint8_t *pt;
  size_t pt_len;

  if (!bcrypto_rsa_decrypt_oaep(alg, md, ml, &priv, ld, ll, &pt, &pt_len))
    return Nan::ThrowError("Could not decrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::SignPSS) {
  if (info.Length() < 10)
    return Nan::ThrowError("rsa.signPSS() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[8].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[9].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  int salt_len = -1;

  if (info.Length() > 10 && !IsNull(info[10])) {
    if (!info[10]->IsNumber())
      return Nan::ThrowTypeError("Eleventh argument must be a number.");

    salt_len = (int)Nan::To<uint32_t>(info[10]).FromJust();
  }

  uint8_t *sig;
  size_t sig_len;

  if (!bcrypto_rsa_sign_pss(alg, md, ml, &priv, salt_len, &sig, &sig_len))
    return Nan::ThrowError("Could not sign message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(BRSA::VerifyPSS) {
  if (info.Length() < 5)
    return Nan::ThrowError("rsa.verifyPSS() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;

  v8::Local<v8::Object> mbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  int salt_len = -1;

  if (info.Length() > 5 && !IsNull(info[5])) {
    if (!info[5]->IsNumber())
      return Nan::ThrowTypeError("Sixth argument must be a number.");

    salt_len = (int)Nan::To<uint32_t>(info[5]).FromJust();
  }

  bool result = bcrypto_rsa_verify_pss(alg, md, ml, sd, sl, &pub, salt_len);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BRSA::EncryptRaw) {
  if (info.Length() < 3)
    return Nan::ThrowError("rsa.encryptRaw() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *ct;
  size_t ct_len;

  if (!bcrypto_rsa_encrypt_raw(md, ml, &pub, &ct, &ct_len))
    return Nan::ThrowError("Could not encrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::DecryptRaw) {
  if (info.Length() < 9)
    return Nan::ThrowError("rsa.decryptRaw() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> nbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> dbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> dpbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> dqbuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> qibuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)
      || !node::Buffer::HasInstance(dbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(dpbuf)
      || !node::Buffer::HasInstance(dqbuf)
      || !node::Buffer::HasInstance(qibuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_rsa_key_t priv;
  bcrypto_rsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.nd = (uint8_t *)node::Buffer::Data(nbuf);
  priv.nl = node::Buffer::Length(nbuf);

  priv.ed = (uint8_t *)node::Buffer::Data(ebuf);
  priv.el = node::Buffer::Length(ebuf);

  priv.dd = (uint8_t *)node::Buffer::Data(dbuf);
  priv.dl = node::Buffer::Length(dbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.dpd = (uint8_t *)node::Buffer::Data(dpbuf);
  priv.dpl = node::Buffer::Length(dpbuf);

  priv.dqd = (uint8_t *)node::Buffer::Data(dqbuf);
  priv.dql = node::Buffer::Length(dqbuf);

  priv.qid = (uint8_t *)node::Buffer::Data(qibuf);
  priv.qil = node::Buffer::Length(qibuf);

  uint8_t *pt;
  size_t pt_len;

  if (!bcrypto_rsa_decrypt_raw(md, ml, &priv, &pt, &pt_len))
    return Nan::ThrowError("Could not decrypt message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)pt, pt_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Veil) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.veil() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *ct;
  size_t ct_len;

  if (!bcrypto_rsa_veil(md, ml, bits, &pub, &ct, &ct_len))
    return Nan::ThrowError("Could not veil message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::Unveil) {
  if (info.Length() < 4)
    return Nan::ThrowError("rsa.unveil() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  v8::Local<v8::Object> nbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ebuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf)
      || !node::Buffer::HasInstance(ebuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  size_t bits = (size_t)Nan::To<uint32_t>(info[1]).FromJust();

  bcrypto_rsa_key_t pub;
  bcrypto_rsa_key_init(&pub);

  pub.nd = (uint8_t *)node::Buffer::Data(nbuf);
  pub.nl = node::Buffer::Length(nbuf);

  pub.ed = (uint8_t *)node::Buffer::Data(ebuf);
  pub.el = node::Buffer::Length(ebuf);

  uint8_t *ct;
  size_t ct_len;

  if (!bcrypto_rsa_unveil(md, ml, bits, &pub, &ct, &ct_len))
    return Nan::ThrowError("Could not unveil message.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)ct, ct_len).ToLocalChecked());
}

NAN_METHOD(BRSA::HasHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("rsa.hasHash() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;
  bool result = bcrypto_rsa_has_hash(alg);

  if (!result && strcmp(alg, "SHA256") == 0)
    return Nan::ThrowError("Algorithms not loaded for RSA.");

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
#endif
