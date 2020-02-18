#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10

#include "common.h"
#include "dsa/dsa.h"
#include "dsa.h"
#include "dsa_async.h"

void
BDSA::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "paramsGenerate", BDSA::ParamsGenerate);
  Nan::Export(obj, "paramsGenerateAsync", BDSA::ParamsGenerateAsync);
  Nan::Export(obj, "paramsVerify", BDSA::ParamsVerify);
  Nan::Export(obj, "paramsExport", BDSA::ParamsExport);
  Nan::Export(obj, "paramsImport", BDSA::ParamsImport);
  Nan::Export(obj, "privateKeyCreate", BDSA::PrivateKeyCreate);
  Nan::Export(obj, "privateKeyCompute", BDSA::PrivateKeyCompute);
  Nan::Export(obj, "privateKeyVerify", BDSA::PrivateKeyVerify);
  Nan::Export(obj, "privateKeyExport", BDSA::PrivateKeyExport);
  Nan::Export(obj, "privateKeyImport", BDSA::PrivateKeyImport);
  Nan::Export(obj, "privateKeyExportPKCS8", BDSA::PrivateKeyExportPKCS8);
  Nan::Export(obj, "privateKeyImportPKCS8", BDSA::PrivateKeyImportPKCS8);
  Nan::Export(obj, "publicKeyVerify", BDSA::PublicKeyVerify);
  Nan::Export(obj, "publicKeyExport", BDSA::PublicKeyExport);
  Nan::Export(obj, "publicKeyImport", BDSA::PublicKeyImport);
  Nan::Export(obj, "publicKeyExportSPKI", BDSA::PublicKeyExportSPKI);
  Nan::Export(obj, "publicKeyImportSPKI", BDSA::PublicKeyImportSPKI);
  Nan::Export(obj, "sign", BDSA::Sign);
  Nan::Export(obj, "verify", BDSA::Verify);
  Nan::Export(obj, "derive", BDSA::Derive);

  Nan::Set(target, Nan::New("dsa").ToLocalChecked(), obj);
}

NAN_METHOD(BDSA::ParamsGenerate) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsGenerate() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  bcrypto_dsa_key_t *k = bcrypto_dsa_params_generate((int)bits);

  if (!k)
    return Nan::ThrowTypeError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::ParamsGenerateAsync) {
  if (info.Length() < 2)
    return Nan::ThrowError("dsa.paramsGenerateAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  if (!info[1]->IsFunction())
    return Nan::ThrowTypeError("Second argument must be a function.");

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  v8::Local<v8::Function> callback = info[1].As<v8::Function>();

  BDSAWorker *worker = new BDSAWorker(
    (int)bits,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BDSA::ParamsVerify) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.paramsVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t params;
  bcrypto_dsa_key_init(&params);

  params.pd = (uint8_t *)node::Buffer::Data(pbuf);
  params.pl = node::Buffer::Length(pbuf);

  params.qd = (uint8_t *)node::Buffer::Data(qbuf);
  params.ql = node::Buffer::Length(qbuf);

  params.gd = (uint8_t *)node::Buffer::Data(gbuf);
  params.gl = node::Buffer::Length(gbuf);

  bool result = bcrypto_dsa_params_verify(&params);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::ParamsExport) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.paramsExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t params;
  bcrypto_dsa_key_init(&params);

  params.pd = (uint8_t *)node::Buffer::Data(pbuf);
  params.pl = node::Buffer::Length(pbuf);

  params.qd = (uint8_t *)node::Buffer::Data(qbuf);
  params.ql = node::Buffer::Length(qbuf);

  params.gd = (uint8_t *)node::Buffer::Data(gbuf);
  params.gl = node::Buffer::Length(gbuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_dsa_params_export(&params, &out, &out_len))
    return Nan::ThrowError("Could not export params.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::ParamsImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.paramsImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_params_import(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import params.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PrivateKeyCreate) {
  if (info.Length() < 3)
    return Nan::ThrowError("dsa.privateKeyCreate() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t params;
  bcrypto_dsa_key_init(&params);

  params.pd = (uint8_t *)node::Buffer::Data(pbuf);
  params.pl = node::Buffer::Length(pbuf);

  params.qd = (uint8_t *)node::Buffer::Data(qbuf);
  params.ql = node::Buffer::Length(qbuf);

  params.gd = (uint8_t *)node::Buffer::Data(gbuf);
  params.gl = node::Buffer::Length(gbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_privkey_create(&params);

  if (!k)
    return Nan::ThrowError("Could not generate key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->yd, k->yl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->xd, k->xl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PrivateKeyCompute) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *y;
  size_t y_len;

  if (!bcrypto_dsa_privkey_compute(&priv, &y, &y_len))
    return Nan::ThrowError("Could not compute private key.");

  if (!y)
    return info.GetReturnValue().Set(Nan::Null());

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)y, y_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyVerify) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  bool result = bcrypto_dsa_privkey_verify(&priv);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PrivateKeyExport) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_dsa_privkey_export(&priv, &out, &out_len))
    return Nan::ThrowError("Could not export private key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_privkey_import(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import private key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->yd, k->yl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->xd, k->xl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PrivateKeyExportPKCS8) {
  if (info.Length() < 5)
    return Nan::ThrowError("dsa.privateKeyExportPKCS8() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_dsa_privkey_export_pkcs8(&priv, &out, &out_len))
    return Nan::ThrowError("Could not export private key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PrivateKeyImportPKCS8) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.privateKeyImportPKCS8() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_privkey_import_pkcs8(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import private key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->yd, k->yl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->xd, k->xl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PublicKeyVerify) {
  if (info.Length() < 4)
    return Nan::ThrowError("dsa.publicKeyVerify() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(pbuf);
  pub.pl = node::Buffer::Length(pbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(qbuf);
  pub.ql = node::Buffer::Length(qbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(gbuf);
  pub.gl = node::Buffer::Length(gbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(ybuf);
  pub.yl = node::Buffer::Length(ybuf);

  bool result = bcrypto_dsa_pubkey_verify(&pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::PublicKeyExport) {
  if (info.Length() < 4)
    return Nan::ThrowError("dsa.publicKeyExport() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(pbuf);
  pub.pl = node::Buffer::Length(pbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(qbuf);
  pub.ql = node::Buffer::Length(qbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(gbuf);
  pub.gl = node::Buffer::Length(gbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(ybuf);
  pub.yl = node::Buffer::Length(ybuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_dsa_pubkey_export(&pub, &out, &out_len))
    return Nan::ThrowError("Could not export public key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PublicKeyImport) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyImport() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_pubkey_import(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->yd, k->yl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::PublicKeyExportSPKI) {
  if (info.Length() < 4)
    return Nan::ThrowError("dsa.publicKeyExportSPKI() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(pbuf);
  pub.pl = node::Buffer::Length(pbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(qbuf);
  pub.ql = node::Buffer::Length(qbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(gbuf);
  pub.gl = node::Buffer::Length(gbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(ybuf);
  pub.yl = node::Buffer::Length(ybuf);

  uint8_t *out;
  size_t out_len;

  if (!bcrypto_dsa_pubkey_export_spki(&pub, &out, &out_len))
    return Nan::ThrowError("Could not export public key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BDSA::PublicKeyImportSPKI) {
  if (info.Length() < 1)
    return Nan::ThrowError("dsa.publicKeyImportSPKI() requires arguments.");

  v8::Local<v8::Object> rbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  bcrypto_dsa_key_t *k = bcrypto_dsa_pubkey_import_spki(rd, rl);

  if (!k)
    return Nan::ThrowError("Could not import public key.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->gd, k->gl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->yd, k->yl).ToLocalChecked());

  bcrypto_dsa_key_free(k);

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::Sign) {
  if (info.Length() < 6)
    return Nan::ThrowError("dsa.sign() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> xbuf = info[5].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)
      || !node::Buffer::HasInstance(xbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  priv.pd = (uint8_t *)node::Buffer::Data(pbuf);
  priv.pl = node::Buffer::Length(pbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(qbuf);
  priv.ql = node::Buffer::Length(qbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(gbuf);
  priv.gl = node::Buffer::Length(gbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(ybuf);
  priv.yl = node::Buffer::Length(ybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(xbuf);
  priv.xl = node::Buffer::Length(xbuf);

  uint8_t *r;
  size_t rl;
  uint8_t *s;
  size_t sl;

  if (!bcrypto_dsa_sign(md, ml, &priv, &r, &rl, &s, &sl))
    return Nan::ThrowError("Could not sign message.");

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::NewBuffer((char *)r, rl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::NewBuffer((char *)s, sl).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BDSA::Verify) {
  if (info.Length() < 7)
    return Nan::ThrowError("dsa.verify() requires arguments.");

  v8::Local<v8::Object> mbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pbuf = info[3].As<v8::Object>();
  v8::Local<v8::Object> qbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> gbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[6].As<v8::Object>();

  if (!node::Buffer::HasInstance(mbuf)
      || !node::Buffer::HasInstance(rbuf)
      || !node::Buffer::HasInstance(sbuf)
      || !node::Buffer::HasInstance(pbuf)
      || !node::Buffer::HasInstance(qbuf)
      || !node::Buffer::HasInstance(gbuf)
      || !node::Buffer::HasInstance(ybuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  const uint8_t *md = (const uint8_t *)node::Buffer::Data(mbuf);
  size_t ml = node::Buffer::Length(mbuf);

  const uint8_t *rd = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rl = node::Buffer::Length(rbuf);

  const uint8_t *sd = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t sl = node::Buffer::Length(sbuf);

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(pbuf);
  pub.pl = node::Buffer::Length(pbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(qbuf);
  pub.ql = node::Buffer::Length(qbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(gbuf);
  pub.gl = node::Buffer::Length(gbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(ybuf);
  pub.yl = node::Buffer::Length(ybuf);

  bool result = bcrypto_dsa_verify(md, ml, rd, rl, sd, sl, &pub);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(BDSA::Derive) {
  if (info.Length() < 9)
    return Nan::ThrowError("dsa.derive() requires arguments.");

  v8::Local<v8::Object> ppbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> pqbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> pgbuf = info[2].As<v8::Object>();
  v8::Local<v8::Object> pybuf = info[3].As<v8::Object>();

  v8::Local<v8::Object> spbuf = info[4].As<v8::Object>();
  v8::Local<v8::Object> sqbuf = info[5].As<v8::Object>();
  v8::Local<v8::Object> sgbuf = info[6].As<v8::Object>();
  v8::Local<v8::Object> sybuf = info[7].As<v8::Object>();
  v8::Local<v8::Object> sxbuf = info[8].As<v8::Object>();

  if (!node::Buffer::HasInstance(ppbuf)
      || !node::Buffer::HasInstance(pqbuf)
      || !node::Buffer::HasInstance(pgbuf)
      || !node::Buffer::HasInstance(pybuf)
      || !node::Buffer::HasInstance(spbuf)
      || !node::Buffer::HasInstance(sqbuf)
      || !node::Buffer::HasInstance(sgbuf)
      || !node::Buffer::HasInstance(sybuf)
      || !node::Buffer::HasInstance(sxbuf)) {
    return Nan::ThrowTypeError("Arguments must be buffers.");
  }

  bcrypto_dsa_key_t pub;
  bcrypto_dsa_key_init(&pub);

  pub.pd = (uint8_t *)node::Buffer::Data(ppbuf);
  pub.pl = node::Buffer::Length(ppbuf);

  pub.qd = (uint8_t *)node::Buffer::Data(pqbuf);
  pub.ql = node::Buffer::Length(pqbuf);

  pub.gd = (uint8_t *)node::Buffer::Data(pgbuf);
  pub.gl = node::Buffer::Length(pgbuf);

  pub.yd = (uint8_t *)node::Buffer::Data(pybuf);
  pub.yl = node::Buffer::Length(pybuf);

  bcrypto_dsa_key_t priv;
  bcrypto_dsa_key_init(&priv);

  priv.pd = (uint8_t *)node::Buffer::Data(spbuf);
  priv.pl = node::Buffer::Length(spbuf);

  priv.qd = (uint8_t *)node::Buffer::Data(sqbuf);
  priv.ql = node::Buffer::Length(sqbuf);

  priv.gd = (uint8_t *)node::Buffer::Data(sgbuf);
  priv.gl = node::Buffer::Length(sgbuf);

  priv.yd = (uint8_t *)node::Buffer::Data(sybuf);
  priv.yl = node::Buffer::Length(sybuf);

  priv.xd = (uint8_t *)node::Buffer::Data(sxbuf);
  priv.xl = node::Buffer::Length(sxbuf);

  uint8_t *out = NULL;
  size_t out_len = 0;

  if (!bcrypto_dsa_derive(&pub, &priv, &out, &out_len))
    return Nan::ThrowError("Could not derive key.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}
#endif
