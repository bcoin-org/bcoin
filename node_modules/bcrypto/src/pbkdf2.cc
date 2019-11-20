#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "openssl/evp.h"
#include "pbkdf2/pbkdf2.h"
#include "pbkdf2.h"
#include "pbkdf2_async.h"

void
BPBKDF2::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "derive", BPBKDF2::Derive);
  Nan::Export(obj, "deriveAsync", BPBKDF2::DeriveAsync);
  Nan::Export(obj, "hasHash", BPBKDF2::HasHash);

  Nan::Set(target, Nan::New("pbkdf2").ToLocalChecked(), obj);
}

NAN_METHOD(BPBKDF2::Derive) {
  if (info.Length() < 5)
    return Nan::ThrowError("pbkdf2.derive() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(kbuf);
  size_t datalen = (size_t)node::Buffer::Length(kbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = Nan::To<uint32_t>(info[3]).FromJust();
  size_t keylen = (size_t)Nan::To<uint32_t>(info[4]).FromJust();

  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!bcrypto_pbkdf2(name, data, datalen, salt, saltlen, iter, key, keylen)) {
    free(key);
    return Nan::ThrowError("PBKDF2 failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(BPBKDF2::DeriveAsync) {
  if (info.Length() < 6)
    return Nan::ThrowError("pbkdf2.deriveAsync() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  v8::Local<v8::Object> dbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(dbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsFunction())
    return Nan::ThrowTypeError("Sixth argument must be a Function.");

  v8::Local<v8::Function> callback = info[5].As<v8::Function>();

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;

  char *alg = strdup(name);

  if (alg == NULL)
    return Nan::ThrowError("Could not allocate algorithm.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(dbuf);
  size_t datalen = (size_t)node::Buffer::Length(dbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = Nan::To<uint32_t>(info[3]).FromJust();
  size_t keylen = (size_t)Nan::To<uint32_t>(info[4]).FromJust();

  BPBKDF2Worker *worker = new BPBKDF2Worker(
    dbuf,
    sbuf,
    alg,
    data,
    datalen,
    salt,
    saltlen,
    iter,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BPBKDF2::HasHash) {
  if (info.Length() < 1)
    return Nan::ThrowError("pbkdf2.hasHash() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String alg_(info[0]);
  const char *alg = (const char *)*alg_;
  bool result = bcrypto_pbkdf2_has_hash(alg);

  if (!result) {
    if (strcmp(alg, "SHA256") == 0 || strcmp(alg, "SHA512") == 0)
      return Nan::ThrowError("Algorithms not loaded for PBKDF2.");
  }

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
