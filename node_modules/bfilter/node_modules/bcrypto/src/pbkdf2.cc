#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/kdf.h>

#include "common.h"
#include "pbkdf2.h"
#include "pbkdf2_async.h"

void
BPBKDF2::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "derive", BPBKDF2::Derive);
  Nan::Export(obj, "deriveAsync", BPBKDF2::DeriveAsync);

  Nan::Set(target, Nan::New("pbkdf2").ToLocalChecked(), obj);
}

NAN_METHOD(BPBKDF2::Derive) {
  if (info.Length() < 5)
    return Nan::ThrowError("pbkdf2.derive() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t passlen = (size_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = Nan::To<uint32_t>(info[3]).FromJust();
  size_t keylen = (size_t)Nan::To<uint32_t>(info[4]).FromJust();
  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!pbkdf2_derive(key, type, pass, passlen, salt, saltlen, iter, keylen)) {
    free(key);
    return Nan::ThrowError("PBKDF2 failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(BPBKDF2::DeriveAsync) {
  if (info.Length() < 6)
    return Nan::ThrowError("pbkdf2.deriveAsync() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> pbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
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

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t passlen = (size_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint32_t iter = Nan::To<uint32_t>(info[3]).FromJust();
  size_t keylen = (size_t)Nan::To<uint32_t>(info[4]).FromJust();
  v8::Local<v8::Function> callback = info[5].As<v8::Function>();

  BPBKDF2Worker *worker = new BPBKDF2Worker(
    pbuf,
    sbuf,
    type,
    pass,
    passlen,
    salt,
    saltlen,
    iter,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}
