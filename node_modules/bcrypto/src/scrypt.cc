#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/kdf.h>

#include "common.h"
#include "scrypt.h"
#include "scrypt_async.h"

void
BScrypt::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "derive", BScrypt::Derive);
  Nan::Export(obj, "deriveAsync", BScrypt::DeriveAsync);

  Nan::Set(target, Nan::New("scrypt").ToLocalChecked(), obj);
}

NAN_METHOD(BScrypt::Derive) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt.derive() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t passlen = (size_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)Nan::To<int64_t>(info[2]).FromJust();
  uint32_t r = (uint32_t)Nan::To<int64_t>(info[3]).FromJust();
  uint32_t p = (uint32_t)Nan::To<int64_t>(info[4]).FromJust();
  size_t keylen = (size_t)Nan::To<int64_t>(info[5]).FromJust();
  uint8_t *key = (uint8_t *)malloc(keylen);

  if (key == NULL)
    return Nan::ThrowError("Could not allocate key.");

  if (!scrypt_derive(key, pass, passlen, salt, saltlen, N, r, p, keylen)) {
    free(key);
    return Nan::ThrowError("Scrypt failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked());
}

NAN_METHOD(BScrypt::DeriveAsync) {
  if (info.Length() < 6)
    return Nan::ThrowError("scrypt.deriveAsync() requires arguments.");

  v8::Local<v8::Object> pbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(pbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> sbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  if (!info[3]->IsNumber())
    return Nan::ThrowTypeError("Fourth argument must be a number.");

  if (!info[4]->IsNumber())
    return Nan::ThrowTypeError("Fifth argument must be a number.");

  if (!info[5]->IsNumber())
    return Nan::ThrowTypeError("Sixth argument must be a number.");

  if (!info[6]->IsFunction())
    return Nan::ThrowTypeError("Seventh argument must be a Function.");

  const uint8_t *pass = (const uint8_t *)node::Buffer::Data(pbuf);
  size_t passlen = (size_t)node::Buffer::Length(pbuf);
  const uint8_t *salt = (const uint8_t *)node::Buffer::Data(sbuf);
  size_t saltlen = (size_t)node::Buffer::Length(sbuf);
  uint64_t N = (uint64_t)Nan::To<int64_t>(info[2]).FromJust();
  uint32_t r = (uint32_t)Nan::To<int64_t>(info[3]).FromJust();
  uint32_t p = (uint32_t)Nan::To<int64_t>(info[4]).FromJust();
  size_t keylen = (size_t)Nan::To<int64_t>(info[5]).FromJust();
  v8::Local<v8::Function> callback = info[6].As<v8::Function>();

  BScryptWorker *worker = new BScryptWorker(
    pbuf,
    sbuf,
    pass,
    passlen,
    salt,
    saltlen,
    N,
    r,
    p,
    keylen,
    new Nan::Callback(callback)
  );

  Nan::AsyncQueueWorker(worker);
}
