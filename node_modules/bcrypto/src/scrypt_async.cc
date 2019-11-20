#include "common.h"
#include "scrypt/scrypt.h"
#include "scrypt_async.h"

BScryptWorker::BScryptWorker (
  v8::Local<v8::Object> &passHandle,
  v8::Local<v8::Object> &saltHandle,
  const uint8_t *pass,
  const uint32_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint64_t N,
  uint64_t r,
  uint64_t p,
  size_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , pass(pass)
  , passlen(passlen)
  , salt(salt)
  , saltlen(saltlen)
  , N(N)
  , r(r)
  , p(p)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("pass", passHandle);
  SaveToPersistent("salt", saltHandle);
}

BScryptWorker::~BScryptWorker() {}

void
BScryptWorker::Execute() {
  key = (uint8_t *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("Scrypt failed.");
    return;
  }

  if (!bcrypto_scrypt(pass, passlen, salt, saltlen, N, r, p, key, keylen)) {
    free(key);
    key = NULL;
    SetErrorMessage("Scrypt failed.");
  }
}

void
BScryptWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(key);

  v8::Local<v8::Value> keyBuffer =
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked();

  v8::Local<v8::Value> argv[] = { Nan::Null(), keyBuffer };

  callback->Call(2, argv, async_resource);
}
