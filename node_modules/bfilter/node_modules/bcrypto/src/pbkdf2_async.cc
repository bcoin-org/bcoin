#include <torsion/kdf.h>
#include "common.h"
#include "pbkdf2_async.h"

BPBKDF2Worker::BPBKDF2Worker (
  v8::Local<v8::Object> &passHandle,
  v8::Local<v8::Object> &saltHandle,
  int type,
  const uint8_t *pass,
  size_t passlen,
  const uint8_t *salt,
  size_t saltlen,
  uint32_t iter,
  size_t keylen,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:pbkdf2")
  , type(type)
  , pass(pass)
  , passlen(passlen)
  , salt(salt)
  , saltlen(saltlen)
  , iter(iter)
  , key(NULL)
  , keylen(keylen)
{
  Nan::HandleScope scope;
  SaveToPersistent("pass", passHandle);
  SaveToPersistent("salt", saltHandle);
}

BPBKDF2Worker::~BPBKDF2Worker() {
  if (key != NULL) {
    free(key);
    key = NULL;
  }
}

void
BPBKDF2Worker::Execute() {
  key = (uint8_t *)malloc(keylen);

  if (key == NULL) {
    SetErrorMessage("PBKDF2 failed.");
    return;
  }

  if (!pbkdf2_derive(key, type, pass, passlen, salt, saltlen, iter, keylen))
    SetErrorMessage("PBKDF2 failed.");
}

void
BPBKDF2Worker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(key != NULL);

  v8::Local<v8::Value> argv[] = {
    Nan::Null(),
    Nan::NewBuffer((char *)key, keylen).ToLocalChecked()
  };

  key = NULL;

  callback->Call(2, argv, async_resource);
}
