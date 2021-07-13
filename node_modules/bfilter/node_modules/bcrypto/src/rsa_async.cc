#include <assert.h>
#include <node.h>
#include <nan.h>
#include <torsion/rsa.h>

#include "common.h"
#include "rsa_async.h"

BRSAWorker::BRSAWorker (
  uint32_t bits,
  uint64_t exp,
  uint8_t seed[32],
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:rsa_privkey_generate")
  , bits(bits)
  , exp(exp)
  , key(NULL)
  , key_len(0)
{
  Nan::HandleScope scope;
  memcpy(entropy, seed, 32);
}

BRSAWorker::~BRSAWorker() {
  if (key != NULL) {
    free(key);
    key = NULL;
    key_len = 0;
  }
}

void
BRSAWorker::Execute() {
  key = (uint8_t *)malloc(RSA_MAX_PRIV_SIZE);
  key_len = RSA_MAX_PRIV_SIZE;

  if (key == NULL) {
    SetErrorMessage("Could not generate key.");
    return;
  }

  if (!rsa_privkey_generate(key, &key_len, bits, exp, entropy)) {
    SetErrorMessage("Could not generate key.");
    return;
  }

  key = (uint8_t *)realloc(key, key_len);

  if (key == NULL)
    SetErrorMessage("Could not generate key.");
}

void
BRSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(key != NULL);
  assert(key_len != 0);

  v8::Local<v8::Value> argv[] = {
    Nan::Null(),
    Nan::NewBuffer((char *)key, key_len).ToLocalChecked()
  };

  key = NULL;
  key_len = 0;

  callback->Call(2, argv, async_resource);
}
