#ifndef _BCRYPTO_PBKDF2_ASYNC_HH
#define _BCRYPTO_PBKDF2_ASYNC_HH

#include <node.h>
#include <nan.h>
#include "openssl/evp.h"

class BPBKDF2Worker : public Nan::AsyncWorker {
public:
  BPBKDF2Worker (
    v8::Local<v8::Object> &dataHandle,
    v8::Local<v8::Object> &saltHandle,
    char *name,
    const uint8_t *data,
    size_t datalen,
    const uint8_t *salt,
    size_t saltlen,
    uint32_t iter,
    size_t keylen,
    Nan::Callback *callback
  );

  virtual ~BPBKDF2Worker ();
  virtual void Execute ();
  void HandleOKCallback();

private:
  char *name;
  const uint8_t *data;
  size_t datalen;
  const uint8_t *salt;
  size_t saltlen;
  uint32_t iter;
  uint8_t *key;
  size_t keylen;
};

#endif
