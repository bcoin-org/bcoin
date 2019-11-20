#ifndef _BCRYPTO_SCRYPT_ASYNC_HH
#define _BCRYPTO_SCRYPT_ASYNC_HH

#include <node.h>
#include <nan.h>

class BScryptWorker : public Nan::AsyncWorker {
public:
  BScryptWorker (
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
  );

  virtual ~BScryptWorker ();
  virtual void Execute ();
  void HandleOKCallback();

private:
  const uint8_t *pass;
  const uint32_t passlen;
  const uint8_t *salt;
  size_t saltlen;
  uint64_t N;
  uint64_t r;
  uint64_t p;
  uint8_t *key;
  size_t keylen;
};

#endif
