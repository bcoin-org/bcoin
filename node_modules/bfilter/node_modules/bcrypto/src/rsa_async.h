#ifndef _BCRYPTO_RSA_ASYNC_HH
#define _BCRYPTO_RSA_ASYNC_HH

#include <stddef.h>
#include <node.h>
#include <nan.h>

class BRSAWorker : public Nan::AsyncWorker {
public:
  BRSAWorker (
    uint32_t bits,
    uint64_t exp,
    uint8_t seed[32],
    Nan::Callback *callback
  );

  virtual ~BRSAWorker();
  virtual void Execute();
  void HandleOKCallback();

private:
  uint32_t bits;
  uint64_t exp;
  uint8_t entropy[32];
  uint8_t *key;
  size_t key_len;
};

#endif
