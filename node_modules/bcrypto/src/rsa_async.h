#ifndef _BCRYPTO_RSA_ASYNC_HH
#define _BCRYPTO_RSA_ASYNC_HH

#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
#include "rsa/rsa.h"

class BRSAWorker : public Nan::AsyncWorker {
public:
  BRSAWorker (
    int bits,
    unsigned long long exp,
    Nan::Callback *callback
  );

  virtual ~BRSAWorker();
  virtual void Execute();
  void HandleOKCallback();

private:
  int bits;
  unsigned long long exp;
  bcrypto_rsa_key_t *key;
};
#endif

#endif
