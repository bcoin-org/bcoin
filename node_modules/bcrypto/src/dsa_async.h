#ifndef _BCRYPTO_DSA_ASYNC_HH
#define _BCRYPTO_DSA_ASYNC_HH

#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
#include "dsa/dsa.h"

class BDSAWorker : public Nan::AsyncWorker {
public:
  BDSAWorker (
    int bits,
    Nan::Callback *callback
  );

  virtual ~BDSAWorker();
  virtual void Execute();
  void HandleOKCallback();

private:
  int bits;
  bcrypto_dsa_key_t *key;
};
#endif

#endif
