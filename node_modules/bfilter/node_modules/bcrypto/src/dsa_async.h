#ifndef _BCRYPTO_DSA_ASYNC_HH
#define _BCRYPTO_DSA_ASYNC_HH

#include <node.h>
#include <nan.h>

class BDSAWorker : public Nan::AsyncWorker {
public:
  BDSAWorker (
    uint32_t bits,
    uint8_t seed[32],
    Nan::Callback *callback
  );

  virtual ~BDSAWorker();
  virtual void Execute();
  void HandleOKCallback();

private:
  uint32_t bits;
  uint8_t entropy[32];
  uint8_t *params;
  size_t params_len;
};
#endif
