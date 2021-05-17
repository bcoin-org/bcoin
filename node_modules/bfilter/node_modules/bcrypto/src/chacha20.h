#ifndef _BCRYPTO_CHACHA20_HH
#define _BCRYPTO_CHACHA20_HH

#include <node.h>
#include <nan.h>
#include <torsion/chacha20.h>

class BChaCha20 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BChaCha20();
  ~BChaCha20();

  chacha20_t ctx;
  bool started;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Destroy);
  static NAN_METHOD(Derive);
};
#endif
