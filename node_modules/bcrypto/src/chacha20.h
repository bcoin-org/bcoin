#ifndef _BCRYPTO_CHACHA20_HH
#define _BCRYPTO_CHACHA20_HH

#include <node.h>
#include <nan.h>

#include "chacha20/chacha20.h"

class BChaCha20 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BChaCha20();
  ~BChaCha20();

  bcrypto_chacha20_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(InitIV);
  static NAN_METHOD(InitKey);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Crypt);
  static NAN_METHOD(SetCounter);
  static NAN_METHOD(GetCounter);
  static NAN_METHOD(Destroy);
};
#endif
