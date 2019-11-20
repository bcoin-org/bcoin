#ifndef _BCRYPTO_RIPEMD160_HH
#define _BCRYPTO_RIPEMD160_HH
#include <node.h>
#include <nan.h>
#include "openssl/ripemd.h"

class BRIPEMD160 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BRIPEMD160();
  ~BRIPEMD160();

  RIPEMD160_CTX ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Multi);
};
#endif
