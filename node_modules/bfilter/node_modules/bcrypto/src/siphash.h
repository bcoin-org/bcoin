#ifndef _BCRYPTO_SIPHASH_HH
#define _BCRYPTO_SIPHASH_HH

#include <node.h>
#include <nan.h>

class BSiphash {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Siphash);
  static NAN_METHOD(Siphash32);
  static NAN_METHOD(Siphash64);
  static NAN_METHOD(Siphash32k256);
  static NAN_METHOD(Siphash64k256);
  static NAN_METHOD(Sipmod);
};

#endif
