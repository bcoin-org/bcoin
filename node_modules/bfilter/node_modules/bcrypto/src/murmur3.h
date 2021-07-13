#ifndef _BCRYPTO_MURMUR3_HH
#define _BCRYPTO_MURMUR3_HH

#include <node.h>
#include <nan.h>

class BMurmur3 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Sum);
  static NAN_METHOD(Tweak);
};

#endif
