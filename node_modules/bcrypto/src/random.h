#ifndef _BCRYPTO_RANDOM_HH
#define _BCRYPTO_RANDOM_HH
#include <node.h>
#include <nan.h>

class BRandom {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(RandomFill);
};

#endif
