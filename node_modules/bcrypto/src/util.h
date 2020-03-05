#ifndef _BCRYPTO_UTIL_HH
#define _BCRYPTO_UTIL_HH
#include <node.h>
#include <nan.h>

class BUtil {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Cleanse);
};

#endif
