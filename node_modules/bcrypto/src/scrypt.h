#ifndef _BCRYPTO_SCRYPT_HH
#define _BCRYPTO_SCRYPT_HH
#include <node.h>
#include <nan.h>

class BScrypt {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Derive);
  static NAN_METHOD(DeriveAsync);
};

#endif
