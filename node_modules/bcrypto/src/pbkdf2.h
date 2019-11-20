#ifndef _BCRYPTO_PBKDF2_HH
#define _BCRYPTO_PBKDF2_HH
#include <node.h>
#include <nan.h>

class BPBKDF2 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Derive);
  static NAN_METHOD(DeriveAsync);
  static NAN_METHOD(HasHash);
};

#endif
