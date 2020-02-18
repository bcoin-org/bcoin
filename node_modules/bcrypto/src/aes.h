#ifndef _BCRYPTO_AES_HH
#define _BCRYPTO_AES_HH
#include <node.h>
#include <nan.h>

class BAES {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Encipher);
  static NAN_METHOD(Decipher);
};

#endif
