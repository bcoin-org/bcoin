#ifndef _BCRYPTO_AEAD_HH
#define _BCRYPTO_AEAD_HH

#include <node.h>
#include <nan.h>

#include "aead/aead.h"

class BAEAD : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BAEAD();
  ~BAEAD();

  bcrypto_aead_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(AAD);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Decrypt);
  static NAN_METHOD(Auth);
  static NAN_METHOD(Final);
  static NAN_METHOD(EncryptStatic);
  static NAN_METHOD(DecryptStatic);
  static NAN_METHOD(AuthStatic);
  static NAN_METHOD(Verify);
};
#endif
