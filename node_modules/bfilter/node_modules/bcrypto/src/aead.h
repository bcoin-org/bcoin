#ifndef _BCRYPTO_AEAD_HH
#define _BCRYPTO_AEAD_HH

#include <node.h>
#include <nan.h>
#include <torsion/aead.h>

class BAEAD : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BAEAD();
  ~BAEAD();

  aead_t ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(AAD);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Decrypt);
  static NAN_METHOD(Auth);
  static NAN_METHOD(Final);
  static NAN_METHOD(Destroy);
  static NAN_METHOD(Verify);
  static NAN_METHOD(StaticEncrypt);
  static NAN_METHOD(StaticDecrypt);
  static NAN_METHOD(StaticAuth);
};
#endif
