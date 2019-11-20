#ifndef _BCRYPTO_ED448_HH
#define _BCRYPTO_ED448_HH

#include <node.h>
#include <nan.h>

class BED448 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(PrivateKeyConvert);
  static NAN_METHOD(ScalarTweakAdd);
  static NAN_METHOD(ScalarTweakMul);
  static NAN_METHOD(ScalarNegate);
  static NAN_METHOD(ScalarInverse);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyFromScalar);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyDeconvert);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyTweakAdd);
  static NAN_METHOD(PublicKeyTweakMul);
  static NAN_METHOD(PublicKeyAdd);
  static NAN_METHOD(PublicKeyNegate);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignWithScalar);
  static NAN_METHOD(SignTweakAdd);
  static NAN_METHOD(SignTweakMul);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Derive);
  static NAN_METHOD(DeriveWithScalar);
  static NAN_METHOD(Exchange);
  static NAN_METHOD(ExchangeWithScalar);
};

#endif
