#ifndef _BCRYPTO_DSA_HH
#define _BCRYPTO_DSA_HH

#include <node.h>
#include <nan.h>

class BDSA {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(ParamsCreate);
  static NAN_METHOD(ParamsGenerate);
  static NAN_METHOD(ParamsGenerateAsync);
  static NAN_METHOD(ParamsBits);
  static NAN_METHOD(ParamsVerify);
  static NAN_METHOD(ParamsImport);
  static NAN_METHOD(ParamsExport);
  static NAN_METHOD(PrivateKeyCreate);
  static NAN_METHOD(PrivateKeyBits);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyBits);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(SignatureExport);
  static NAN_METHOD(SignatureImport);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignDER);
  static NAN_METHOD(Verify);
  static NAN_METHOD(VerifyDER);
  static NAN_METHOD(Derive);
};
#endif
