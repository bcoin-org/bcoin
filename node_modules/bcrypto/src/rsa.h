#ifndef _BCRYPTO_RSA_HH
#define _BCRYPTO_RSA_HH

#include <node.h>
#include <nan.h>

class BRSA {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyGenerateAsync);
  static NAN_METHOD(PrivateKeyBits);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyBits);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Decrypt);
  static NAN_METHOD(SignPSS);
  static NAN_METHOD(VerifyPSS);
  static NAN_METHOD(EncryptOAEP);
  static NAN_METHOD(DecryptOAEP);
  static NAN_METHOD(Veil);
  static NAN_METHOD(Unveil);
};
#endif
