#ifndef _BCRYPTO_ECDSA_HH
#define _BCRYPTO_ECDSA_HH

#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BECDSA {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyExportPKCS8);
  static NAN_METHOD(PrivateKeyImportPKCS8);
  static NAN_METHOD(PrivateKeyTweakAdd);
  static NAN_METHOD(PrivateKeyTweakMul);
  static NAN_METHOD(PrivateKeyNegate);
  static NAN_METHOD(PrivateKeyInverse);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyExportSPKI);
  static NAN_METHOD(PublicKeyImportSPKI);
  static NAN_METHOD(PublicKeyTweakAdd);
  static NAN_METHOD(PublicKeyTweakMul);
  static NAN_METHOD(PublicKeyAdd);
  static NAN_METHOD(PublicKeyNegate);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Recover);
  static NAN_METHOD(Derive);
};
#endif

#endif
