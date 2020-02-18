#ifndef _BCRYPTO_DSA_HH
#define _BCRYPTO_DSA_HH
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BDSA {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(ParamsGenerate);
  static NAN_METHOD(ParamsGenerateAsync);
  static NAN_METHOD(ParamsVerify);
  static NAN_METHOD(ParamsExport);
  static NAN_METHOD(ParamsImport);
  static NAN_METHOD(PrivateKeyCreate);
  static NAN_METHOD(PrivateKeyCompute);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyExportPKCS8);
  static NAN_METHOD(PrivateKeyImportPKCS8);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyExportSPKI);
  static NAN_METHOD(PublicKeyImportSPKI);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Derive);
};
#endif

#endif
