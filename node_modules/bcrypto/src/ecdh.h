#ifndef _BCRYPTO_ECDH_HH
#define _BCRYPTO_ECDH_HH

#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>

class BECDH : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BECDH();
  ~BECDH();

  ecdh_t *ctx;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;

private:
  static NAN_METHOD(Size);
  static NAN_METHOD(Bits);
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyFromUniform);
  static NAN_METHOD(PublicKeyToUniform);
  static NAN_METHOD(PublicKeyFromHash);
  static NAN_METHOD(PublicKeyToHash);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyIsSmall);
  static NAN_METHOD(PublicKeyHasTorsion);
  static NAN_METHOD(Derive);
};
#endif
