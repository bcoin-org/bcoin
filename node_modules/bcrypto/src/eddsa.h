#ifndef _BCRYPTO_EDDSA_HH
#define _BCRYPTO_EDDSA_HH

#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>

class BEDDSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BEDDSA();
  ~BEDDSA();

  eddsa_t *ctx;
  eddsa_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t priv_size;
  size_t pub_size;
  size_t sig_size;

private:
  static NAN_METHOD(Size);
  static NAN_METHOD(Bits);
  static NAN_METHOD(Randomize);
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyExpand);
  static NAN_METHOD(PrivateKeyConvert);
  static NAN_METHOD(ScalarGenerate);
  static NAN_METHOD(ScalarVerify);
  static NAN_METHOD(ScalarClamp);
  static NAN_METHOD(ScalarIsZero);
  static NAN_METHOD(ScalarTweakAdd);
  static NAN_METHOD(ScalarTweakMul);
  static NAN_METHOD(ScalarReduce);
  static NAN_METHOD(ScalarNegate);
  static NAN_METHOD(ScalarInvert);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyFromScalar);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyFromUniform);
  static NAN_METHOD(PublicKeyToUniform);
  static NAN_METHOD(PublicKeyFromHash);
  static NAN_METHOD(PublicKeyToHash);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyIsInfinity);
  static NAN_METHOD(PublicKeyIsSmall);
  static NAN_METHOD(PublicKeyHasTorsion);
  static NAN_METHOD(PublicKeyTweakAdd);
  static NAN_METHOD(PublicKeyTweakMul);
  static NAN_METHOD(PublicKeyCombine);
  static NAN_METHOD(PublicKeyNegate);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignWithScalar);
  static NAN_METHOD(SignTweakAdd);
  static NAN_METHOD(SignTweakMul);
  static NAN_METHOD(Verify);
  static NAN_METHOD(VerifySingle);
  static NAN_METHOD(VerifyBatch);
  static NAN_METHOD(Derive);
  static NAN_METHOD(DeriveWithScalar);
};
#endif
