#ifndef _BCRYPTO_ECDSA_HH
#define _BCRYPTO_ECDSA_HH

#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>

class BECDSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BECDSA();
  ~BECDSA();

  ecdsa_t *ctx;
  ecdsa_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t sig_size;
  size_t schnorr_size;

private:
  static NAN_METHOD(Size);
  static NAN_METHOD(Bits);
  static NAN_METHOD(Randomize);
  static NAN_METHOD(PrivateKeyGenerate);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PrivateKeyExport);
  static NAN_METHOD(PrivateKeyImport);
  static NAN_METHOD(PrivateKeyTweakAdd);
  static NAN_METHOD(PrivateKeyTweakMul);
  static NAN_METHOD(PrivateKeyReduce);
  static NAN_METHOD(PrivateKeyNegate);
  static NAN_METHOD(PrivateKeyInvert);
  static NAN_METHOD(PublicKeyCreate);
  static NAN_METHOD(PublicKeyConvert);
  static NAN_METHOD(PublicKeyFromUniform);
  static NAN_METHOD(PublicKeyToUniform);
  static NAN_METHOD(PublicKeyFromHash);
  static NAN_METHOD(PublicKeyToHash);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(PublicKeyExport);
  static NAN_METHOD(PublicKeyImport);
  static NAN_METHOD(PublicKeyTweakAdd);
  static NAN_METHOD(PublicKeyTweakMul);
  static NAN_METHOD(PublicKeyCombine);
  static NAN_METHOD(PublicKeyNegate);
  static NAN_METHOD(SignatureNormalize);
  static NAN_METHOD(SignatureNormalizeDER);
  static NAN_METHOD(SignatureExport);
  static NAN_METHOD(SignatureImport);
  static NAN_METHOD(IsLowS);
  static NAN_METHOD(IsLowDER);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignRecoverable);
  static NAN_METHOD(SignDER);
  static NAN_METHOD(SignRecoverableDER);
  static NAN_METHOD(Verify);
  static NAN_METHOD(VerifyDER);
  static NAN_METHOD(Recover);
  static NAN_METHOD(RecoverDER);
  static NAN_METHOD(Derive);
  static NAN_METHOD(SchnorrSign);
  static NAN_METHOD(SchnorrVerify);
  static NAN_METHOD(SchnorrVerifyBatch);
};
#endif
