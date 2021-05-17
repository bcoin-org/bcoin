#ifndef _BCRYPTO_SCHNORR_HH
#define _BCRYPTO_SCHNORR_HH

#include <node.h>
#include <nan.h>
#include <torsion/ecc.h>

class BSchnorr : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BSchnorr();
  ~BSchnorr();

  schnorr_t *ctx;
  schnorr_scratch_t *scratch;
  size_t scalar_size;
  size_t scalar_bits;
  size_t field_size;
  size_t field_bits;
  size_t sig_size;

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
  static NAN_METHOD(PrivateKeyInvert);
  static NAN_METHOD(PublicKeyCreate);
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
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Derive);
  static NAN_METHOD(VerifyBatch);
};
#endif
