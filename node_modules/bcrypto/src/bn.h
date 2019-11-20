/**
 * bn.h - native bn object for node.js.
 * Copyright (c) 2019, Christopher Jeffrey (MIT License)
 */

#ifndef _BCRYPTO_BN_H
#define _BCRYPTO_BN_H

#include <node.h>
#include <nan.h>
#include <gmp.h>

class BBN : public Nan::ObjectWrap {
public:
  static void Init(v8::Local<v8::Object> &target);
  static bool HasInstance(v8::Local<v8::Value> val);
  static NAN_METHOD(New);

  BBN();
  ~BBN();

  mpz_t n;

private:
  static NAN_METHOD(Iadd);
  static NAN_METHOD(Iaddn);
  static NAN_METHOD(Isub);
  static NAN_METHOD(Isubn);
  static NAN_METHOD(MulTo);
  static NAN_METHOD(Imul);
  static NAN_METHOD(Imuln);
  static NAN_METHOD(Idiv);
  static NAN_METHOD(Idivn);
  static NAN_METHOD(IdivRound);
  static NAN_METHOD(Imod);
  static NAN_METHOD(Imodn);
  static NAN_METHOD(Modrn);
  static NAN_METHOD(Iumod);
  static NAN_METHOD(Iumodn);
  static NAN_METHOD(Umodrn);
  static NAN_METHOD(Ipow);
  static NAN_METHOD(Ipown);
  static NAN_METHOD(Isqr);
  static NAN_METHOD(Isqrt);
  static NAN_METHOD(IsSquare);
  static NAN_METHOD(Iand);
  static NAN_METHOD(Iandn);
  static NAN_METHOD(Andrn);
  static NAN_METHOD(Iuand);
  static NAN_METHOD(Iuandn);
  static NAN_METHOD(Uandrn);
  static NAN_METHOD(Ior);
  static NAN_METHOD(Iorn);
  static NAN_METHOD(Iuor);
  static NAN_METHOD(Iuorn);
  static NAN_METHOD(Ixor);
  static NAN_METHOD(Ixorn);
  static NAN_METHOD(Iuxor);
  static NAN_METHOD(Iuxorn);
  static NAN_METHOD(Inotn);
  static NAN_METHOD(Ishln);
  static NAN_METHOD(Iushln);
  static NAN_METHOD(Ishrn);
  static NAN_METHOD(Iushrn);
  static NAN_METHOD(Setn);
  static NAN_METHOD(Testn);
  static NAN_METHOD(Imaskn);
  static NAN_METHOD(Andln);
  static NAN_METHOD(Bincn);
  static NAN_METHOD(Ineg);
  static NAN_METHOD(Iabs);
  static NAN_METHOD(Cmp);
  static NAN_METHOD(Cmpn);
  static NAN_METHOD(Eq);
  static NAN_METHOD(Eqn);
  static NAN_METHOD(Ucmp);
  static NAN_METHOD(Ucmpn);
  static NAN_METHOD(Jacobi);
  static NAN_METHOD(Igcd);
  static NAN_METHOD(Egcd);
  static NAN_METHOD(Iinvm);
  static NAN_METHOD(Ifinvm);
  static NAN_METHOD(Ipowm);
  static NAN_METHOD(Ipowmn);
  static NAN_METHOD(Isqrtp);
  static NAN_METHOD(Isqrtpq);
  static NAN_METHOD(IsPrimeMR);
  static NAN_METHOD(IsPrimeLucas);
  static NAN_METHOD(ToTwos);
  static NAN_METHOD(FromTwos);
  static NAN_METHOD(IsZero);
  static NAN_METHOD(IsNeg);
  static NAN_METHOD(IsOdd);
  static NAN_METHOD(IsEven);
  static NAN_METHOD(Inject);
  static NAN_METHOD(Set);
  static NAN_METHOD(ByteLength);
  static NAN_METHOD(BitLength);
  static NAN_METHOD(ZeroBits);
  static NAN_METHOD(IsSafe);
  static NAN_METHOD(ToNumber);
  static NAN_METHOD(ToDouble);
  static NAN_METHOD(ToBool);
  static NAN_METHOD(ToBuffer);
  static NAN_METHOD(ToString);
  static NAN_METHOD(FromNumber);
  static NAN_METHOD(FromDouble);
  static NAN_METHOD(FromBool);
  static NAN_METHOD(FromBuffer);
  static NAN_METHOD(FromString);
  static NAN_METHOD(RandomBits);
  static NAN_METHOD(Random);
};

#endif
