/**
 * n64.h - native int64 object for node.js.
 * Copyright (c) 2017, Christopher Jeffrey (MIT License)
 */

#ifndef _N64_MODULE_H
#define _N64_MODULE_H

#include <node.h>
#include <nan.h>
#include <inttypes.h>

class N64 : public Nan::ObjectWrap {
public:
  static void Init(v8::Local<v8::Object> &target);
  static bool HasInstance(v8::Local<v8::Value> val);
  static NAN_METHOD(New);

  N64();
  ~N64();

  uint64_t n;
  uint8_t sign;

private:
  static NAN_METHOD(GetHi);
  static NAN_METHOD(SetHi);
  static NAN_METHOD(GetLo);
  static NAN_METHOD(SetLo);
  static NAN_METHOD(GetSign);
  static NAN_METHOD(SetSign);
  static NAN_METHOD(Iadd);
  static NAN_METHOD(Iaddn);
  static NAN_METHOD(Isub);
  static NAN_METHOD(Isubn);
  static NAN_METHOD(Imul);
  static NAN_METHOD(Imuln);
  static NAN_METHOD(Idiv);
  static NAN_METHOD(Idivn);
  static NAN_METHOD(Imod);
  static NAN_METHOD(Imodn);
  static NAN_METHOD(Ipown);
  static NAN_METHOD(Iand);
  static NAN_METHOD(Iandn);
  static NAN_METHOD(Ior);
  static NAN_METHOD(Iorn);
  static NAN_METHOD(Ixor);
  static NAN_METHOD(Ixorn);
  static NAN_METHOD(Inot);
  static NAN_METHOD(Ishln);
  static NAN_METHOD(Ishrn);
  static NAN_METHOD(Iushrn);
  static NAN_METHOD(Setn);
  static NAN_METHOD(Testn);
  static NAN_METHOD(Setb);
  static NAN_METHOD(Orb);
  static NAN_METHOD(Getb);
  static NAN_METHOD(Imaskn);
  static NAN_METHOD(Andln);
  static NAN_METHOD(Ineg);
  static NAN_METHOD(Cmp);
  static NAN_METHOD(Cmpn);
  static NAN_METHOD(Eq);
  static NAN_METHOD(Eqn);
  static NAN_METHOD(IsZero);
  static NAN_METHOD(IsNeg);
  static NAN_METHOD(IsOdd);
  static NAN_METHOD(IsEven);
  static NAN_METHOD(Inject);
  static NAN_METHOD(Set);
  static NAN_METHOD(Join);
  static NAN_METHOD(BitLength);
  static NAN_METHOD(IsSafe);
  static NAN_METHOD(ToNumber);
  static NAN_METHOD(ToDouble);
  static NAN_METHOD(ToInt);
  static NAN_METHOD(ToBool);
  static NAN_METHOD(ToString);
  static NAN_METHOD(FromNumber);
  static NAN_METHOD(FromInt);
  static NAN_METHOD(FromBool);
  static NAN_METHOD(FromBits);
  static NAN_METHOD(FromString);
};

#endif
