/**
 * bn.cc - native bn object for node.js.
 * Copyright (c) 2019, Christopher Jeffrey (MIT License)
 */

#include <node.h>
#include <nan.h>
#include <stdlib.h>

#include "common.h"
#include "bn.h"
#include "bn/bmpz-impl.h"

#define ARG_ERROR(name, len) ("BN#" #name " requires " #len " argument(s).")
#define TYPE_ERROR(name, type) ("\"" #name "\" must be a(n) " #type ".")
#define RANGE_ERROR(name) ("\"" #name "\" only works with positive numbers.")
#define NONZERO_ERROR ("Cannot divide by zero.")

static int64_t I32_MIN = -2147483648;
static int64_t I32_MAX = 2147483647;
static int64_t U32_MAX = 4294967295;
static int64_t MAX_SAFE_INTEGER = 0x1fffffffffffff;

typedef struct bmpz_rng_data_s {
  v8::Local<v8::Function> callback;
  int is_bytes;
} bmpz_rng_data_t;

static int
bmpz_rng_custom(mpz_t ret, unsigned long bits, void *data);

NAN_INLINE static bool
IsInt(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= -MAX_SAFE_INTEGER && num <= MAX_SAFE_INTEGER;
}

NAN_INLINE static bool
IsUint(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= 0 && num <= MAX_SAFE_INTEGER;
}

NAN_INLINE static bool
IsInt32(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= I32_MIN && num <= I32_MAX;
}

NAN_INLINE static bool
IsUint32(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= 0 && num <= U32_MAX;
}

NAN_INLINE static bool
IsSMI(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= -0x3ffffff && num <= 0x3ffffff;
}

NAN_INLINE static bool
IsUSMI(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;

  if (!obj->IsNumber())
    return false;

  int64_t num = Nan::To<int64_t>(obj).FromJust();

  if (Nan::To<double>(obj).FromJust() != (double)num)
    return false;

  return num >= 0 && num <= 0x3ffffff;
}

static Nan::Persistent<v8::FunctionTemplate> bn_constructor;

BBN::BBN() {
  mpz_init(n);
  mpz_set_ui(n, 0);
}

BBN::~BBN() {
  mpz_clear(n);
}

void
BBN::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BBN::New);

  bn_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("BN").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "iadd", BBN::Iadd);
  Nan::SetPrototypeMethod(tpl, "iaddn", BBN::Iaddn);
  Nan::SetPrototypeMethod(tpl, "isub", BBN::Isub);
  Nan::SetPrototypeMethod(tpl, "isubn", BBN::Isubn);
  Nan::SetPrototypeMethod(tpl, "mulTo", BBN::MulTo);
  Nan::SetPrototypeMethod(tpl, "imul", BBN::Imul);
  Nan::SetPrototypeMethod(tpl, "imuln", BBN::Imuln);
  Nan::SetPrototypeMethod(tpl, "idiv", BBN::Idiv);
  Nan::SetPrototypeMethod(tpl, "idivn", BBN::Idivn);
  Nan::SetPrototypeMethod(tpl, "idivRound", BBN::IdivRound);
  Nan::SetPrototypeMethod(tpl, "imod", BBN::Imod);
  Nan::SetPrototypeMethod(tpl, "imodn", BBN::Imodn);
  Nan::SetPrototypeMethod(tpl, "modrn", BBN::Modrn);
  Nan::SetPrototypeMethod(tpl, "iumod", BBN::Iumod);
  Nan::SetPrototypeMethod(tpl, "iumodn", BBN::Iumodn);
  Nan::SetPrototypeMethod(tpl, "umodrn", BBN::Umodrn);
  Nan::SetPrototypeMethod(tpl, "ipow", BBN::Ipow);
  Nan::SetPrototypeMethod(tpl, "ipown", BBN::Ipown);
  Nan::SetPrototypeMethod(tpl, "isqr", BBN::Isqr);
  Nan::SetPrototypeMethod(tpl, "isqrt", BBN::Isqrt);
  Nan::SetPrototypeMethod(tpl, "isSquare", BBN::IsSquare);
  Nan::SetPrototypeMethod(tpl, "iand", BBN::Iand);
  Nan::SetPrototypeMethod(tpl, "iandn", BBN::Iandn);
  Nan::SetPrototypeMethod(tpl, "andrn", BBN::Andrn);
  Nan::SetPrototypeMethod(tpl, "iuand", BBN::Iuand);
  Nan::SetPrototypeMethod(tpl, "iuandn", BBN::Iuandn);
  Nan::SetPrototypeMethod(tpl, "uandrn", BBN::Uandrn);
  Nan::SetPrototypeMethod(tpl, "ior", BBN::Ior);
  Nan::SetPrototypeMethod(tpl, "iorn", BBN::Iorn);
  Nan::SetPrototypeMethod(tpl, "iuor", BBN::Iuor);
  Nan::SetPrototypeMethod(tpl, "iuorn", BBN::Iuorn);
  Nan::SetPrototypeMethod(tpl, "ixor", BBN::Ixor);
  Nan::SetPrototypeMethod(tpl, "ixorn", BBN::Ixorn);
  Nan::SetPrototypeMethod(tpl, "iuxor", BBN::Iuxor);
  Nan::SetPrototypeMethod(tpl, "iuxorn", BBN::Iuxorn);
  Nan::SetPrototypeMethod(tpl, "inotn", BBN::Inotn);
  Nan::SetPrototypeMethod(tpl, "ishln", BBN::Ishln);
  Nan::SetPrototypeMethod(tpl, "iushln", BBN::Iushln);
  Nan::SetPrototypeMethod(tpl, "ishrn", BBN::Ishrn);
  Nan::SetPrototypeMethod(tpl, "iushrn", BBN::Iushrn);
  Nan::SetPrototypeMethod(tpl, "setn", BBN::Setn);
  Nan::SetPrototypeMethod(tpl, "testn", BBN::Testn);
  Nan::SetPrototypeMethod(tpl, "imaskn", BBN::Imaskn);
  Nan::SetPrototypeMethod(tpl, "andln", BBN::Andln);
  Nan::SetPrototypeMethod(tpl, "bincn", BBN::Bincn);
  Nan::SetPrototypeMethod(tpl, "ineg", BBN::Ineg);
  Nan::SetPrototypeMethod(tpl, "iabs", BBN::Iabs);
  Nan::SetPrototypeMethod(tpl, "cmp", BBN::Cmp);
  Nan::SetPrototypeMethod(tpl, "cmpn", BBN::Cmpn);
  Nan::SetPrototypeMethod(tpl, "eq", BBN::Eq);
  Nan::SetPrototypeMethod(tpl, "eqn", BBN::Eqn);
  Nan::SetPrototypeMethod(tpl, "ucmp", BBN::Ucmp);
  Nan::SetPrototypeMethod(tpl, "ucmpn", BBN::Ucmpn);
  Nan::SetPrototypeMethod(tpl, "jacobi", BBN::Jacobi);
  Nan::SetPrototypeMethod(tpl, "igcd", BBN::Igcd);
  Nan::SetPrototypeMethod(tpl, "egcd", BBN::Egcd);
  Nan::SetPrototypeMethod(tpl, "iinvm", BBN::Iinvm);
  Nan::SetPrototypeMethod(tpl, "ifinvm", BBN::Ifinvm);
  Nan::SetPrototypeMethod(tpl, "ipowm", BBN::Ipowm);
  Nan::SetPrototypeMethod(tpl, "ipowmn", BBN::Ipowmn);
  Nan::SetPrototypeMethod(tpl, "isqrtp", BBN::Isqrtp);
  Nan::SetPrototypeMethod(tpl, "isqrtpq", BBN::Isqrtpq);
  Nan::SetPrototypeMethod(tpl, "isPrimeMR", BBN::IsPrimeMR);
  Nan::SetPrototypeMethod(tpl, "isPrimeLucas", BBN::IsPrimeLucas);
  Nan::SetPrototypeMethod(tpl, "toTwos", BBN::ToTwos);
  Nan::SetPrototypeMethod(tpl, "fromTwos", BBN::FromTwos);
  Nan::SetPrototypeMethod(tpl, "isZero", BBN::IsZero);
  Nan::SetPrototypeMethod(tpl, "isNeg", BBN::IsNeg);
  Nan::SetPrototypeMethod(tpl, "isOdd", BBN::IsOdd);
  Nan::SetPrototypeMethod(tpl, "isEven", BBN::IsEven);
  Nan::SetPrototypeMethod(tpl, "inject", BBN::Inject);
  Nan::SetPrototypeMethod(tpl, "set", BBN::Set);
  Nan::SetPrototypeMethod(tpl, "byteLength", BBN::ByteLength);
  Nan::SetPrototypeMethod(tpl, "bitLength", BBN::BitLength);
  Nan::SetPrototypeMethod(tpl, "zeroBits", BBN::ZeroBits);
  Nan::SetPrototypeMethod(tpl, "isSafe", BBN::IsSafe);
  Nan::SetPrototypeMethod(tpl, "toNumber", BBN::ToNumber);
  Nan::SetPrototypeMethod(tpl, "toDouble", BBN::ToDouble);
  Nan::SetPrototypeMethod(tpl, "toBool", BBN::ToBool);
  Nan::SetPrototypeMethod(tpl, "toBuffer", BBN::ToBuffer);
  Nan::SetPrototypeMethod(tpl, "toString", BBN::ToString);
  Nan::SetPrototypeMethod(tpl, "fromNumber", BBN::FromNumber);
  Nan::SetPrototypeMethod(tpl, "fromDouble", BBN::FromDouble);
  Nan::SetPrototypeMethod(tpl, "fromBool", BBN::FromBool);
  Nan::SetPrototypeMethod(tpl, "fromBuffer", BBN::FromBuffer);
  Nan::SetPrototypeMethod(tpl, "fromString", BBN::FromString);
  Nan::SetMethod(tpl, "randomBits", BBN::RandomBits);
  Nan::SetMethod(tpl, "random", BBN::Random);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(bn_constructor);

  Nan::Set(target, Nan::New("BN").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

bool BBN::HasInstance(v8::Local<v8::Value> val) {
  Nan::HandleScope scope;
  return Nan::New(bn_constructor)->HasInstance(val);
}

NAN_METHOD(BBN::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("BN must be called with `new`.");

  BBN *obj = new BBN();
  obj->Wrap(info.This());

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBN::Iadd) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iadd, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_add(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iaddn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iaddn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    mpz_sub_ui(a->n, a->n, -num);
  else
    mpz_add_ui(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isub) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(isub, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_sub(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isubn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(isubn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    mpz_add_ui(a->n, a->n, -num);
  else
    mpz_sub_ui(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::MulTo) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(mulTo, 2));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(out, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  BBN *out = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());

  mpz_mul(out->n, a->n, b->n);

  info.GetReturnValue().Set(info[1]);
}

NAN_METHOD(BBN::Imul) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(imul, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_mul(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Imuln) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(imuln, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  mpz_mul_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Idiv) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(idiv, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  mpz_tdiv_q(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Idivn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(idivn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  int pos = (mpz_sgn(a->n) == -1) == (num < 0);

  if (num < 0)
    num = -num;

  mpz_tdiv_q_ui(a->n, a->n, num);

  int sgn = mpz_sgn(a->n);

  if ((pos && sgn == -1)
      || (!pos && sgn == 1)) {
    mpz_neg(a->n, a->n);
  }

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::IdivRound) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(idivRound, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  bmpz_div_round(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Imod) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(imod, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  mpz_tdiv_r(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Imodn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(imodn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  int pos = mpz_sgn(a->n) == 1;

  mpz_tdiv_r_ui(a->n, a->n, num);

  int sgn = mpz_sgn(a->n);

  if ((pos && sgn == -1)
      || (!pos && sgn == 1)) {
    mpz_neg(a->n, a->n);
  }

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Modrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(modrn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  if (num < 0)
    num = -num;

  int64_t r = mpz_tdiv_ui(a->n, num);

  if (mpz_sgn(a->n) < 0)
    r = -r;

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::Iumod) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iumod, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  mpz_mod(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iumodn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iumodn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  if (num < 0)
    num = -num;

  mpz_mod_ui(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Umodrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(umodrn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num == 0)
    return Nan::ThrowRangeError(NONZERO_ERROR);

  if (num < 0)
    num = -num;

  int64_t r = mpz_fdiv_ui(a->n, num);

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::Ipow) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ipow, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  bmpz_pow(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ipown) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ipown, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    num = -num;

  mpz_pow_ui(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isqr) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  mpz_mul(a->n, a->n, a->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isqrt) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  mpz_sqrt(a->n, a->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::IsSquare) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  bool ret = mpz_sgn(a->n) >= 0 && mpz_perfect_square_p(a->n) != 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(ret));
}

NAN_METHOD(BBN::Iand) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iand, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_and(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iandn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iandn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  bmpz_and_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Andrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(andrn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();
  int64_t r = mpz_get_si(a->n) & num;

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::Iuand) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuand, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  int neg = mpz_sgn(b->n) < 0;

  if (neg)
    mpz_neg(b->n, b->n);

  mpz_and(a->n, a->n, b->n);

  if (neg)
    mpz_neg(b->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iuandn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuandn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    num = -num;

  bmpz_and_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Uandrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(uandrn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    num = -num;

  int64_t r = mpz_get_si(a->n) & num;

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::Ior) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ior, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_ior(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iorn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iorn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  bmpz_ior_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iuor) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuor, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_ior(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iuorn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuorn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  bmpz_ior_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ixor) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ixor, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_xor(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ixorn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ixorn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  bmpz_xor_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iuxor) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuxor, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_xor(a->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iuxorn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iuxorn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  bmpz_xor_si(a->n, a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Inotn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(inotn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(width, integer));

  uint32_t width = Nan::To<uint32_t>(info[0]).FromJust();

  bmpz_not(a->n, a->n, width);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ishln) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ishln, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bits, integer));

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  mpz_mul_2exp(a->n, a->n, bits);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iushln) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iushln, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bits, integer));

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  mpz_mul_2exp(a->n, a->n, bits);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ishrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ishrn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bits, integer));

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  mpz_fdiv_q_2exp(a->n, a->n, bits);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iushrn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iushrn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bits, integer));

  uint32_t bits = Nan::To<uint32_t>(info[0]).FromJust();

  mpz_fdiv_q_2exp(a->n, a->n, bits);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Setn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(setn, 2));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bit, integer));

  if (!info[1]->IsNumber() && !info[1]->IsBoolean())
    return Nan::ThrowTypeError(TYPE_ERROR(val, number));

  uint32_t bit = Nan::To<uint32_t>(info[0]).FromJust();
  bool val = Nan::To<bool>(info[1]).FromJust();

  if (val)
    mpz_setbit(a->n, bit);
  else
    mpz_clrbit(a->n, bit);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Testn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(testn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bit, integer));

  uint32_t bit = Nan::To<uint32_t>(info[0]).FromJust();
  bool ret = (bool)mpz_tstbit(a->n, bit);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(ret));
}

NAN_METHOD(BBN::Imaskn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(imaskn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(bit, integer));

  uint32_t bit = Nan::To<uint32_t>(info[0]).FromJust();

  bmpz_mask(a->n, a->n, bit);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Andln) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(andln, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();
  int64_t r = mpz_get_ui(a->n) & num;

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::Bincn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(bincn, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, integer));

  uint32_t bit = Nan::To<uint32_t>(info[0]).FromJust();

  bmpz_binc(a->n, a->n, bit);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ineg) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  mpz_neg(a->n, a->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iabs) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  mpz_abs(a->n, a->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Cmp) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(cmp, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  int32_t r = mpz_cmp(a->n, b->n);

  if (r < 0)
    r = -1;
  else if (r > 0)
    r = 1;

  info.GetReturnValue().Set(Nan::New<v8::Int32>(r));
}

NAN_METHOD(BBN::Cmpn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(cmpn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();
  int32_t r = mpz_cmp_si(a->n, num);

  if (r < 0)
    r = -1;
  else if (r > 0)
    r = 1;

  info.GetReturnValue().Set(Nan::New<v8::Int32>(r));
}

NAN_METHOD(BBN::Eq) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(eq, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  bool r = mpz_cmp(a->n, b->n) == 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::Eqn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(eqn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();
  bool r = mpz_cmp_si(a->n, num) == 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::Ucmp) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ucmp, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  int32_t r = mpz_cmpabs(a->n, b->n);

  if (r < 0)
    r = -1;
  else if (r > 0)
    r = 1;

  info.GetReturnValue().Set(Nan::New<v8::Int32>(r));
}

NAN_METHOD(BBN::Ucmpn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ucmpn, 1));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, smi));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  if (num < 0)
    num = -num;

  int32_t r = mpz_cmpabs_ui(a->n, num);

  if (r < 0)
    r = -1;
  else if (r > 0)
    r = 1;

  info.GetReturnValue().Set(Nan::New<v8::Int32>(r));
}

NAN_METHOD(BBN::Jacobi) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(jacobi, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) == 0 || mpz_even_p(b->n))
    return Nan::ThrowError("jacobi: `y` must be odd.");

  int32_t r = bmpz_jacobi(a->n, b->n);

  info.GetReturnValue().Set(Nan::New<v8::Int32>(r));
}

NAN_METHOD(BBN::Igcd) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(igcd, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(a->n) < 0)
    mpz_neg(a->n, a->n);

  int neg = mpz_sgn(b->n) < 0;

  if (neg)
    mpz_neg(b->n, b->n);

  mpz_gcd(a->n, a->n, b->n);

  if (neg)
    mpz_neg(b->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Egcd) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 4)
    return Nan::ThrowError(ARG_ERROR(egcd, 4));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[2]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[3]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *s = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  BBN *t = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());
  BBN *g = ObjectWrap::Unwrap<BBN>(info[2].As<v8::Object>());
  BBN *b = ObjectWrap::Unwrap<BBN>(info[3].As<v8::Object>());

  if (mpz_sgn(b->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(egcd));

  mpz_gcdext(g->n, s->n, t->n, a->n, b->n);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Iinvm) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(iinvm, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(iinvm));

  if (mpz_invert(a->n, a->n, b->n) == 0)
    return Nan::ThrowError("Not invertible.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ifinvm) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(ifinvm, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(b->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(ifinvm));

  if (!bmpz_finvm(a->n, a->n, b->n))
    return Nan::ThrowError("Not invertible.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ipowm) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(ipowm, 2));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  BBN *c = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());

  if (mpz_sgn(a->n) < 0 || mpz_sgn(c->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(ipowm));

  if (!bmpz_powm(a->n, a->n, b->n, c->n))
    return Nan::ThrowError("Not invertible.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Ipowmn) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(ipowmn, 2));

  if (!IsSMI(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  int64_t b = Nan::To<int64_t>(info[0]).FromJust();
  BBN *c = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());

  if (mpz_sgn(a->n) < 0 || mpz_sgn(c->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(ipowmn));

  if (!bmpz_powm_si(a->n, a->n, b, c->n))
    return Nan::ThrowError("Not invertible.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isqrtp) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(isqrtp, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  if (mpz_sgn(a->n) < 0 || mpz_sgn(b->n) <= 0)
    return Nan::ThrowRangeError(RANGE_ERROR(isqrtp));

  if (!bmpz_sqrtp(a->n, a->n, b->n))
    return Nan::ThrowError("X is not a square mod P.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::Isqrtpq) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(isqrtpq, 2));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());
  BBN *c = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());

  if (mpz_sgn(a->n) < 0
      || mpz_sgn(b->n) <= 0
      || mpz_sgn(c->n) <= 0) {
    return Nan::ThrowRangeError(RANGE_ERROR(isqrtpq));
  }

  if (!bmpz_sqrtpq(a->n, a->n, b->n, c->n))
    return Nan::ThrowError("X is not a square mod P.");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::IsPrimeMR) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError(ARG_ERROR(isPrimeMR, 3));

  if (!info[0]->IsObject() && !info[0]->IsFunction())
    return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

  if (!IsUint32(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(nreps, integer));

  if (!info[2]->IsBoolean())
    return Nan::ThrowTypeError(TYPE_ERROR(force2, boolean));

  bmpz_rng_t rng = bmpz_rng_custom;
  bmpz_rng_data_t data;

  if (!info[0]->IsFunction()) {
    v8::Local<v8::Object> obj = info[0].As<v8::Object>();
    v8::Local<v8::Value> val =
      obj->Get(Nan::New<v8::String>("randomBytes").ToLocalChecked());

    if (!val->IsFunction())
      return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

    data.callback = val.As<v8::Function>();
    data.is_bytes = 1;
  } else {
    data.callback = info[0].As<v8::Function>();
    data.is_bytes = 0;
  }

  uint32_t nreps = Nan::To<uint32_t>(info[1]).FromJust();
  bool force2 = Nan::To<bool>(info[2]).FromJust();

  int r = bmpz_prime_mr(a->n, nreps, force2, rng, (void *)&data);

  if (r == -1)
    return Nan::ThrowError("RNG failure.");

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::IsPrimeLucas) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(isPrimeLucas, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(limit, integer));

  uint32_t limit = Nan::To<uint32_t>(info[0]).FromJust();
  bool r = bmpz_prime_lucas(a->n, limit);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::ToTwos) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(toTwos, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(width, integer));

  uint32_t width = Nan::To<uint32_t>(info[0]).FromJust();

  bmpz_to_twos(a->n, a->n, width);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::FromTwos) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(fromTwos, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(width, integer));

  uint32_t width = Nan::To<uint32_t>(info[0]).FromJust();

  bmpz_from_twos(a->n, a->n, width);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::IsZero) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_sgn(a->n) == 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::IsNeg) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_sgn(a->n) < 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::IsOdd) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_odd_p(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::IsEven) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_even_p(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::Inject) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(inject, 1));

  if (!BBN::HasInstance(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  BBN *b = ObjectWrap::Unwrap<BBN>(info[0].As<v8::Object>());

  mpz_set(a->n, b->n);
}

NAN_METHOD(BBN::Set) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(set, 1));

  if (!IsInt(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, integer));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  mpz_set_si(a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::ByteLength) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  uint32_t bytes = bmpz_bytelen(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(bytes));
}

NAN_METHOD(BBN::BitLength) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  uint32_t bits = bmpz_bitlen(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(bits));
}

NAN_METHOD(BBN::ZeroBits) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  uint32_t bits = bmpz_zerobits(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Uint32>(bits));
}

NAN_METHOD(BBN::IsSafe) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_sizeinbase(a->n, 2) <= 53;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::ToNumber) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (mpz_sizeinbase(a->n, 2) > 53)
    return Nan::ThrowRangeError("Number can only safely store up to 53 bits.");

  double r = mpz_get_d(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::ToDouble) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  double r = mpz_get_d(a->n);

  info.GetReturnValue().Set(Nan::New<v8::Number>(r));
}

NAN_METHOD(BBN::ToBool) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());
  bool r = mpz_sgn(a->n) != 0;

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(r));
}

NAN_METHOD(BBN::ToBuffer) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(toBuffer, 2));

  if (!info[0]->IsString())
    return Nan::ThrowTypeError(TYPE_ERROR(endian, string));

  if (!IsUint32(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(length, integer));

  Nan::Utf8String endian_(info[0]);
  const char *endian = *endian_;

  if (strcmp(endian, "le") != 0 && strcmp(endian, "be") != 0)
    return Nan::ThrowTypeError(TYPE_ERROR(endian, endianness));

  size_t length = (size_t)Nan::To<uint32_t>(info[1]).FromJust();
  size_t bytes = bmpz_bytelen(a->n);

  if (bytes == 0)
    bytes += 1;

  size_t size = length;

  if (size == 0)
    size = bytes;

  if (bytes > size)
    return Nan::ThrowRangeError("Byte array longer than desired length.");

  uint8_t *out = (uint8_t *)malloc(size);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate buffer.");

  int end = strcmp(endian, "be") == 0 ? 1 : -1;

  uint8_t *o;

  if (end == -1) {
    o = &out[0];
    memset(&out[bytes], 0x00, size - bytes);
  } else {
    memset(&out[0], 0x00, size - bytes);
    o = &out[size - bytes];
  }

  mpz_export(o, NULL, end, 1, 0, 0, a->n);

  if (mpz_sgn(a->n) == 0)
    o[0] = 0x00;

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, size).ToLocalChecked());
}

NAN_METHOD(BBN::ToString) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(toString, 1));

  if (!IsUint32(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(base, integer));

  uint32_t base = Nan::To<uint32_t>(info[0]).FromJust();

  if (base < 2 || base > 36)
    return Nan::ThrowRangeError("Base ranges between 2 and 36.");

  int neg = mpz_sgn(a->n) == -1;

  if (neg)
    mpz_neg(a->n, a->n);

  char *str = mpz_get_str(NULL, base, a->n);
  assert(str != NULL);

  if (neg)
    mpz_neg(a->n, a->n);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)str).ToLocalChecked());

  free(str);
}

NAN_METHOD(BBN::FromNumber) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(fromNumber, 1));

  if (!IsInt(info[0]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, integer));

  int64_t num = Nan::To<int64_t>(info[0]).FromJust();

  mpz_set_si(a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::FromDouble) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(fromDouble, 1));

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError(TYPE_ERROR(num, number));

  double num = Nan::To<double>(info[0]).FromJust();

  mpz_set_d(a->n, num);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::FromBool) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError(ARG_ERROR(fromBool, 1));

  if (!info[0]->IsBoolean())
    return Nan::ThrowTypeError(TYPE_ERROR(num, boolean));

  mpz_set_ui(a->n, (uint64_t)Nan::To<bool>(info[0]).FromJust());

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::FromBuffer) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(fromBuffer, 2));

  v8::Local<v8::Object> nbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(nbuf))
    return Nan::ThrowTypeError(TYPE_ERROR(buf, buffer));

  if (!info[1]->IsString())
    return Nan::ThrowTypeError(TYPE_ERROR(endian, string));

  Nan::Utf8String endian_(info[1]);
  const char *endian = *endian_;

  if (strcmp(endian, "le") != 0 && strcmp(endian, "be") != 0)
    return Nan::ThrowTypeError(TYPE_ERROR(endian, endianness));

  const uint8_t *input = (const uint8_t *)node::Buffer::Data(nbuf);
  size_t size = node::Buffer::Length(nbuf);

  int end = strcmp(endian, "be") == 0 ? 1 : -1;

  mpz_import(a->n, size, end, 1, 0, 0, input);

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::FromString) {
  BBN *a = ObjectWrap::Unwrap<BBN>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError(ARG_ERROR(fromString, 1));

  if (!info[0]->IsString())
    return Nan::ThrowTypeError(TYPE_ERROR(str, string));

  if (!IsUint32(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(base, integer));

  Nan::Utf8String nstr(info[0]);
  const char *str = *nstr;

  uint32_t base = Nan::To<uint32_t>(info[1]).FromJust();

  if (base < 2 || base > 36)
    return Nan::ThrowRangeError("Base ranges between 2 and 36.");

  if (mpz_set_str(a->n, str, base) != 0)
    return Nan::ThrowError("Invalid string (parse error).");

  info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BBN::RandomBits) {
  if (info.Length() < 3)
    return Nan::ThrowError(ARG_ERROR(randomBits, 3));

  if (!info[0]->IsObject() && !info[0]->IsFunction())
    return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!IsUint32(info[2]))
    return Nan::ThrowTypeError(TYPE_ERROR(bits, integer));

  bmpz_rng_t rng = bmpz_rng_custom;
  bmpz_rng_data_t data;

  if (!info[0]->IsFunction()) {
    v8::Local<v8::Object> obj = info[0].As<v8::Object>();
    v8::Local<v8::Value> val =
      obj->Get(Nan::New<v8::String>("randomBytes").ToLocalChecked());

    if (!val->IsFunction())
      return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

    data.callback = val.As<v8::Function>();
    data.is_bytes = 1;
  } else {
    data.callback = info[0].As<v8::Function>();
    data.is_bytes = 0;
  }

  BBN *a = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());

  uint32_t bits = Nan::To<uint32_t>(info[2]).FromJust();

  if (!rng(a->n, bits, (void *)&data))
    return Nan::ThrowError("RNG failure.");

  info.GetReturnValue().Set(info[1]);
}

NAN_METHOD(BBN::Random) {
  if (info.Length() < 4)
    return Nan::ThrowError(ARG_ERROR(random, 4));

  if (!info[0]->IsObject() && !info[0]->IsFunction())
    return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

  if (!BBN::HasInstance(info[1]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[2]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  if (!BBN::HasInstance(info[3]))
    return Nan::ThrowTypeError(TYPE_ERROR(num, bignum));

  bmpz_rng_t rng = bmpz_rng_custom;
  bmpz_rng_data_t data;

  if (!info[0]->IsFunction()) {
    v8::Local<v8::Object> obj = info[0].As<v8::Object>();
    v8::Local<v8::Value> val =
      obj->Get(Nan::New<v8::String>("randomBytes").ToLocalChecked());

    if (!val->IsFunction())
      return Nan::ThrowTypeError(TYPE_ERROR(rng, rng));

    data.callback = val.As<v8::Function>();
    data.is_bytes = 1;
  } else {
    data.callback = info[0].As<v8::Function>();
    data.is_bytes = 0;
  }

  BBN *a = ObjectWrap::Unwrap<BBN>(info[1].As<v8::Object>());
  BBN *b = ObjectWrap::Unwrap<BBN>(info[2].As<v8::Object>());
  BBN *c = ObjectWrap::Unwrap<BBN>(info[3].As<v8::Object>());

  if (!bmpz_random_int(a->n, b->n, c->n, rng, (void *)&data))
    return Nan::ThrowError("RNG failure.");

  info.GetReturnValue().Set(info[1]);
}

static int
bmpz_rng_custom(mpz_t ret, unsigned long bits, void *data) {
  Nan::HandleScope scope;

  bmpz_rng_data_t *rng_data = (bmpz_rng_data_t *)data;

  uint32_t bytes = (bits + 7) >> 3;
  uint32_t arg = rng_data->is_bytes ? bytes : bits;

  v8::Local<v8::Value> argv[] = {
    Nan::New<v8::Uint32>(arg)
  };

  Nan::TryCatch try_catch;
  v8::MaybeLocal<v8::Value> result_ =
    Nan::Call(rng_data->callback, rng_data->callback, 1, argv);

  if (result_.IsEmpty())
    return 0;

  if (try_catch.HasCaught())
    return 0;

  v8::Local<v8::Value> result = result_.ToLocalChecked();

  if (IsNull(result))
    return 0;

  v8::Local<v8::Object> obj = result.As<v8::Object>();

  if (rng_data->is_bytes) {
    if (!node::Buffer::HasInstance(obj))
      return 0;

    const uint8_t *input = (const uint8_t *)node::Buffer::Data(obj);
    size_t size = node::Buffer::Length(obj);
    uint32_t total = bytes * 8;

    if (size != bytes)
      return 0;

    mpz_import(ret, size, 1, 1, 0, 0, input);

    if (total > bits)
      mpz_div_2exp(ret, ret, total - bits);
  } else {
    if (!BBN::HasInstance(obj))
      return 0;

    BBN *a = Nan::ObjectWrap::Unwrap<BBN>(obj);

    if (mpz_sgn(a->n) < 0 || bmpz_bitlen(a->n) > bits)
      return 0;

    mpz_set(ret, a->n);
  }

  return 1;
}
