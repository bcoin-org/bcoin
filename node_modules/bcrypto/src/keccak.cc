#include "common.h"
#include "keccak.h"

static Nan::Persistent<v8::FunctionTemplate> keccak_constructor;

BKeccak::BKeccak() {
  memset(&ctx, 0, sizeof(keccak_t));
  started = false;
}

BKeccak::~BKeccak() {}

void
BKeccak::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BKeccak::New);

  keccak_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Keccak").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BKeccak::Init);
  Nan::SetPrototypeMethod(tpl, "update", BKeccak::Update);
  Nan::SetPrototypeMethod(tpl, "final", BKeccak::Final);
  Nan::SetMethod(tpl, "digest", BKeccak::Digest);
  Nan::SetMethod(tpl, "root", BKeccak::Root);
  Nan::SetMethod(tpl, "multi", BKeccak::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(keccak_constructor);

  Nan::Set(target, Nan::New("Keccak").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BKeccak::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Keccak instance.");

  BKeccak *keccak = new BKeccak();
  keccak->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Init) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  uint32_t bits = 256;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    bits = Nan::To<uint32_t>(info[0]).FromJust();
  }

  size_t rate = 1600 - bits * 2;

  if (bits < 128 || bits > 512 || (rate & 63) != 0)
    return Nan::ThrowError("Could not initialize context.");

  keccak_init(&keccak->ctx, bits);
  keccak->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Update) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("keccak.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!keccak->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  keccak_update(&keccak->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BKeccak::Final) {
  BKeccak *keccak = ObjectWrap::Unwrap<BKeccak>(info.Holder());

  if (!keccak->started)
    return Nan::ThrowError("Context is not initialized.");

  int pad = 0x01;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    pad = (int)Nan::To<uint32_t>(info[0]).FromJust();
  }

  size_t outlen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    outlen = (size_t)Nan::To<uint32_t>(info[1]).FromJust();
  }

  if (outlen == 0)
    outlen = 100 - (keccak->ctx.bs >> 1);

  if (outlen >= keccak->ctx.bs)
    return Nan::ThrowError("Could not finalize context.");

  uint8_t out[200];

  keccak_final(&keccak->ctx, out, pad, outlen);
  keccak->started = false;

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("keccak.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t bits = 256;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    bits = Nan::To<uint32_t>(info[1]).FromJust();
  }

  int pad = 0x01;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    pad = (int)Nan::To<uint32_t>(info[2]).FromJust();
  }

  size_t outlen = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    outlen = (size_t)Nan::To<uint32_t>(info[3]).FromJust();
  }

  keccak_t ctx;
  uint8_t out[200];
  size_t rate = 1600 - bits * 2;
  size_t bs = rate >> 3;

  if (bits < 128 || bits > 512 || (rate & 63) != 0)
    return Nan::ThrowError("Could not initialize context.");

  if (outlen == 0)
    outlen = 100 - (bs >> 1);

  if (outlen >= bs)
    return Nan::ThrowError("Could not finalize context.");

  keccak_init(&ctx, bits);
  keccak_update(&ctx, in, inlen);
  keccak_final(&ctx, out, pad, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("keccak.root() requires arguments.");

  v8::Local<v8::Object> lbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *left = (const uint8_t *)node::Buffer::Data(lbuf);
  size_t leftlen = node::Buffer::Length(lbuf);

  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *right = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  uint32_t bits = 256;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    bits = Nan::To<uint32_t>(info[2]).FromJust();
  }

  int pad = 0x01;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    pad = (int)Nan::To<uint32_t>(info[3]).FromJust();
  }

  size_t outlen = 0;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsNumber())
      return Nan::ThrowTypeError("Fifth argument must be a number.");

    outlen = (size_t)Nan::To<uint32_t>(info[4]).FromJust();
  }

  if (outlen != 0) {
    if (leftlen != outlen || rightlen != outlen)
      return Nan::ThrowRangeError("Invalid node sizes.");
  } else {
    if (leftlen != bits / 8 || rightlen != bits / 8)
      return Nan::ThrowRangeError("Invalid node sizes.");
  }

  keccak_t ctx;
  uint8_t out[200];
  size_t rate = 1600 - bits * 2;
  size_t bs = rate >> 3;

  if (bits < 128 || bits > 512 || (rate & 63) != 0)
    return Nan::ThrowError("Could not initialize context.");

  if (outlen == 0)
    outlen = 100 - (bs >> 1);

  if (outlen >= bs)
    return Nan::ThrowError("Could not finalize context.");

  keccak_init(&ctx, bits);
  keccak_update(&ctx, left, leftlen);
  keccak_update(&ctx, right, rightlen);
  keccak_final(&ctx, out, pad, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BKeccak::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("keccak.multi() requires arguments.");

  v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *x = (const uint8_t *)node::Buffer::Data(xbuf);
  size_t xlen = node::Buffer::Length(xbuf);

  v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *y = (const uint8_t *)node::Buffer::Data(ybuf);
  size_t ylen = node::Buffer::Length(ybuf);

  const uint8_t *z = NULL;
  size_t zlen = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> zbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(zbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    z = (const uint8_t *)node::Buffer::Data(zbuf);
    zlen = node::Buffer::Length(zbuf);
  }

  uint32_t bits = 256;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    bits = Nan::To<uint32_t>(info[3]).FromJust();
  }

  int pad = 0x01;

  if (info.Length() > 4 && !IsNull(info[4])) {
    if (!info[4]->IsNumber())
      return Nan::ThrowTypeError("Fifth argument must be a number.");

    pad = (int)Nan::To<uint32_t>(info[4]).FromJust();
  }

  size_t outlen = 0;

  if (info.Length() > 5 && !IsNull(info[5])) {
    if (!info[5]->IsNumber())
      return Nan::ThrowTypeError("Sixth argument must be a number.");

    outlen = (size_t)Nan::To<uint32_t>(info[5]).FromJust();
  }

  keccak_t ctx;
  uint8_t out[200];
  size_t rate = 1600 - bits * 2;
  size_t bs = rate >> 3;

  if (bits < 128 || bits > 512 || (rate & 63) != 0)
    return Nan::ThrowError("Could not initialize context.");

  if (outlen == 0)
    outlen = 100 - (bs >> 1);

  if (outlen >= bs)
    return Nan::ThrowError("Could not finalize context.");

  keccak_init(&ctx, bits);
  keccak_update(&ctx, x, xlen);
  keccak_update(&ctx, y, ylen);
  keccak_update(&ctx, z, zlen);
  keccak_final(&ctx, out, pad, outlen);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}
