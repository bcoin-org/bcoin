#include "common.h"
#include "blake2s.h"

static Nan::Persistent<v8::FunctionTemplate> blake2s_constructor;

BBLAKE2s::BBLAKE2s() {
  memset(&ctx, 0, sizeof(blake2s_t));
  started = false;
}

BBLAKE2s::~BBLAKE2s() {}

void
BBLAKE2s::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BBLAKE2s::New);

  blake2s_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("BLAKE2s").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BBLAKE2s::Init);
  Nan::SetPrototypeMethod(tpl, "update", BBLAKE2s::Update);
  Nan::SetPrototypeMethod(tpl, "final", BBLAKE2s::Final);
  Nan::SetMethod(tpl, "digest", BBLAKE2s::Digest);
  Nan::SetMethod(tpl, "root", BBLAKE2s::Root);
  Nan::SetMethod(tpl, "multi", BBLAKE2s::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(blake2s_constructor);

  Nan::Set(target, Nan::New("BLAKE2s").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create BLAKE2s instance.");

  BBLAKE2s *blake = new BBLAKE2s();
  blake->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Init) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  uint32_t outlen = 32;

  if (info.Length() > 0 && !IsNull(info[0])) {
    if (!info[0]->IsNumber())
      return Nan::ThrowTypeError("First argument must be a number.");

    outlen = Nan::To<uint32_t>(info[0]).FromJust();

    if (outlen == 0 || outlen > 32)
      return Nan::ThrowRangeError("Invalid output length.");
  }

  const uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Object> buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    key = (const uint8_t *)node::Buffer::Data(buf);
    keylen = node::Buffer::Length(buf);

    if (keylen > 32)
      return Nan::ThrowRangeError("Invalid key size.");
  }

  blake2s_init(&blake->ctx, outlen, key, keylen);
  blake->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Update) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("blake2s.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!blake->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  blake2s_update(&blake->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BBLAKE2s::Final) {
  BBLAKE2s *blake = ObjectWrap::Unwrap<BBLAKE2s>(info.Holder());

  if (!blake->started)
    return Nan::ThrowError("Context is not initialized.");

  uint32_t outlen = blake->ctx.outlen;
  uint8_t out[32];

  blake2s_final(&blake->ctx, &out[0]);
  blake->started = false;

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("blake2s.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  uint32_t outlen = 32;
  const uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 1 && !IsNull(info[1])) {
    if (!info[1]->IsNumber())
      return Nan::ThrowTypeError("Second argument must be a number.");

    outlen = Nan::To<uint32_t>(info[1]).FromJust();

    if (outlen == 0 || outlen > 32)
      return Nan::ThrowRangeError("Invalid output length.");
  }

  if (info.Length() > 2 && !IsNull(info[2])) {
    v8::Local<v8::Object> kbuf = info[2].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    key = (const uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > 32)
      return Nan::ThrowRangeError("Invalid key size.");
  }

  blake2s_t ctx;
  uint8_t out[32];

  blake2s_init(&ctx, outlen, key, keylen);
  blake2s_update(&ctx, in, inlen);
  blake2s_final(&ctx, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2s.root() requires arguments.");

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

  uint32_t outlen = 32;
  const uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 2 && !IsNull(info[2])) {
    if (!info[2]->IsNumber())
      return Nan::ThrowTypeError("Third argument must be a number.");

    outlen = Nan::To<uint32_t>(info[2]).FromJust();

    if (outlen == 0 || outlen > 32)
      return Nan::ThrowRangeError("Invalid output length.");
  }

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> kbuf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Fourth argument must be a buffer.");

    key = (const uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > 32)
      return Nan::ThrowRangeError("Invalid key size.");
  }

  if (leftlen != outlen || rightlen != outlen)
    return Nan::ThrowRangeError("Invalid node sizes.");

  blake2s_t ctx;
  uint8_t out[32];

  blake2s_init(&ctx, outlen, key, keylen);
  blake2s_update(&ctx, left, leftlen);
  blake2s_update(&ctx, right, rightlen);
  blake2s_final(&ctx, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}

NAN_METHOD(BBLAKE2s::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("blake2s.multi() requires arguments.");

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

  uint32_t outlen = 32;
  const uint8_t *key = NULL;
  size_t keylen = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    outlen = Nan::To<uint32_t>(info[3]).FromJust();

    if (outlen == 0 || outlen > 32)
      return Nan::ThrowRangeError("Invalid output length.");
  }

  if (info.Length() > 4 && !IsNull(info[4])) {
    v8::Local<v8::Object> kbuf = info[4].As<v8::Object>();

    if (!node::Buffer::HasInstance(kbuf))
      return Nan::ThrowTypeError("Fifth argument must be a buffer.");

    key = (const uint8_t *)node::Buffer::Data(kbuf);
    keylen = node::Buffer::Length(kbuf);

    if (keylen > 32)
      return Nan::ThrowRangeError("Invalid key size.");
  }

  blake2s_t ctx;
  uint8_t out[32];

  blake2s_init(&ctx, outlen, key, keylen);
  blake2s_update(&ctx, x, xlen);
  blake2s_update(&ctx, y, ylen);
  blake2s_update(&ctx, z, zlen);
  blake2s_final(&ctx, &out[0]);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], outlen).ToLocalChecked());
}
