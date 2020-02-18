#include "common.h"
#include "sha512.h"

static Nan::Persistent<v8::FunctionTemplate> sha512_constructor;

BSHA512::BSHA512() {
  memset(&ctx, 0, sizeof(SHA512_CTX));
}

BSHA512::~BSHA512() {}

void
BSHA512::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA512::New);

  sha512_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA512").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA512::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA512::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA512::Final);
  Nan::SetMethod(tpl, "digest", BSHA512::Digest);
  Nan::SetMethod(tpl, "root", BSHA512::Root);
  Nan::SetMethod(tpl, "multi", BSHA512::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha512_constructor);

  Nan::Set(target, Nan::New("SHA512").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSHA512::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA512 instance.");

  BSHA512 *sha = new BSHA512();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA512::Init) {
  BSHA512 *sha = ObjectWrap::Unwrap<BSHA512>(info.Holder());

  SHA512_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA512::Update) {
  BSHA512 *sha = ObjectWrap::Unwrap<BSHA512>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha512.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA512_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA512::Final) {
  BSHA512 *sha = ObjectWrap::Unwrap<BSHA512>(info.Holder());

  uint8_t out[64];

  SHA512_Final(&out[0], &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BSHA512::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha512.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA512_CTX ctx;
  uint8_t out[64];

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, in, inlen);
  SHA512_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BSHA512::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha512.root() requires arguments.");

  v8::Local<v8::Object> lbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *left = (const uint8_t *)node::Buffer::Data(lbuf);
  const uint8_t *right = (const uint8_t *)node::Buffer::Data(rbuf);

  size_t leftlen = node::Buffer::Length(lbuf);
  size_t rightlen = node::Buffer::Length(rbuf);

  if (leftlen != 64 || rightlen != 64)
    return Nan::ThrowRangeError("Invalid node sizes.");

  SHA512_CTX ctx;
  uint8_t out[64];

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, left, leftlen);
  SHA512_Update(&ctx, right, rightlen);
  SHA512_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BSHA512::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha512.multi() requires arguments.");

  v8::Local<v8::Object> xbuf = info[0].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *x = (const uint8_t *)node::Buffer::Data(xbuf);
  const uint8_t *y = (const uint8_t *)node::Buffer::Data(ybuf);

  size_t xlen = node::Buffer::Length(xbuf);
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

  SHA512_CTX ctx;
  uint8_t out[64];

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, x, xlen);
  SHA512_Update(&ctx, y, ylen);
  SHA512_Update(&ctx, z, zlen);
  SHA512_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}
