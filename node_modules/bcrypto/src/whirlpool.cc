#include "common.h"
#include "whirlpool.h"

static Nan::Persistent<v8::FunctionTemplate> whirlpool_constructor;

BWhirlpool::BWhirlpool() {
  memset(&ctx, 0, sizeof(WHIRLPOOL_CTX));
}

BWhirlpool::~BWhirlpool() {}

void
BWhirlpool::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BWhirlpool::New);

  whirlpool_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Whirlpool").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BWhirlpool::Init);
  Nan::SetPrototypeMethod(tpl, "update", BWhirlpool::Update);
  Nan::SetPrototypeMethod(tpl, "final", BWhirlpool::Final);
  Nan::SetMethod(tpl, "digest", BWhirlpool::Digest);
  Nan::SetMethod(tpl, "root", BWhirlpool::Root);
  Nan::SetMethod(tpl, "multi", BWhirlpool::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(whirlpool_constructor);

  Nan::Set(target, Nan::New("Whirlpool").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BWhirlpool::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Whirlpool instance.");

  BWhirlpool *sha = new BWhirlpool();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BWhirlpool::Init) {
  BWhirlpool *sha = ObjectWrap::Unwrap<BWhirlpool>(info.Holder());

  WHIRLPOOL_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BWhirlpool::Update) {
  BWhirlpool *sha = ObjectWrap::Unwrap<BWhirlpool>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("whirlpool.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  WHIRLPOOL_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BWhirlpool::Final) {
  BWhirlpool *sha = ObjectWrap::Unwrap<BWhirlpool>(info.Holder());

  uint8_t out[64];

  WHIRLPOOL_Final(&out[0], &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BWhirlpool::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("whirlpool.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  WHIRLPOOL_CTX ctx;
  uint8_t out[64];

  WHIRLPOOL_Init(&ctx);
  WHIRLPOOL_Update(&ctx, in, inlen);
  WHIRLPOOL_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BWhirlpool::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("whirlpool.root() requires arguments.");

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

  WHIRLPOOL_CTX ctx;
  uint8_t out[64];

  WHIRLPOOL_Init(&ctx);
  WHIRLPOOL_Update(&ctx, left, leftlen);
  WHIRLPOOL_Update(&ctx, right, rightlen);
  WHIRLPOOL_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}

NAN_METHOD(BWhirlpool::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("whirlpool.multi() requires arguments.");

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

  WHIRLPOOL_CTX ctx;
  uint8_t out[64];

  WHIRLPOOL_Init(&ctx);
  WHIRLPOOL_Update(&ctx, x, xlen);
  WHIRLPOOL_Update(&ctx, y, ylen);
  WHIRLPOOL_Update(&ctx, z, zlen);
  WHIRLPOOL_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 64).ToLocalChecked());
}
