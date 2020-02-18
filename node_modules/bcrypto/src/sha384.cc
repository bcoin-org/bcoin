#include "common.h"
#include "sha384.h"

static Nan::Persistent<v8::FunctionTemplate> sha384_constructor;

BSHA384::BSHA384() {
  memset(&ctx, 0, sizeof(SHA512_CTX));
}

BSHA384::~BSHA384() {}

void
BSHA384::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA384::New);

  sha384_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA384").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA384::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA384::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA384::Final);
  Nan::SetMethod(tpl, "digest", BSHA384::Digest);
  Nan::SetMethod(tpl, "root", BSHA384::Root);
  Nan::SetMethod(tpl, "multi", BSHA384::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha384_constructor);

  Nan::Set(target, Nan::New("SHA384").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSHA384::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA384 instance.");

  BSHA384 *sha = new BSHA384();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Init) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  SHA384_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Update) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha384.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA384_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA384::Final) {
  BSHA384 *sha = ObjectWrap::Unwrap<BSHA384>(info.Holder());

  uint8_t out[64];

  SHA384_Final(&out[0], &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha384.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA512_CTX ctx;
  uint8_t out[64];

  SHA384_Init(&ctx);
  SHA384_Update(&ctx, in, inlen);
  SHA384_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha384.root() requires arguments.");

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

  if (leftlen != 48 || rightlen != 48)
    return Nan::ThrowRangeError("Invalid node sizes.");

  SHA512_CTX ctx;
  uint8_t out[64];

  SHA384_Init(&ctx);
  SHA384_Update(&ctx, left, leftlen);
  SHA384_Update(&ctx, right, rightlen);
  SHA384_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 48).ToLocalChecked());
}

NAN_METHOD(BSHA384::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha384.multi() requires arguments.");

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

  SHA384_Init(&ctx);
  SHA384_Update(&ctx, x, xlen);
  SHA384_Update(&ctx, y, ylen);
  SHA384_Update(&ctx, z, zlen);
  SHA384_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 48).ToLocalChecked());
}
