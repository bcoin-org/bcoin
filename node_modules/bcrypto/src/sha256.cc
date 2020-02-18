#include "common.h"
#include "sha256.h"

static Nan::Persistent<v8::FunctionTemplate> sha256_constructor;

BSHA256::BSHA256() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

BSHA256::~BSHA256() {}

void
BSHA256::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA256::New);

  sha256_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA256").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA256::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA256::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA256::Final);
  Nan::SetMethod(tpl, "digest", BSHA256::Digest);
  Nan::SetMethod(tpl, "root", BSHA256::Root);
  Nan::SetMethod(tpl, "multi", BSHA256::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha256_constructor);

  Nan::Set(target, Nan::New("SHA256").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSHA256::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA256 instance.");

  BSHA256 *sha = new BSHA256();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA256::Init) {
  BSHA256 *sha = ObjectWrap::Unwrap<BSHA256>(info.Holder());

  SHA256_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA256::Update) {
  BSHA256 *sha = ObjectWrap::Unwrap<BSHA256>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha256.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA256::Final) {
  BSHA256 *sha = ObjectWrap::Unwrap<BSHA256>(info.Holder());

  uint8_t out[32];

  SHA256_Final(&out[0], &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BSHA256::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha256.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_CTX ctx;
  uint8_t out[32];

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, in, inlen);
  SHA256_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BSHA256::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha256.root() requires arguments.");

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

  if (leftlen != 32 || rightlen != 32)
    return Nan::ThrowRangeError("Invalid node sizes.");

  SHA256_CTX ctx;
  uint8_t out[32];

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, left, leftlen);
  SHA256_Update(&ctx, right, rightlen);
  SHA256_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}

NAN_METHOD(BSHA256::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha256.multi() requires arguments.");

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

  SHA256_CTX ctx;
  uint8_t out[32];

  SHA256_Init(&ctx);
  SHA256_Update(&ctx, x, xlen);
  SHA256_Update(&ctx, y, ylen);
  SHA256_Update(&ctx, z, zlen);
  SHA256_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 32).ToLocalChecked());
}
