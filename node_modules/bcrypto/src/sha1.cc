#include "common.h"
#include "sha1.h"

static Nan::Persistent<v8::FunctionTemplate> sha1_constructor;

BSHA1::BSHA1() {
  memset(&ctx, 0, sizeof(SHA_CTX));
}

BSHA1::~BSHA1() {}

void
BSHA1::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BSHA1::New);

  sha1_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("SHA1").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BSHA1::Init);
  Nan::SetPrototypeMethod(tpl, "update", BSHA1::Update);
  Nan::SetPrototypeMethod(tpl, "final", BSHA1::Final);
  Nan::SetMethod(tpl, "digest", BSHA1::Digest);
  Nan::SetMethod(tpl, "root", BSHA1::Root);
  Nan::SetMethod(tpl, "multi", BSHA1::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(sha1_constructor);

  Nan::Set(target, Nan::New("SHA1").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BSHA1::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create SHA1 instance.");

  BSHA1 *sha = new BSHA1();
  sha->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA1::Init) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

  SHA1_Init(&sha->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA1::Update) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("sha1.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA1_Update(&sha->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BSHA1::Final) {
  BSHA1 *sha = ObjectWrap::Unwrap<BSHA1>(info.Holder());

  uint8_t out[20];

  SHA1_Final(&out[0], &sha->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("sha1.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA_CTX ctx;
  uint8_t out[20];

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, in, inlen);
  SHA1_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha1.root() requires arguments.");

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

  if (leftlen != 20 || rightlen != 20)
    return Nan::ThrowRangeError("Invalid node sizes.");

  SHA_CTX ctx;
  uint8_t out[20];

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, left, leftlen);
  SHA1_Update(&ctx, right, rightlen);
  SHA1_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BSHA1::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("sha1.multi() requires arguments.");

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

  SHA_CTX ctx;
  uint8_t out[20];

  SHA1_Init(&ctx);
  SHA1_Update(&ctx, x, xlen);
  SHA1_Update(&ctx, y, ylen);
  SHA1_Update(&ctx, z, zlen);
  SHA1_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
