#include "common.h"
#include "md4.h"

static Nan::Persistent<v8::FunctionTemplate> md4_constructor;

BMD4::BMD4() {
  memset(&ctx, 0, sizeof(MD4_CTX));
}

BMD4::~BMD4() {}

void
BMD4::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BMD4::New);

  md4_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("MD4").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BMD4::Init);
  Nan::SetPrototypeMethod(tpl, "update", BMD4::Update);
  Nan::SetPrototypeMethod(tpl, "final", BMD4::Final);
  Nan::SetMethod(tpl, "digest", BMD4::Digest);
  Nan::SetMethod(tpl, "root", BMD4::Root);
  Nan::SetMethod(tpl, "multi", BMD4::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(md4_constructor);

  Nan::Set(target, Nan::New("MD4").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BMD4::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create MD4 instance.");

  BMD4 *md4 = new BMD4();
  md4->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD4::Init) {
  BMD4 *md4 = ObjectWrap::Unwrap<BMD4>(info.Holder());

  MD4_Init(&md4->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD4::Update) {
  BMD4 *md4 = ObjectWrap::Unwrap<BMD4>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("md4.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD4_Update(&md4->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD4::Final) {
  BMD4 *md4 = ObjectWrap::Unwrap<BMD4>(info.Holder());

  uint8_t out[16];

  MD4_Final(&out[0], &md4->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD4::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("md4.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD4_CTX ctx;
  uint8_t out[16];

  MD4_Init(&ctx);
  MD4_Update(&ctx, in, inlen);
  MD4_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD4::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("md4.root() requires arguments.");

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

  if (leftlen != 16 || rightlen != 16)
    return Nan::ThrowRangeError("Invalid node sizes.");

  MD4_CTX ctx;
  uint8_t out[16];

  MD4_Init(&ctx);
  MD4_Update(&ctx, left, leftlen);
  MD4_Update(&ctx, right, rightlen);
  MD4_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD4::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("md4.multi() requires arguments.");

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

  MD4_CTX ctx;
  uint8_t out[16];

  MD4_Init(&ctx);
  MD4_Update(&ctx, x, xlen);
  MD4_Update(&ctx, y, ylen);
  MD4_Update(&ctx, z, zlen);
  MD4_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}
