#include "common.h"
#include "md5.h"

static Nan::Persistent<v8::FunctionTemplate> md5_constructor;

BMD5::BMD5() {
  memset(&ctx, 0, sizeof(MD5_CTX));
}

BMD5::~BMD5() {}

void
BMD5::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BMD5::New);

  md5_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("MD5").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BMD5::Init);
  Nan::SetPrototypeMethod(tpl, "update", BMD5::Update);
  Nan::SetPrototypeMethod(tpl, "final", BMD5::Final);
  Nan::SetMethod(tpl, "digest", BMD5::Digest);
  Nan::SetMethod(tpl, "root", BMD5::Root);
  Nan::SetMethod(tpl, "multi", BMD5::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(md5_constructor);

  Nan::Set(target, Nan::New("MD5").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BMD5::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create MD5 instance.");

  BMD5 *md5 = new BMD5();
  md5->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Init) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  MD5_Init(&md5->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Update) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("md5.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD5_Update(&md5->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BMD5::Final) {
  BMD5 *md5 = ObjectWrap::Unwrap<BMD5>(info.Holder());

  uint8_t out[16];

  MD5_Final(&out[0], &md5->ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("md5.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  MD5_CTX ctx;
  uint8_t out[16];

  MD5_Init(&ctx);
  MD5_Update(&ctx, in, inlen);
  MD5_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("md5.root() requires arguments.");

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

  MD5_CTX ctx;
  uint8_t out[16];

  MD5_Init(&ctx);
  MD5_Update(&ctx, left, leftlen);
  MD5_Update(&ctx, right, rightlen);
  MD5_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}

NAN_METHOD(BMD5::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("md5.multi() requires arguments.");

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

  MD5_CTX ctx;
  uint8_t out[16];

  MD5_Init(&ctx);
  MD5_Update(&ctx, x, xlen);
  MD5_Update(&ctx, y, ylen);
  MD5_Update(&ctx, z, zlen);
  MD5_Final(&out[0], &ctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 16).ToLocalChecked());
}
