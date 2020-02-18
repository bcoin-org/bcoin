#include "common.h"
#include "hash160.h"
#include "openssl/ripemd.h"

static Nan::Persistent<v8::FunctionTemplate> hash160_constructor;

BHash160::BHash160() {
  memset(&ctx, 0, sizeof(SHA256_CTX));
}

BHash160::~BHash160() {}

void
BHash160::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHash160::New);

  hash160_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash160").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHash160::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHash160::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHash160::Final);
  Nan::SetMethod(tpl, "digest", BHash160::Digest);
  Nan::SetMethod(tpl, "root", BHash160::Root);
  Nan::SetMethod(tpl, "multi", BHash160::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash160_constructor);

  Nan::Set(target, Nan::New("Hash160").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BHash160::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash160 instance.");

  BHash160 *hash = new BHash160();
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Init) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  SHA256_Init(&hash->ctx);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Update) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash160.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_Update(&hash->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash160::Final) {
  BHash160 *hash = ObjectWrap::Unwrap<BHash160>(info.Holder());

  RIPEMD160_CTX rctx;
  uint8_t out[32];

  SHA256_Final(&out[0], &hash->ctx);

  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, &out[0], 32);
  RIPEMD160_Final(&out[0], &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Digest) {
  if (info.Length() < 1)
    return Nan::ThrowError("hash160.digest() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  SHA256_CTX sctx;
  RIPEMD160_CTX rctx;
  uint8_t out[32];

  SHA256_Init(&sctx);
  SHA256_Update(&sctx, in, inlen);
  SHA256_Final(&out[0], &sctx);

  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, &out[0], 32);
  RIPEMD160_Final(&out[0], &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Root) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.root() requires arguments.");

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

  SHA256_CTX sctx;
  RIPEMD160_CTX rctx;
  uint8_t out[32];

  SHA256_Init(&sctx);
  SHA256_Update(&sctx, left, leftlen);
  SHA256_Update(&sctx, right, rightlen);
  SHA256_Final(&out[0], &sctx);

  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, &out[0], 32);
  RIPEMD160_Final(&out[0], &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}

NAN_METHOD(BHash160::Multi) {
  if (info.Length() < 2)
    return Nan::ThrowError("hash160.multi() requires arguments.");

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

  SHA256_CTX sctx;
  RIPEMD160_CTX rctx;
  uint8_t out[32];

  SHA256_Init(&sctx);
  SHA256_Update(&sctx, x, xlen);
  SHA256_Update(&sctx, y, ylen);
  SHA256_Update(&sctx, z, zlen);
  SHA256_Final(&out[0], &sctx);

  RIPEMD160_Init(&rctx);
  RIPEMD160_Update(&rctx, &out[0], 32);
  RIPEMD160_Final(&out[0], &rctx);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&out[0], 20).ToLocalChecked());
}
