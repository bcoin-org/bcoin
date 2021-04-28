#include <torsion/util.h>

#include "common.h"
#include "hash.h"

static Nan::Persistent<v8::FunctionTemplate> hash_constructor;

BHash::BHash() {
  type = -1;
  started = false;
}

BHash::~BHash() {}

void
BHash::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BHash::New);

  hash_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Hash").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BHash::Init);
  Nan::SetPrototypeMethod(tpl, "update", BHash::Update);
  Nan::SetPrototypeMethod(tpl, "final", BHash::Final);
  Nan::SetMethod(tpl, "digest", BHash::Digest);
  Nan::SetMethod(tpl, "root", BHash::Root);
  Nan::SetMethod(tpl, "multi", BHash::Multi);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(hash_constructor);

  Nan::Set(target, Nan::New("Hash").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BHash::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Hash instance.");

  if (info.Length() < 1)
    return Nan::ThrowError("Hash() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  BHash *hash = new BHash();
  hash->type = type;
  hash->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash::Init) {
  BHash *hash = ObjectWrap::Unwrap<BHash>(info.Holder());

  hash_init(&hash->ctx, hash->type);
  hash->started = true;

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash::Update) {
  BHash *hash = ObjectWrap::Unwrap<BHash>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("hash.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!hash->started)
    return Nan::ThrowError("Context is not initialized.");

  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);

  hash_update(&hash->ctx, in, inlen);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BHash::Final) {
  BHash *hash = ObjectWrap::Unwrap<BHash>(info.Holder());

  if (!hash->started)
    return Nan::ThrowError("Context is not initialized.");

  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(hash->type);

  hash_final(&hash->ctx, out, len);
  hash->started = false;

  cleanse(&hash->ctx, sizeof(hash->ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}

NAN_METHOD(BHash::Digest) {
  if (info.Length() < 2)
    return Nan::ThrowError("Hash.digest() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *in = (const uint8_t *)node::Buffer::Data(buf);
  size_t inlen = node::Buffer::Length(buf);
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(type);
  hash_t ctx;

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  hash_init(&ctx, type);
  hash_update(&ctx, in, inlen);
  hash_final(&ctx, out, len);

  cleanse(&ctx, sizeof(ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}

NAN_METHOD(BHash::Root) {
  if (info.Length() < 3)
    return Nan::ThrowError("Hash.root() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> lbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> rbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(lbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(rbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *left = (const uint8_t *)node::Buffer::Data(lbuf);
  size_t leftlen = node::Buffer::Length(lbuf);
  const uint8_t *right = (const uint8_t *)node::Buffer::Data(rbuf);
  size_t rightlen = node::Buffer::Length(rbuf);
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(type);
  hash_t ctx;

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  if (leftlen != len || rightlen != len)
    return Nan::ThrowRangeError("Invalid node sizes.");

  hash_init(&ctx, type);
  hash_update(&ctx, left, leftlen);
  hash_update(&ctx, right, rightlen);
  hash_final(&ctx, out, len);

  cleanse(&ctx, sizeof(ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}

NAN_METHOD(BHash::Multi) {
  if (info.Length() < 3)
    return Nan::ThrowError("Hash.multi() requires arguments.");

  if (!info[0]->IsNumber())
    return Nan::ThrowTypeError("First argument must be a number.");

  v8::Local<v8::Object> xbuf = info[1].As<v8::Object>();
  v8::Local<v8::Object> ybuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(xbuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(ybuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  int type = (int)Nan::To<int32_t>(info[0]).FromJust();
  const uint8_t *x = (const uint8_t *)node::Buffer::Data(xbuf);
  size_t xlen = node::Buffer::Length(xbuf);
  const uint8_t *y = (const uint8_t *)node::Buffer::Data(ybuf);
  size_t ylen = node::Buffer::Length(ybuf);
  const uint8_t *z = NULL;
  size_t zlen = 0;
  uint8_t out[HASH_MAX_OUTPUT_SIZE];
  size_t len = hash_output_size(type);
  hash_t ctx;

  if (info.Length() > 3 && !IsNull(info[3])) {
    v8::Local<v8::Object> zbuf = info[3].As<v8::Object>();

    if (!node::Buffer::HasInstance(zbuf))
      return Nan::ThrowTypeError("Third argument must be a buffer.");

    z = (const uint8_t *)node::Buffer::Data(zbuf);
    zlen = node::Buffer::Length(zbuf);
  }

  if (!hash_has_backend(type))
    return Nan::ThrowError("Hash not available.");

  hash_init(&ctx, type);
  hash_update(&ctx, x, xlen);
  hash_update(&ctx, y, ylen);
  hash_update(&ctx, z, zlen);
  hash_final(&ctx, out, len);

  cleanse(&ctx, sizeof(ctx));

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)out, len).ToLocalChecked());
}
