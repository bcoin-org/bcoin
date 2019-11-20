#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "aes/aes.h"
#include "aes.h"

void
BAES::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "encipher", BAES::Encipher);
  Nan::Export(obj, "decipher", BAES::Decipher);

  Nan::Set(target, Nan::New("aes").ToLocalChecked(), obj);
}

NAN_METHOD(BAES::Encipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("aes.encipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowRangeError("Invalid key size.");

  if (ilen != 16)
    return Nan::ThrowRangeError("Invalid IV size.");

  uint32_t olen = BCRYPTO_AES_ENCIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate ciphertext.");

  if (!bcrypto_aes_encipher(data, dlen, key, iv, out, &olen)) {
    free(out);
    return Nan::ThrowError("Encipher failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}

NAN_METHOD(BAES::Decipher) {
  if (info.Length() < 3)
    return Nan::ThrowError("aes.decipher() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[1]))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  if (!node::Buffer::HasInstance(info[2]))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();
  v8::Local<v8::Object> bkey = info[1].As<v8::Object>();
  v8::Local<v8::Object> biv = info[2].As<v8::Object>();

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(bdata);
  size_t dlen = node::Buffer::Length(bdata);

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(bkey);
  size_t klen = node::Buffer::Length(bkey);

  const uint8_t *iv = (const uint8_t *)node::Buffer::Data(biv);
  size_t ilen = node::Buffer::Length(biv);

  if (klen != 32)
    return Nan::ThrowRangeError("Invalid key size.");

  if (ilen != 16)
    return Nan::ThrowRangeError("Invalid IV size.");

  uint32_t olen = BCRYPTO_AES_DECIPHER_SIZE(dlen);
  uint8_t *out = (uint8_t *)malloc(olen);

  if (out == NULL)
    return Nan::ThrowError("Could not allocate plaintext.");

  if (!bcrypto_aes_decipher(data, dlen, key, iv, out, &olen)) {
    free(out);
    return Nan::ThrowError("Decipher failed.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, olen).ToLocalChecked());
}
