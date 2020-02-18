#include "common.h"
#include "cipherbase.h"
#include "openssl/evp.h"

static Nan::Persistent<v8::FunctionTemplate> cipher_constructor;

static bool IsValidGCMTagLength(unsigned int tag_len) {
  return tag_len == 4 || tag_len == 8 || (tag_len >= 12 && tag_len <= 16);
}

#if NODE_MAJOR_VERSION < 10
#define BCRYPTO_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#define BCRYPTO_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG
#define BCRYPTO_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#else
#define BCRYPTO_AEAD_SET_IVLEN EVP_CTRL_AEAD_SET_IVLEN
#define BCRYPTO_AEAD_SET_TAG EVP_CTRL_AEAD_SET_TAG
#define BCRYPTO_AEAD_GET_TAG EVP_CTRL_AEAD_GET_TAG
#endif

BCipherBase::BCipherBase() {
  type = NULL;
  encrypt = false;
  ctx = NULL;
}

BCipherBase::~BCipherBase() {
  type = NULL;
  encrypt = false;
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
  }
}

void
BCipherBase::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BCipherBase::New);

  cipher_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("CipherBase").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", BCipherBase::Init);
  Nan::SetPrototypeMethod(tpl, "update", BCipherBase::Update);
  Nan::SetPrototypeMethod(tpl, "final", BCipherBase::Final);
  Nan::SetPrototypeMethod(tpl, "setAAD", BCipherBase::SetAAD);
  Nan::SetPrototypeMethod(tpl, "getAuthTag", BCipherBase::GetAuthTag);
  Nan::SetPrototypeMethod(tpl, "setAuthTag", BCipherBase::SetAuthTag);
  Nan::SetMethod(tpl, "hasCipher", BCipherBase::HasCipher);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(cipher_constructor);

  Nan::Set(target, Nan::New("CipherBase").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(BCipherBase::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Cipher instance.");

  if (info.Length() < 2)
    return Nan::ThrowError("cipher requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsBoolean())
    return Nan::ThrowTypeError("Second argument must be a boolean.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;
  bool encrypt = Nan::To<bool>(info[1]).FromJust();

  const EVP_CIPHER *type = EVP_get_cipherbyname(name);

  if (!type)
    return Nan::ThrowError("Invalid cipher name.");

  int mode = EVP_CIPHER_mode(type);

  if (mode != EVP_CIPH_ECB_MODE
      && mode != EVP_CIPH_CBC_MODE
      && mode != EVP_CIPH_CTR_MODE
      && mode != EVP_CIPH_CFB_MODE
      && mode != EVP_CIPH_OFB_MODE
      && mode != EVP_CIPH_GCM_MODE) {
    return Nan::ThrowError("Invalid cipher mode.");
  }

  BCipherBase *cipher = new BCipherBase();
  cipher->type = type;
  cipher->encrypt = encrypt;
  cipher->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Init) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.init() requires arguments.");

  v8::Local<v8::Object> key_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(key_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *key = (const uint8_t *)node::Buffer::Data(key_buf);
  size_t key_len = node::Buffer::Length(key_buf);

  const uint8_t *iv = NULL;
  int iv_len = -1;

  if (info.Length() > 1 && !IsNull(info[1])) {
    v8::Local<v8::Value> iv_buf = info[1].As<v8::Object>();

    if (!node::Buffer::HasInstance(iv_buf))
      return Nan::ThrowTypeError("Second argument must be a buffer.");

    iv = (const uint8_t *)node::Buffer::Data(iv_buf);
    iv_len = node::Buffer::Length(iv_buf);
  }

  int mode = EVP_CIPHER_mode(cipher->type);

  if (mode != EVP_CIPH_GCM_MODE) {
    int expected_iv_len = EVP_CIPHER_iv_length(cipher->type);
    bool has_iv = iv_len >= 0;

    if ((!has_iv && expected_iv_len != 0)
        || (has_iv && iv_len != expected_iv_len)) {
      return Nan::ThrowRangeError("Invalid IV length.");
    }
  }

  if (cipher->ctx) {
    EVP_CIPHER_CTX_free(cipher->ctx);
    cipher->ctx = NULL;
  }

  cipher->ctx = EVP_CIPHER_CTX_new();

  if (!cipher->ctx)
    return Nan::ThrowError("Failed to initialize cipher.");

  int r = EVP_CipherInit_ex(cipher->ctx, cipher->type, NULL,
                            NULL, NULL, cipher->encrypt);

  if (r != 1)
    return Nan::ThrowError("Failed to initialize cipher.");

  if (mode == EVP_CIPH_GCM_MODE) {
    if (!EVP_CIPHER_CTX_ctrl(cipher->ctx,
                             BCRYPTO_AEAD_SET_IVLEN,
                             iv_len,
                             NULL)) {
      return Nan::ThrowError("Failed to initialize cipher.");
    }
  }

  if (!EVP_CIPHER_CTX_set_key_length(cipher->ctx, key_len))
    return Nan::ThrowRangeError("Invalid key length.");

  r = EVP_CipherInit_ex(cipher->ctx, NULL, NULL, key, iv, cipher->encrypt);

  if (r != 1)
    return Nan::ThrowError("Failed to initialize cipher.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::Update) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.update() requires arguments.");

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> data_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(data_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(data_buf);
  size_t data_len = node::Buffer::Length(data_buf);

  int buff_len = data_len + EVP_CIPHER_CTX_block_size(cipher->ctx);
  uint8_t *out = (uint8_t *)malloc(buff_len);
  int out_len;

  if (!out)
    return Nan::ThrowError("Failed to update cipher.");

  int r = EVP_CipherUpdate(cipher->ctx, out, &out_len, data, data_len);

  assert(out_len <= buff_len);

  if (r != 1) {
    free(out);
    return Nan::ThrowError("Failed to update cipher.");
  }

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::Final) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  size_t block_size = EVP_CIPHER_CTX_block_size(cipher->ctx);
  uint8_t *out = (uint8_t *)malloc(block_size);
  int out_len = -1;

  if (!out)
    return Nan::ThrowError("Failed to finalize cipher.");

  int r = EVP_CipherFinal_ex(cipher->ctx, out, &out_len);

  if (r != 1 || out_len < 0) {
    free(out);
    return Nan::ThrowError("Failed to finalize cipher.");
  }

  if (out_len == 0) {
    free(out);
    out = NULL;
  }

  return info.GetReturnValue().Set(
    Nan::NewBuffer((char *)out, (size_t)out_len).ToLocalChecked());
}

NAN_METHOD(BCipherBase::SetAAD) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.setAAD() requires arguments.");

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  int outlen;
  const int mode = EVP_CIPHER_CTX_mode(cipher->ctx);

  if (mode != EVP_CIPH_GCM_MODE)
    return Nan::ThrowError("Cipher is not authenticated.");

  int r = EVP_CipherUpdate(cipher->ctx,
                           nullptr,
                           &outlen,
                           (const unsigned char *)data,
                           len);

  if (r != 1)
    return Nan::ThrowError("Could not set AAD.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::GetAuthTag) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  const int mode = EVP_CIPHER_CTX_mode(cipher->ctx);

  if (mode != EVP_CIPH_GCM_MODE)
    return Nan::ThrowError("Cipher is not authenticated.");

  if (!cipher->encrypt)
    return Nan::ThrowError("Cannot get auth tag when decrypting.");

  uint8_t tag[16];

  int r = EVP_CIPHER_CTX_ctrl(cipher->ctx, BCRYPTO_AEAD_GET_TAG,
                              16, (unsigned char *)tag);

  if (r != 1)
    return Nan::ThrowError("Could not set auth tag.");

  return info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&tag[0], 16).ToLocalChecked());
}

NAN_METHOD(BCipherBase::SetAuthTag) {
  BCipherBase *cipher = ObjectWrap::Unwrap<BCipherBase>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("cipher.setAuthTag() requires arguments.");

  if (!cipher->ctx)
    return Nan::ThrowError("Cipher is not initialized.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (!IsValidGCMTagLength(len))
    return Nan::ThrowRangeError("Invalid tag length.");

  const int mode = EVP_CIPHER_CTX_mode(cipher->ctx);

  if (mode != EVP_CIPH_GCM_MODE)
    return Nan::ThrowError("Cipher is not authenticated.");

  if (cipher->encrypt)
    return Nan::ThrowError("Cannot set auth tag when encrypting.");

  int r = EVP_CIPHER_CTX_ctrl(cipher->ctx,
                              BCRYPTO_AEAD_SET_TAG,
                              len,
                              (unsigned char *)data);

  if (r != 1)
    return Nan::ThrowTypeError("Could not get auth tag.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BCipherBase::HasCipher) {
  if (info.Length() < 1)
    return Nan::ThrowError("cipher.hasCipher() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String name_(info[0]);
  const char *name = (const char *)*name_;
  bool result = EVP_get_cipherbyname(name) != NULL;

  if (!result && strcasecmp(name, "AES-256-CBC") == 0)
    return Nan::ThrowError("Algorithms not loaded for Cipher.");

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
