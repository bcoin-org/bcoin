#ifndef _BCRYPTO_CIPHER_HH
#define _BCRYPTO_CIPHER_HH

#include <node.h>
#include <nan.h>

#include "openssl/evp.h"

class BCipherBase : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BCipherBase();
  ~BCipherBase();

  const EVP_CIPHER *type;
  bool encrypt;
  EVP_CIPHER_CTX *ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(SetAAD);
  static NAN_METHOD(GetAuthTag);
  static NAN_METHOD(SetAuthTag);
  static NAN_METHOD(HasCipher);
};
#endif
