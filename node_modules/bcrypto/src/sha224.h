#ifndef _BCRYPTO_SHA224_HH
#define _BCRYPTO_SHA224_HH
#include <node.h>
#include <nan.h>
#include "openssl/sha.h"

class BSHA224 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BSHA224();
  ~BSHA224();

  SHA256_CTX ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Multi);
};
#endif
