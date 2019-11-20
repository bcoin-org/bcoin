#ifndef _BCRYPTO_BLAKE2S_HH
#define _BCRYPTO_BLAKE2S_HH
#include <node.h>
#include <nan.h>
#include "blake2s/blake2s.h"

class BBLAKE2s : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BBLAKE2s();
  ~BBLAKE2s();

  bcrypto_blake2s_ctx ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Multi);
};
#endif
