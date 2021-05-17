#ifndef _BCRYPTO_BLAKE2S_HH
#define _BCRYPTO_BLAKE2S_HH
#include <node.h>
#include <nan.h>
#include <torsion/hash.h>

class BBLAKE2s : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BBLAKE2s();
  ~BBLAKE2s();

  blake2s_t ctx;
  bool started;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
  static NAN_METHOD(Root);
  static NAN_METHOD(Multi);
};
#endif
