#ifndef _BCRYPTO_BLAKE2B_HH
#define _BCRYPTO_BLAKE2B_HH
#include <node.h>
#include <nan.h>
#include <torsion/hash.h>

class BBLAKE2b : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BBLAKE2b();
  ~BBLAKE2b();

  blake2b_t ctx;
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
