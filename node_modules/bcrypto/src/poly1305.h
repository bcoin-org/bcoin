#ifndef _BCRYPTO_POLY1305_HH
#define _BCRYPTO_POLY1305_HH
#include <node.h>
#include <nan.h>
#include <torsion/poly1305.h>

class BPoly1305 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BPoly1305();
  ~BPoly1305();

  poly1305_t ctx;
  bool started;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Destroy);
  static NAN_METHOD(Verify);
};
#endif
