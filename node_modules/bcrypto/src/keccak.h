#ifndef _BCRYPTO_KECCAK_HH
#define _BCRYPTO_KECCAK_HH
#include <node.h>
#include <nan.h>
#include <torsion/hash.h>

class BKeccak : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BKeccak();
  ~BKeccak();

  keccak_t ctx;
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
