#ifndef _BCRYPTO_HASH_HH
#define _BCRYPTO_HASH_HH
#include <node.h>
#include <nan.h>
#include <torsion/hash.h>

class BHash : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BHash();
  ~BHash();

  int type;
  hash_t ctx;
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
