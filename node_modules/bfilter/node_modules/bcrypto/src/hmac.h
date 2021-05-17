#ifndef _BCRYPTO_HMAC_HH
#define _BCRYPTO_HMAC_HH
#include <node.h>
#include <nan.h>
#include <torsion/hash.h>

class BHMAC : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BHMAC();
  ~BHMAC();

  int type;
  hmac_t ctx;
  bool started;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
  static NAN_METHOD(Digest);
};
#endif
