#ifndef _BCRYPTO_SALSA20_HH
#define _BCRYPTO_SALSA20_HH

#include <node.h>
#include <nan.h>
#include <torsion/salsa20.h>

class BSalsa20 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BSalsa20();
  ~BSalsa20();

  salsa20_t ctx;
  bool started;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Destroy);
  static NAN_METHOD(Derive);
};
#endif
