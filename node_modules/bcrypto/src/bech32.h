#ifndef _BCRYPTO_BECH32_HH
#define _BCRYPTO_BECH32_HH
#include <node.h>
#include <nan.h>

class BBech32 {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(Serialize);
  static NAN_METHOD(Deserialize);
  static NAN_METHOD(Is);
  static NAN_METHOD(ConvertBits);
  static NAN_METHOD(Encode);
  static NAN_METHOD(Decode);
  static NAN_METHOD(Test);
};

#endif
