#ifndef _BCRYPTO_COMMON_HH
#define _BCRYPTO_COMMON_HH
#include <node.h>
#include <nan.h>

#define COPY_BUFFER(d, l) \
  (Nan::CopyBuffer((char *)(d), (l)).ToLocalChecked())

#define NEW_BUFFER(d, l) \
  (Nan::NewBuffer((char *)(d), (l)).ToLocalChecked())

NAN_INLINE static bool
IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}

#endif
