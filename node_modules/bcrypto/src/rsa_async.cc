#include <assert.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
#include "common.h"
#include "rsa/rsa.h"
#include "rsa_async.h"

BRSAWorker::BRSAWorker (
  int bits,
  unsigned long long exp,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , bits(bits)
  , exp(exp)
  , key(NULL)
{
  Nan::HandleScope scope;
}

BRSAWorker::~BRSAWorker() {}

void
BRSAWorker::Execute() {
  key = bcrypto_rsa_privkey_generate(bits, exp);

  if (key == NULL)
    SetErrorMessage("Could not generate key.");
}

void
BRSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  bcrypto_rsa_key_t *k = key;
  assert(k);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  callback->Call(2, argv, async_resource);
}
#endif
