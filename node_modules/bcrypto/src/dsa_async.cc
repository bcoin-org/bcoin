#include <assert.h>
#include <node.h>
#include <nan.h>
#include <torsion/dsa.h>
#include <torsion/util.h>

#include "common.h"
#include "dsa_async.h"

BDSAWorker::BDSAWorker (
  uint32_t bits,
  uint8_t seed[32],
  Nan::Callback *callback
) : Nan::AsyncWorker(callback, "bcrypto:dsa_params_generate")
  , bits(bits)
  , params(NULL)
  , params_len(0)
{
  Nan::HandleScope scope;
  memcpy(entropy, seed, 32);
}

BDSAWorker::~BDSAWorker() {
  if (params != NULL) {
    free(params);
    params = NULL;
    params_len = 0;
  }
}

void
BDSAWorker::Execute() {
  params = (uint8_t *)malloc(DSA_MAX_PARAMS_SIZE);
  params_len = DSA_MAX_PARAMS_SIZE;

  if (params == NULL) {
    SetErrorMessage("Could not generate params.");
    return;
  }

  if (!dsa_params_generate(params, &params_len, bits, entropy)) {
    SetErrorMessage("Could not generate params.");
    return;
  }

  params = (uint8_t *)realloc(params, params_len);

  if (params == NULL)
    SetErrorMessage("Could not generate params.");
}

void
BDSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  assert(params != NULL);
  assert(params_len != 0);

  v8::Local<v8::Value> argv[] = {
    Nan::Null(),
    Nan::NewBuffer((char *)params, params_len).ToLocalChecked()
  };

  params = NULL;
  params_len = 0;

  callback->Call(2, argv, async_resource);
}
