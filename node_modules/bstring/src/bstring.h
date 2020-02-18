#ifndef _BSTRING_BSTRING_H
#define _BSTRING_BSTRING_H

#include <node.h>
#include <nan.h>

NAN_METHOD(base58_encode);
NAN_METHOD(base58_decode);
NAN_METHOD(base58_test);
NAN_METHOD(bech32_encode);
NAN_METHOD(bech32_decode);
NAN_METHOD(bech32_test);
NAN_METHOD(cashaddr_encode);
NAN_METHOD(cashaddr_decode);
NAN_METHOD(cashaddr_test);

#endif
