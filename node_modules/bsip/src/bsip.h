#ifndef _BSIP_BSIP_H
#define _BSIP_BSIP_H

#include <node.h>
#include <nan.h>

NAN_METHOD(siphash);
NAN_METHOD(siphash32);
NAN_METHOD(siphash64);
NAN_METHOD(siphash32k256);
NAN_METHOD(siphash64k256);
NAN_METHOD(sipmod);

#endif
