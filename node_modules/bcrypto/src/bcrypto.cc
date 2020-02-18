/**
 * bcrypto.cc - fast native bindings to crypto functions.
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License)
 */

#include <node.h>
#include <nan.h>

#include "common.h"
#include "aead.h"
#include "base58.h"
#include "bech32.h"
#include "blake2b.h"
#include "blake2s.h"
#include "cash32.h"
#include "chacha20.h"
#include "dsa.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "hash.h"
#include "hmac.h"
#include "keccak.h"
#include "murmur3.h"
#include "poly1305.h"
#include "pbkdf2.h"
#include "rsa.h"
#include "salsa20.h"
#include "scrypt.h"
#ifdef BCRYPTO_USE_SECP256K1
#include "secp256k1.h"
#endif
#include "siphash.h"
#include "util.h"

NAN_MODULE_INIT(init) {
  BAEAD::Init(target);
  BBase58::Init(target);
  BBech32::Init(target);
  BBLAKE2b::Init(target);
  BBLAKE2s::Init(target);
  BCash32::Init(target);
  BChaCha20::Init(target);
  BDSA::Init(target);
  BECDH::Init(target);
  BECDSA::Init(target);
  BEDDSA::Init(target);
  BHash::Init(target);
  BHMAC::Init(target);
  BKeccak::Init(target);
  BMurmur3::Init(target);
  BPoly1305::Init(target);
  BPBKDF2::Init(target);
  BRSA::Init(target);
  BSalsa20::Init(target);
  BScrypt::Init(target);
#ifdef BCRYPTO_USE_SECP256K1
  BSecp256k1::Init(target);
#endif
  BSiphash::Init(target);
  BUtil::Init(target);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(bcrypto, init)
#else
NODE_MODULE(bcrypto, init)
#endif
