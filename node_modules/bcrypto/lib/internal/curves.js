/*!
 * curves.js - elliptic curve definitions
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const curves = {
  P192: {
    id: 'P192',
    type: 'short',
    ossl: 'prime192v1',
    oid: '2a8648ce3d030101',
    bits: 192,
    size: 24,
    order: 'ffffffffffffffffffffffff99def836146bc9b1b4d22831',
    half: '7fffffffffffffffffffffffccef7c1b0a35e4d8da691418'
  },
  P224: {
    id: 'P224',
    type: 'short',
    oid: '2b81040021',
    ossl: 'secp224r1',
    bits: 224,
    size: 28,
    order: 'ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
    half: '7fffffffffffffffffffffffffff8b51705c781f09ee94a2ae2e151e'
  },
  P256: {
    id: 'P256',
    type: 'short',
    ossl: 'prime256v1',
    oid: '2a8648ce3d030107',
    bits: 256,
    size: 32,
    order: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    half: '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8'
  },
  P384: {
    id: 'P384',
    type: 'short',
    ossl: 'secp384r1',
    oid: '2b81040022',
    bits: 384,
    size: 48,
    order: ''
      + 'ffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'c7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    half: ''
      + '7fffffffffffffffffffffffffffffffffffffffffffffff'
      + 'e3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9'
  },
  P521: {
    id: 'P521',
    type: 'short',
    ossl: 'secp521r1',
    oid: '2b81040023',
    bits: 521,
    size: 66,
    order: ''
      + '01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'a51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409',
    half: ''
      + '00fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      + 'd28c343c1df97cb35bfe600a47b84d2e81ddae4dc44ce23d75db7db8f489c3204'
  },
  SECP256K1: {
    id: 'SECP256K1',
    type: 'short',
    ossl: 'secp256k1',
    oid: '2b8104000a',
    bits: 256,
    size: 32,
    order: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    half: '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0'
  }
};

/*
 * Expose
 */

module.exports = curves;
