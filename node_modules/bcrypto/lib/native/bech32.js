/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Bech32
 */

class BECH32 {
  constructor(checksum) {
    assert((checksum >>> 0) === checksum);
    this.checksum = checksum;
    this.native = 2;
  }

  serialize(hrp, data) {
    assert(typeof hrp === 'string');
    assert(Buffer.isBuffer(data));

    return binding.bech32_serialize(hrp, data, this.checksum);
  }

  deserialize(str) {
    assert(typeof str === 'string');
    return binding.bech32_deserialize(str, this.checksum);
  }

  is(str) {
    assert(typeof str === 'string');
    return binding.bech32_is(str, this.checksum);
  }

  convertBits(data, srcbits, dstbits, pad) {
    assert(Buffer.isBuffer(data));
    assert((srcbits >>> 0) === srcbits);
    assert((dstbits >>> 0) === dstbits);
    assert(typeof pad === 'boolean');

    return binding.bech32_convert_bits(data, srcbits, dstbits, pad);
  }

  encode(hrp, version, hash) {
    assert(typeof hrp === 'string');
    assert((version >>> 0) === version);
    assert(Buffer.isBuffer(hash));

    return binding.bech32_encode(hrp, version, hash, this.checksum);
  }

  decode(addr) {
    assert(typeof addr === 'string');
    return binding.bech32_decode(addr, this.checksum);
  }

  test(addr) {
    assert(typeof addr === 'string');
    return binding.bech32_test(addr, this.checksum);
  }
}

/*
 * Expose
 */

module.exports = BECH32;
