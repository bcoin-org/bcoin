/*!
 * bstring
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bstring
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const assert = require('bsert');
const binding = require('loady')('bstring', __dirname);

exports.base58 = {
  encode: binding.base58_encode,
  decode: binding.base58_decode,
  test: binding.base58_test
};

exports.bech32 = {
  serialize: binding.bech32_serialize,
  deserialize: binding.bech32_deserialize,
  is: binding.bech32_is,
  convertBits: binding.bech32_convert_bits,
  encode: binding.bech32_encode,
  decode: binding.bech32_decode,
  test: binding.bech32_test
};

exports.cashaddr = {
  encode(prefix, type, hash) {
    assert((type & 0x0f) === type, 'Invalid cashaddr type.');
    return binding.cashaddr_encode(prefix, type, hash);
  },
  decode(str, defaultPrefix = 'bitcoincash') {
    return binding.cashaddr_decode(str, defaultPrefix);
  },
  test(str, defaultPrefix = 'bitcoincash') {
    return binding.cashaddr_test(str, defaultPrefix);
  }
};
