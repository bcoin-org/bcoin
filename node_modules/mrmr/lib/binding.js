/*!
 * mrmr
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/mrmr
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const binding = require('loady')('mrmr', __dirname);

exports.murmur3 = {
  sum: binding.murmur3_sum,
  tweak: binding.murmur3_tweak
};
