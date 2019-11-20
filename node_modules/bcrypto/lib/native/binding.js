/*!
 * bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const binding = require('loady')('bcrypto', __dirname);

const parts = process.version.split(/[^\d]/);
const major = parts[1] >>> 0;
const minor = parts[2] >>> 0;
const patch = parts[3] >>> 0;

if (major !== binding.major
    || minor !== binding.minor
    || Math.abs(patch - binding.patch) > 5) {
  const expect = [
    binding.major,
    binding.minor,
    binding.patch
  ].join('.');

  console.error('WARNING: Bcrypto built for node.js v%s, not %s!',
                expect, process.version);
}

let loaded = false;

binding.load = function load() {
  if (!loaded && major < 10) {
    require('crypto');
    loaded = true;
  }
};

module.exports = binding;
