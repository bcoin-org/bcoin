/*!
 * layout-browser.js - mempooldb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');

const layout = {
  binary: false,
  R: 'R',
  V: 'V',
  F: 'F',
  e: function e(hash) {
    return 'e' + hex(hash);
  },
  ee: function ee(key) {
    assert(typeof key === 'string');
    assert(key.length === 65);
    return key.slice(1, 65);
  }
};

/*
 * Helpers
 */

function hex(hash) {
  if (Buffer.isBuffer(hash))
    hash = hash.toString('hex');
  assert(typeof hash === 'string');
  return hash;
}

/*
 * Expose
 */

module.exports = layout;
