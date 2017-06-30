/*!
 * layout-browser.js - mempooldb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const layout = {
  binary: false,
  R: 'R',
  V: 'V',
  F: 'F',
  e: function e(hash) {
    return 'e' + hex(hash);
  },
  ee: function ee(key) {
    return key.slice(1, 65);
  }
};

/*
 * Helpers
 */

function hex(hash) {
  if (typeof hash !== 'string')
    hash = hash.toString('hex');
  return hash;
}

/*
 * Expose
 */

module.exports = layout;
