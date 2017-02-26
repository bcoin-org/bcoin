/*!
 * layout-browser.js - mempooldb layout for browser.
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var pad32 = util.pad32;

var layout = {
  R: 'R',
  e: function e(id, hash) {
    return 'e' + pad32(id) + hex(hash);
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
