/*!
 * common.js - commonly required functions for wallet.
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var common = exports;

/**
 * Test whether a string is eligible
 * to be used as a name or ID.
 * @param {String} key
 * @returns {Boolean}
 */

common.isName = function isName(key) {
  if (typeof key !== 'string')
    return false;

  if (!/^[\-\._0-9A-Za-z]+$/.test(key))
    return false;

  return key.length >= 1 && key.length <= 40;
};
