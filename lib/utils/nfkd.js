/*!
 * nfkd.js - unicode normalization for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var unorm;

/**
 * Normalize unicode string.
 * @alias module:utils.nfkd
 * @param {String} str
 * @returns {String}
 */

function nfkd(str) {
  if (str.normalize)
    return str.normalize('NFKD');

  if (!unorm)
    unorm = require('../../vendor/unorm');

  return unorm.nfkd(str);
}

/*
 * Expose
 */

module.exports = nfkd;
