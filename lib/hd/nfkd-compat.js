/*!
 * nfkd-compat.js - unicode normalization for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const unorm = require('./unorm');

function nfkd(str) {
  if (str.normalize)
    return str.normalize('NFKD');

  return unorm.nfkd(str);
}

/*
 * Expose
 */

module.exports = nfkd;
