/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const binding = require('./binding');

/*
 * Cleanse
 */

function cleanse(data) {
  assert(Buffer.isBuffer(data));
  binding.cleanse(data);
}

/*
 * Static
 */

cleanse.native = 2;

/*
 * Expose
 */

module.exports = cleanse;
