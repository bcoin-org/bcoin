/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('../internal/assert');
const random = require('../random');

/**
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

function cleanse(data) {
  assert(Buffer.isBuffer(data));
  random.randomFill(data, 0, data.length);
}

/*
 * Static
 */

cleanse.native = 0;

/*
 * Expose
 */

module.exports = cleanse;
