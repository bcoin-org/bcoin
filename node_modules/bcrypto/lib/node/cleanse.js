/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const crypto = require('crypto');

/**
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

function cleanse(data) {
  crypto.randomFillSync(data, 0, data.length);
}

cleanse.native = 1;

/*
 * Expose
 */

module.exports = cleanse;
