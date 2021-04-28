/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const backend = require('./binding').util;
const cleanse = backend.cleanse;

cleanse.native = 2;

/*
 * Expose
 */

module.exports = cleanse;
