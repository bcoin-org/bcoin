/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const cleanse = require('./binding').cleanse;

cleanse.native = 2;

/*
 * Expose
 */

module.exports = cleanse;
