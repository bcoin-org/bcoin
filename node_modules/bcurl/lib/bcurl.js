/*!
 * bcurl.js - simple http client
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcurl
 */

'use strict';

const Client = require('./client');

exports.Client = Client;
exports.client = options => new Client(options);
