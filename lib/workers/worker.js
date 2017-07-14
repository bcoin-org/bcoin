/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Master = require('./master');
const util = require('../utils/util');
const server = new Master();

util.log = server.log.bind(server);
util.error = util.log;

server.listen();
