/*!
 * workers/index.js - workers for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module workers
 */

exports.Framer = require('./framer');
exports.jobs = require('./jobs');
// exports.Master = require('./master');
exports.packets = require('./packets');
exports.ParserClient = require('./parser-client');
exports.Parser = require('./parser');
// exports.worker = require('./worker');
exports.WorkerPool = require('./workerpool');
