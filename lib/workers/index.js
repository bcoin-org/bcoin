'use strict';

/**
 * @module workers
 */

exports.jobs = require('./jobs');
exports.Framer = require('./framer');
exports.Parser = require('./parser');
exports.Worker = require('./workerpool').Worker;
exports.WorkerPool = require('./workerpool').WorkerPool;
