/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var AsyncObject = require('./async');
var utils = require('./utils');

/**
 * Base class from which every other
 * Node-like object inherits.
 * @exports Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  AsyncObject.call(this);

  options = this._parseOptions(options);

  this.options = options;
  this.network = bcoin.network.get(options.network);
  this.prefix = options.prefix;

  this.logger = options.logger;
  this.db = options.db;
  this.mempool = null;
  this.pool = null;
  this.chain = null;
  this.fees = null;
  this.miner = null;
  this.walletdb = null;
  this.wallet = null;

  this._bound = [];

  if (!this.logger) {
    this.logger = new bcoin.logger({
      level: options.logLevel || 'none',
      console: options.logConsole,
      file: options.logFile
    });
  }

  this.__init();
}

utils.inherits(Node, AsyncObject);

/**
 * Initialize node.
 * @private
 */

Node.prototype.__init = function __init() {
  var self = this;
  this.on('preopen', function() {
    self._onOpen();
  });
  this.on('close', function() {
    self._onClose();
  });
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype._onOpen = function _onOpen() {
  var self = this;

  this.logger.open();

  this._bind(bcoin.time, 'offset', function(offset) {
    self.logger.info('Time offset: %d (%d minutes).', offset, offset / 60 | 0);
  });

  this._bind(bcoin.time, 'sample', function(sample, total) {
    self.logger.debug('Added time data: samples=%d, offset=%d (%d minutes).',
      total, sample, sample / 60 | 0);
  });

  this._bind(bcoin.time, 'mismatch', function() {
    self.logger.warning('Please make sure your system clock is correct!');
  });

  this._bind(bcoin.workerPool, 'spawn', function(child) {
    self.logger.info('Spawning worker process: %d.', child.id);
  });

  this._bind(bcoin.workerPool, 'exit', function(code, child) {
    self.logger.warning('Worker %d exited: %s.', child.id, code);
  });

  this._bind(bcoin.workerPool, 'error', function(err, child) {
    if (child) {
      self.logger.error('Worker %d error: %s', child.id, err.message);
      return;
    }
    self.emit('error', err);
  });
};

/**
 * Close node. Unbind all events.
 * @private
 */

Node.prototype._onClose = function _onClose() {
  var i, bound;

  this.logger.close();

  for (i = 0; i < this._bound.length; i++) {
    bound = this._bound[i];
    bound[0].removeListener(bound[1], bound[2]);
  }

  this._bound.length = 0;
};

/**
 * Bind to an event on `obj`, save listener for removal.
 * @private
 * @param {EventEmitter} obj
 * @param {String} event
 * @param {Function} listener
 */

Node.prototype._bind = function _bind(obj, event, listener) {
  this._bound.push([obj, event, listener]);
  obj.on(event, listener);
};

/**
 * Emit and log an error.
 * @private
 * @param {Error} err
 */

Node.prototype._error = function _error(err) {
  this.logger.error(err);
  this.emit('error', err);
};

/**
 * Parse options object.
 * @private
 * @param {Object} options
 * @returns {Object}
 */

Node.prototype._parseOptions = function _parseOptions(options) {
  if (!options)
    options = {};

  options = utils.merge({}, options);

  options.network = bcoin.network.get(options.network);

  if (process.env.BCOIN_PREFIX != null)
    options.prefix = process.env.BCOIN_PREFIX;

  if (process.env.BCOIN_DB != null)
    options.db = process.env.BCOIN_DB;

  if (process.env.BCOIN_LOGLEVEL != null)
    options.logLevel = process.env.BCOIN_LOGLEVEL;

  if (process.env.BCOIN_LOGFILE != null) {
    if (process.env.BCOIN_LOGFILE === '0'
        || process.env.BCOIN_LOGFILE === '1') {
      options.logFile = +process.env.BCOIN_LOGFILE === 1;
    } else {
      options.logFile = process.env.BCOIN_LOGFILE;
    }
  }

  if (process.env.BCOIN_SEED != null)
    options.preferredSeed = process.env.BCOIN_SEED;

  if (process.env.BCOIN_RPCUSER != null)
    options.rpcUser = process.env.BCOIN_RPCUSER;

  if (process.env.BCOIN_RPCPASSWORD != null)
    options.rpcPassword = process.env.BCOIN_RPCPASSWORD;

  if (!options.prefix)
    options.prefix = utils.HOME + '/.bcoin';

  if (!options.db)
    options.db = 'memory';

  options.prefix = utils.normalize(options.prefix);

  if (options.logFile && typeof options.logFile !== 'string') {
    options.logFile = options.prefix;
    if (options.network.type !== 'main')
      options.logFile += '/' + options.network.type;
    options.logFile += '/debug.log';
  }

  options.logFile = options.logFile
    ? utils.normalize(options.logFile)
    : null;

  return options;
};

/**
 * Create a file path from a name
 * as well as the node's prefix.
 * @param {String} name
 * @returns {String}
 */

Node.prototype.location = function location(name) {
  var path = this.prefix;
  if (this.network.type !== 'main')
    path += '/' + this.network.type;
  path += '/' + name;
  return path;
};

/*
 * Expose
 */

module.exports = Node;
