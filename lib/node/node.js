/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/async');
var util = require('../utils/util');
var co = require('../utils/co');
var Network = require('../protocol/network');
var Logger = require('./logger');
var NodeClient = require('./nodeclient');
var workerPool = require('../workers/workerpool').pool;
var ec = require('../crypto/ec');
var native = require('../utils/native');

/**
 * Base class from which every other
 * Node-like object inherits.
 * @alias module:node.Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  AsyncObject.call(this);

  this.options = {};
  this.network = Network.primary;
  this.prefix = util.HOME + '/.bcoin';
  this.startTime = -1;
  this.bound = [];

  this.logger = new Logger();
  this.chain = null;
  this.fees = null;
  this.mempool = null;
  this.pool = null;
  this.miner = null;
  this.walletdb = null;
  this.wallet = null;
  this.http = null;
  this.client = null;

  this.init(options);
}

util.inherits(Node, AsyncObject);

/**
 * Initialize options.
 * @private
 * @param {Object} options
 */

Node.prototype.initOptions = function initOptions(options) {
  if (!options)
    return;

  assert(typeof options === 'object');

  this.options = options;

  if (options.network != null) {
    this.network = Network.get(options.network);
    if (this.network !== Network.main)
      this.prefix += '/' + this.network.type;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = util.normalize(options.prefix);
  }

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.logFile != null) {
    if (typeof options.logFile === 'string') {
      this.logger.setFile(options.logFile);
    } else {
      assert(typeof options.logFile === 'boolean');
      if (options.logFile)
        this.logger.setFile(this.location('debug.log'));
    }
  }

  if (options.logLevel != null) {
    assert(typeof options.logLevel === 'string');
    this.logger.setLevel(options.logLevel);
  }

  if (options.logConsole != null) {
    assert(typeof options.logConsole === 'boolean');
    this.logger.console = options.logConsole;
  }
};

/**
 * Initialize node.
 * @private
 * @param {Object} options
 */

Node.prototype.init = function init(options) {
  var self = this;

  this.initOptions(options);

  // Local client for walletdb
  this.client = new NodeClient(this);

  this.on('preopen', function() {
    self.handlePreopen();
  });

  this.on('open', function() {
    self.handleOpen();
  });

  this.on('close', function() {
    self.handleClose();
  });
};

/**
 * Open node. Bind all events.
 * @private
 */

Node.prototype.handlePreopen = function handlePreopen() {
  var self = this;

  this.logger.open();

  this.bind(this.network.time, 'offset', function(offset) {
    self.logger.info('Time offset: %d (%d minutes).', offset, offset / 60 | 0);
  });

  this.bind(this.network.time, 'sample', function(sample, total) {
    self.logger.debug(
      'Added time data: samples=%d, offset=%d (%d minutes).',
      total, sample, sample / 60 | 0);
  });

  this.bind(this.network.time, 'mismatch', function() {
    self.logger.warning('Adjusted time mismatch!');
    self.logger.warning('Please make sure your system clock is correct!');
  });

  this.bind(workerPool, 'spawn', function(child) {
    self.logger.info('Spawning worker process: %d.', child.id);
  });

  this.bind(workerPool, 'exit', function(code, child) {
    self.logger.warning('Worker %d exited: %s.', child.id, code);
  });

  this.bind(workerPool, 'error', function(err, child) {
    if (child) {
      self.logger.error('Worker %d error: %s', child.id, err.message);
      return;
    }
    self.emit('error', err);
  });
};

/**
 * Open node.
 * @private
 */

Node.prototype.handleOpen = function handleOpen() {
  this.startTime = util.now();

  if (!ec.binding) {
    this.logger.warning('Warning: secp256k1-node was not built.');
    this.logger.warning('Verification will be slow.');
  }

  if (!native.binding) {
    this.logger.warning('Warning: bcoin-native was not built.');
    this.logger.warning('Hashing will be slow.');
  }

  if (!workerPool.enabled) {
    this.logger.warning('Warning: worker pool is disabled.');
    this.logger.warning('Verification will be slow.');
  }
};

/**
 * Close node. Unbind all events.
 * @private
 */

Node.prototype.handleClose = function handleClose() {
  var i, bound;

  this.startTime = -1;

  this.logger.close();

  for (i = 0; i < this.bound.length; i++) {
    bound = this.bound[i];
    bound[0].removeListener(bound[1], bound[2]);
  }

  this.bound.length = 0;
};

/**
 * Bind to an event on `obj`, save listener for removal.
 * @private
 * @param {EventEmitter} obj
 * @param {String} event
 * @param {Function} listener
 */

Node.prototype.bind = function bind(obj, event, listener) {
  this.bound.push([obj, event, listener]);
  obj.on(event, listener);
};

/**
 * Emit and log an error.
 * @private
 * @param {Error} err
 */

Node.prototype.error = function error(err) {
  if (!err)
    return;

  if (err.type === 'VerifyError') {
    switch (err.reason) {
      case 'insufficient priority':
      case 'non-final':
        this.logger.spam(err.message);
        break;
      default:
        this.logger.error(err.message);
        break;
    }
  } else if (typeof err.code === 'string' && err.code[0] === 'E') {
    this.logger.error(err.message);
  } else {
    this.logger.error(err);
  }

  this.emit('error', err);
};

/**
 * Create a file path from a name
 * as well as the node's prefix.
 * @param {String} name
 * @returns {String}
 */

Node.prototype.location = function location(name) {
  return this.prefix + '/' + name;
};

/**
 * Get node uptime in seconds.
 * @returns {Number}
 */

Node.prototype.uptime = function uptime() {
  if (this.startTime === -1)
    return 0;

  return util.now() - this.startTime;
};

/**
 * Open and ensure primary wallet.
 * @returns {Promise}
 */

Node.prototype.openWallet = co(function* openWallet() {
  var options, wallet;

  assert(!this.wallet);

  options = {
    id: 'primary',
    passphrase: this.options.passphrase
  };

  wallet = yield this.walletdb.ensure(options);

  this.logger.info(
    'Loaded wallet with id=%s wid=%d address=%s',
    wallet.id, wallet.wid, wallet.getAddress());

  if (this.miner)
    this.miner.addAddress(wallet.getAddress());

  this.wallet = wallet;
});

/*
 * Expose
 */

module.exports = Node;
