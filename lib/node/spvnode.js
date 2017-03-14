/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var Lock = require('../utils/lock');
var Node = require('./node');
var Chain = require('../blockchain/chain');
var Pool = require('../net/pool');
var HTTPServer = require('../http/server');
var RPC = require('../http/rpc');

/**
 * Create an spv node which only maintains
 * a chain, a pool, and an http server.
 * @alias module:node.SPVNode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @param {Buffer?} options.sslKey
 * @param {Buffer?} options.sslCert
 * @param {Number?} options.httpPort
 * @param {String?} options.httpHost
 * @property {Boolean} loaded
 * @property {Chain} chain
 * @property {Pool} pool
 * @property {HTTPServer} http
 * @emits SPVNode#block
 * @emits SPVNode#tx
 * @emits SPVNode#error
 */

function SPVNode(options) {
  if (!(this instanceof SPVNode))
    return new SPVNode(options);

  Node.call(this, options);

  // SPV flag.
  this.spv = true;

  this.chain = new Chain({
    network: this.network,
    logger: this.logger,
    db: this.config.str('db'),
    prefix: this.config.prefix,
    maxFiles: this.config.num('max-files'),
    cacheSize: this.config.mb('cache-size'),
    forceWitness: this.config.bool('force-witness'),
    checkpoints: this.config.bool('checkpoints'),
    spv: true
  });

  this.pool = new Pool({
    network: this.network,
    logger: this.logger,
    chain: this.chain,
    prefix: this.config.prefix,
    proxy: this.config.str('proxy'),
    onion: this.config.bool('onion'),
    upnp: this.config.bool('upnp'),
    seeds: this.config.array('seeds'),
    nodes: this.config.array('nodes'),
    bip151: this.config.bool('bip151'),
    bip150: this.config.bool('bip150'),
    identityKey: this.config.buf('identity-key'),
    maxOutbound: this.config.num('max-outbound'),
    persistent: this.config.bool('persistent'),
    selfish: true,
    listen: false
  });

  this.rpc = new RPC(this);

  if (!HTTPServer.unsupported) {
    this.http = new HTTPServer({
      network: this.network,
      logger: this.logger,
      node: this,
      prefix: this.config.prefix,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('host'),
      port: this.config.num('port'),
      apiKey: this.config.str('api-key'),
      noAuth: this.config.bool('no-auth')
    });
  }

  this.rescanJob = null;
  this.scanLock = new Lock();
  this.watchLock = new Lock();

  this._init();
}

util.inherits(SPVNode, Node);

/**
 * Initialize the node.
 * @private
 */

SPVNode.prototype._init = function _init() {
  var self = this;
  var onError = this.error.bind(this);

  // Bind to errors
  this.chain.on('error', onError);
  this.pool.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  this.pool.on('tx', function(tx) {
    if (self.rescanJob)
      return;

    self.emit('tx', tx);
  });

  this.chain.on('block', function(block) {
    self.emit('block', block);
  });

  this.chain.on('connect', co(function* (entry, block) {
    if (self.rescanJob) {
      try {
        yield self.watchBlock(entry, block);
      } catch (e) {
        self.error(e);
      }
      return;
    }

    self.emit('connect', entry, block);
  }));

  this.chain.on('disconnect', function(entry, block) {
    self.emit('disconnect', entry);
  });

  this.chain.on('reset', function(tip) {
    self.emit('reset', tip);
  });

  this.loadPlugins();
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias SPVNode#open
 * @returns {Promise}
 */

SPVNode.prototype._open = co(function* open(callback) {
  yield this.chain.open();
  yield this.pool.open();

  yield this.openPlugins();

  if (this.http)
    yield this.http.open();

  this.logger.info('Node is loaded.');
});

/**
 * Close the node, wait for the database to close.
 * @alias SPVNode#close
 * @returns {Promise}
 */

SPVNode.prototype._close = co(function* close() {
  if (this.http)
    yield this.http.close();

  yield this.closePlugins();

  yield this.pool.close();
  yield this.chain.close();
});

/**
 * Scan for any missed transactions.
 * Note that this will replay the blockchain sync.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

SPVNode.prototype.scan = co(function* scan(start, filter, iter) {
  var unlock = yield this.scanLock.lock();
  var height = this.chain.height;

  try {
    yield this.chain.replay(start);

    if (this.chain.height < height) {
      // We need to somehow defer this.
      // yield this.connect();
      // this.startSync();
      // yield this.watchUntil(height, iter);
    }
  } finally {
    unlock();
  }
});

/**
 * Watch the blockchain until a certain height.
 * @param {Number} height
 * @param {Function} iter
 * @returns {Promise}
 */

SPVNode.prototype.watchUntil = function watchUntil(height, iter) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.rescanJob = new RescanJob(resolve, reject, height, iter);
  });
};

/**
 * Handled watched block.
 * @param {ChainEntry} entry
 * @param {MerkleBlock} block
 * @returns {Promise}
 */

SPVNode.prototype.watchBlock = co(function* watchBlock(entry, block) {
  var unlock = yield this.watchLock.lock();
  try {
    if (entry.height < this.rescanJob.height) {
      yield this.rescanJob.iter(entry, block.txs);
      return;
    }
    this.rescanJob.resolve();
    this.rescanJob = null;
  } catch (e) {
    this.rescanJob.reject(e);
    this.rescanJob = null;
  } finally {
    unlock();
  }
});

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @returns {Promise}
 */

SPVNode.prototype.broadcast = co(function* broadcast(item) {
  try {
    yield this.pool.broadcast(item);
  } catch (e) {
    this.emit('error', e);
  }
});

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX} tx
 * @returns {Promise}
 */

SPVNode.prototype.sendTX = function sendTX(tx) {
  return this.broadcast(tx);
};

/**
 * Broadcast a transaction. Silence errors.
 * @param {TX} tx
 * @returns {Promise}
 */

SPVNode.prototype.relay = function relay(tx) {
  return this.broadcast(tx);
};

/**
 * Connect to the network.
 * @returns {Promise}
 */

SPVNode.prototype.connect = function connect() {
  return this.pool.connect();
};

/**
 * Disconnect from the network.
 * @returns {Promise}
 */

SPVNode.prototype.disconnect = function disconnect() {
  return this.pool.disconnect();
};

/**
 * Start the blockchain sync.
 */

SPVNode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

/**
 * Stop syncing the blockchain.
 */

SPVNode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

/*
 * Helpers
 */

function RescanJob(resolve, reject, height, iter) {
  this.resolve = resolve;
  this.reject = reject;
  this.height = height;
  this.iter = iter;
}

/*
 * Expose
 */

module.exports = SPVNode;
