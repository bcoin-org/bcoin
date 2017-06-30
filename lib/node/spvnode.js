/*!
 * spvnode.js - spv node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const util = require('../utils/util');
const Lock = require('../utils/lock');
const Node = require('./node');
const Chain = require('../blockchain/chain');
const Pool = require('../net/pool');
const HTTPServer = require('../http/server');
const RPC = require('../http/rpc');

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
    entryCache: this.config.num('entry-cache'),
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
    only: this.config.array('only'),
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
      host: this.config.str('http-host'),
      port: this.config.num('http-port'),
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
  // Bind to errors
  this.chain.on('error', err => this.error(err));
  this.pool.on('error', err => this.error(err));

  if (this.http)
    this.http.on('error', err => this.error(err));

  this.pool.on('tx', (tx) => {
    if (this.rescanJob)
      return;

    this.emit('tx', tx);
  });

  this.chain.on('block', (block) => {
    this.emit('block', block);
  });

  this.chain.on('connect', async (entry, block) => {
    if (this.rescanJob) {
      try {
        await this.watchBlock(entry, block);
      } catch (e) {
        this.error(e);
      }
      return;
    }

    this.emit('connect', entry, block);
  });

  this.chain.on('disconnect', (entry, block) => {
    this.emit('disconnect', entry);
  });

  this.chain.on('reset', (tip) => {
    this.emit('reset', tip);
  });

  this.loadPlugins();
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias SPVNode#open
 * @returns {Promise}
 */

SPVNode.prototype._open = async function open(callback) {
  await this.chain.open();
  await this.pool.open();

  await this.openPlugins();

  if (this.http)
    await this.http.open();

  this.logger.info('Node is loaded.');
};

/**
 * Close the node, wait for the database to close.
 * @alias SPVNode#close
 * @returns {Promise}
 */

SPVNode.prototype._close = async function close() {
  if (this.http)
    await this.http.close();

  await this.closePlugins();

  await this.pool.close();
  await this.chain.close();
};

/**
 * Scan for any missed transactions.
 * Note that this will replay the blockchain sync.
 * @param {Number|Hash} start - Start block.
 * @param {Bloom} filter
 * @param {Function} iter - Iterator.
 * @returns {Promise}
 */

SPVNode.prototype.scan = async function scan(start, filter, iter) {
  let unlock = await this.scanLock.lock();
  let height = this.chain.height;

  try {
    await this.chain.replay(start);

    if (this.chain.height < height) {
      // We need to somehow defer this.
      // await this.connect();
      // this.startSync();
      // await this.watchUntil(height, iter);
    }
  } finally {
    unlock();
  }
};

/**
 * Watch the blockchain until a certain height.
 * @param {Number} height
 * @param {Function} iter
 * @returns {Promise}
 */

SPVNode.prototype.watchUntil = function watchUntil(height, iter) {
  return new Promise((resolve, reject) => {
    this.rescanJob = new RescanJob(resolve, reject, height, iter);
  });
};

/**
 * Handled watched block.
 * @param {ChainEntry} entry
 * @param {MerkleBlock} block
 * @returns {Promise}
 */

SPVNode.prototype.watchBlock = async function watchBlock(entry, block) {
  let unlock = await this.watchLock.lock();
  try {
    if (entry.height < this.rescanJob.height) {
      await this.rescanJob.iter(entry, block.txs);
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
};

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @returns {Promise}
 */

SPVNode.prototype.broadcast = async function broadcast(item) {
  try {
    await this.pool.broadcast(item);
  } catch (e) {
    this.emit('error', e);
  }
};

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
