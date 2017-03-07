/*!
 * foonode.js - foo node for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var co = require('../utils/co');
var Node = require('./node');
// var Chain = require('../blockchain/chain');
// var Fees = require('../mempool/fees');
// var Mempool = require('../mempool/mempool');
var Pool = require('../net/pool');
// var Miner = require('../mining/miner');
// var WalletDB = require('../wallet/walletdb');
var HTTPServer = require('../http/server');

/**
 * Respresents a foonode only usefull for pool connection
 * @alias module:node.FooNode
 * @extends Node
 * @constructor
 * @param {Object?} options
 * @property {Chain} chain
 * @property {PolicyEstimator} fees
 * @property {Mempool} mempool
 * @property {Pool} pool
 * @property {Miner} miner
 * @property {WalletDB} walletdb
 * @property {HTTPServer} http
 * @emits FullNode#block
 * @emits FullNode#tx
 * @emits FullNode#connect
 * @emits FullNode#disconnect
 * @emits FullNode#reset
 * @emits FullNode#error
 */

function FooNode(options) {
  if (!(this instanceof FooNode))
    return new FooNode(options);

  Node.call(this, options);

  // Instantiate blockchain.
  // this.chain = new Chain({
  //   network: this.network,
  //   logger: this.logger,
  //   db: this.options.db,
  //   location: this.location('chain'),
  //   maxFiles: this.options.maxFiles,
  //   cacheSize: this.options.cacheSize,
  //   forceWitness: this.options.forceWitness,
  //   prune: this.options.prune,
  //   checkpoints: this.options.checkpoints,
  //   coinCache: this.options.coinCache,
  //   indexTX: this.options.indexTX,
  //   indexAddress: this.options.indexAddress
  // });

  // Fee estimation.
  // this.fees = new Fees(this.logger);
  // this.fees.init();

  // Mempool needs access to the chain.
  // this.mempool = new Mempool({
  //   network: this.network,
  //   logger: this.logger,
  //   chain: this.chain,
  //   fees: this.fees,
  //   db: this.options.db,
  //   location: this.location('mempool'),
  //   persistent: this.options.persistentMempool,
  //   maxSize: this.options.mempoolSize,
  //   limitFree: this.options.limitFree,
  //   limitFreeRelay: this.options.limitFreeRelay,
  //   requireStandard: this.options.requireStandard,
  //   rejectInsaneFees: this.options.rejectInsaneFees,
  //   replaceByFee: this.options.replaceByFee,
  //   indexAddress: this.options.indexAddress
  // });

  // Pool needs access to the chain and mempool.
  this.pool = new Pool({
    network: this.network,
    logger: this.logger,
    // chain: this.chain,
    // mempool: this.mempool,
    selfish: this.options.selfish,
    compact: this.options.compact,
    bip37: this.options.bip37,
    bip151: this.options.bip151,
    bip150: this.options.bip150,
    authPeers: this.options.authPeers,
    knownPeers: this.options.knownPeers,
    identityKey: this.options.identityKey,
    maxOutbound: this.options.maxOutbound,
    maxInbound: this.options.maxInbound,
    proxy: this.options.proxy,
    onion: this.options.onion,
    seeds: this.options.seeds,
    nodes: this.options.nodes,
    publicHost: this.options.publicHost,
    publicPort: this.options.publicPort,
    host: this.options.host,
    port: this.options.port,
    listen: this.options.listen
  });

  // Miner needs access to the chain and mempool.
  // this.miner = new Miner({
  //   network: this.network,
  //   logger: this.logger,
  //   chain: this.chain,
  //   mempool: this.mempool,
  //   fees: this.fees,
  //   address: this.options.payoutAddress,
  //   coinbaseFlags: this.options.coinbaseFlags,
  //   maxWeight: this.options.maxBlockWeight,
  //   reservedWeight: this.options.reservedBlockWeight,
  //   reservedSigops: this.options.reservedBlockSigops
  // });

  // Wallet database needs access to fees.
  // this.walletdb = new WalletDB({
  //   network: this.network,
  //   logger: this.logger,
  //   client: this.client,
  //   db: this.options.db,
  //   location: this.location('walletdb'),
  //   maxFiles: this.options.walletMaxFiles,
  //   cacheSize: this.options.walletCacheSize,
  //   witness: false,
  //   checkpoints: this.options.checkpoints,
  //   startHeight: this.options.startHeight,
  //   wipeNoReally: this.options.wipeNoReally,
  //   verify: false
  // });

  // HTTP needs access to the node.
  if (!HTTPServer.unsupported) {
    this.http = new HTTPServer({
      network: this.network,
      logger: this.logger,
      node: this,
      key: this.options.sslKey,
      cert: this.options.sslCert,
      port: this.options.httpPort,
      host: this.options.httpHost,
      apiKey: this.options.apiKey,
      serviceKey: this.options.serviceKey,
      walletAuth: this.options.walletAuth,
      noAuth: this.options.noAuth
    });
  }

  this._init();
}

util.inherits(FooNode, Node);

/**
 * Initialize the node.
 * @private
 */

FooNode.prototype._init = function _init() {
  var self = this;
  var onError = this.error.bind(this);

  // Bind to errors
  // this.chain.on('error', onError);
  // this.mempool.on('error', onError);
  this.pool.on('error', onError);
  // this.miner.on('error', onError);
  // this.walletdb.on('error', onError);

  if (this.http)
    this.http.on('error', onError);

  // this.mempool.on('tx', function(tx) {
  //   self.miner.notifyEntry();
  //   self.emit('tx', tx);
  // });

  // this.chain.hook('connect', co(function* (entry, block) {
  //   try {
  //     yield self.mempool._addBlock(entry, block.txs);
  //   } catch (e) {
  //     self.error(e);
  //   }
  //   self.emit('block', block);
  //   self.emit('connect', entry, block);
  // }));

  // this.chain.hook('disconnect', co(function* (entry, block) {
  //   try {
  //     yield self.mempool._removeBlock(entry, block.txs);
  //   } catch (e) {
  //     self.error(e);
  //   }
  //   self.emit('disconnect', entry, block);
  // }));

  // this.chain.hook('reset', co(function* (tip) {
  //   try {
  //     yield self.mempool._reset();
  //   } catch (e) {
  //     self.error(e);
  //   }
  //   self.emit('reset', tip);
  // }));
};

/**
 * Open the node and all its child objects,
 * wait for the database to load.
 * @alias FooNode#open
 * @returns {Promise}
 */

FooNode.prototype._open = co(function* open() {
  // yield this.chain.open();
  // yield this.mempool.open();
  // yield this.miner.open();
  yield this.pool.open();
  // yield this.walletdb.open();

  // Ensure primary wallet.
  // yield this.openWallet();

  if (this.http)
    yield this.http.open();

  this.logger.info('Node is loaded.');
});

/**
 * Close the node, wait for the database to close.
 * @alias FooNode#close
 * @returns {Promise}
 */

FooNode.prototype._close = co(function* close() {
  if (this.http)
    yield this.http.close();

  // yield this.wallet.destroy();

  // this.wallet = null;

  // yield this.walletdb.close();
  yield this.pool.close();
  // yield this.miner.close();
  // yield this.mempool.close();
  // yield this.chain.close();

  this.logger.info('Node is closed.');
});

/**
 * Broadcast a transaction (note that this will _not_ be verified
 * by the mempool - use with care, lest you get banned from
 * bitcoind nodes).
 * @param {TX|Block} item
 * @returns {Promise}
 */

FooNode.prototype.broadcast = co(function* broadcast(item) {
  try {
    yield this.pool.broadcast(item);
  } catch (e) {
    this.emit('error', e);
  }
});

/**
 * Add transaction to mempool, broadcast. Silence errors.
 * @param {TX} tx
 * @returns {Promise}
 */

FooNode.prototype.relay = co(function* relay(tx) {
  try {
    yield this.sendTX(tx);
  } catch (e) {
    this.error(e);
  }
});

/**
 * Connect to the network.
 * @returns {Promise}
 */

FooNode.prototype.connect = function connect() {
  return this.pool.connect();
};

/**
 * Disconnect from the network.
 * @returns {Promise}
 */

FooNode.prototype.disconnect = function disconnect() {
  return this.pool.disconnect();
};

/**
 * Start the blockchain sync.
 */

FooNode.prototype.startSync = function startSync() {
  return this.pool.startSync();
};

/**
 * Stop syncing the blockchain.
 */

FooNode.prototype.stopSync = function stopSync() {
  return this.pool.stopSync();
};

/*
 * Expose
 */

module.exports = FooNode;
