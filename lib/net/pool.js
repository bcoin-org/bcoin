/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var AsyncObject = require('../utils/async');
var util = require('../utils/util');
var IP = require('../utils/ip');
var co = require('../utils/co');
var constants = require('../protocol/constants');
var errors = require('../btc/errors');
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;
var NetworkAddress = require('../primitives/netaddress');
var Address = require('../primitives/address');
var BIP150 = require('./bip150');
var Bloom = require('../utils/bloom');
var ec = require('../crypto/ec');
var InvItem = require('../primitives/invitem');
var Locker = require('../utils/locker');
var Network = require('../protocol/network');
var Peer = require('./peer');
var TX = require('../primitives/tx');
var tcp = require('./tcp');
var request = require('../http/request');

/**
 * A pool of peers for handling all network activity.
 * @exports Pool
 * @constructor
 * @param {Object} options
 * @param {Chain} options.chain
 * @param {Mempool?} options.mempool
 * @param {Number?} [options.maxOutbound=8] - Maximum number of peers.
 * @param {Boolean?} options.spv - Do an SPV sync.
 * @param {Boolean?} options.relay - Whether to ask
 * for relayed transactions.
 * @param {Boolean?} options.headers - Whether
 * to use `getheaders` for sync.
 * @param {Number?} [options.feeRate] - Fee filter rate.
 * @param {Number?} [options.loadTimeout=120000] - Sync timeout before
 * finding a new loader peer.
 * @param {Number?} [options.requestTimeout=120000] - Timeout for in-flight
 * blocks.
 * @param {Number?} [options.invTimeout=60000] - Timeout for broadcasted
 * objects.
 * @param {Boolean?} options.listen - Whether to spin up a server socket
 * and listen for peers.
 * @param {Boolean?} options.selfish - A selfish pool. Will not serve blocks,
 * headers, hashes, utxos, or transactions to peers.
 * @param {Boolean?} options.broadcast - Whether to automatically broadcast
 * transactions accepted to our mempool.
 * @param {Boolean?} options.witness - Request witness blocks and transactions.
 * Only deal with witness peers.
 * @param {Boolean} options.ignoreDiscovery - Automatically discover new
 * peers.
 * @param {String[]} options.seeds
 * @param {Function?} options.createSocket - Custom function to create a socket.
 * Must accept (port, host) and return a node-like socket.
 * @param {Function?} options.createServer - Custom function to create a server.
 * Must return a node-like server.
 * @emits Pool#block
 * @emits Pool#block
 * @emits Pool#tx
 * @emits Pool#peer
 * @emits Pool#open
 * @emits Pool#close
 * @emits Pool#error
 * @emits Pool#fork
 * @emits Pool#invalid
 * @emits Pool#exists
 * @emits Pool#orphan
 * @emits Pool#full
 * @emits Pool#blocks
 * @emits Pool#txs
 * @emits Pool#chain-progress
 * @emits Pool#alert
 * @emits Pool#reject
 * @emits Pool#addr
 * @emits Pool#version
 * @emits Pool#ack
 * @emits Pool#watched
 * @emits Pool#leech
 */

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  AsyncObject.call(this);

  assert(options && options.chain, 'Pool requires a blockchain.');

  this.options = options;
  this.chain = options.chain;
  this.logger = options.logger || this.chain.logger;
  this.mempool = options.mempool;
  this.network = this.chain.network;

  this.services = constants.LOCAL_SERVICES;
  this.port = this.network.port;

  this.server = null;
  this.maxOutbound = 8;
  this.maxInbound = 8;
  this.connected = false;
  this.uid = 0;
  this.createServer = null;
  this.locker = new Locker();
  this.proxyServer = null;
  this.auth = null;
  this.identityKey = null;

  this.syncing = false;

  this.loadTimeout = 120000;

  this.feeRate = -1;

  this.address = new NetworkAddress();

  this.peers = new PeerList(this);
  this.hosts = new HostList(this);

  this.blockType = constants.inv.BLOCK;
  this.txType = constants.inv.TX;

  this.localNonce = util.nonce();

  this.spvFilter = null;
  this.txFilter = null;

  // Requested objects.
  this.requestMap = {};
  this.requestTimeout = 2 * 60000;
  this.activeRequest = 0;
  this.activeBlocks = 0;
  this.activeTX = 0;

  // Currently broadcasted objects.
  this.invMap = {};
  this.invItems = [];
  this.invTimeout = 60000;

  this.scheduled = false;
  this.pendingWatch = null;
  this.timeout = null;
  this.interval = null;

  this._initOptions();
  this._init();
};

util.inherits(Pool, AsyncObject);

/**
 * Initialize options.
 * @private
 */

Pool.prototype._initOptions = function _initOptions() {
  if (this.options.relay == null)
    this.options.relay = !this.options.spv;

  if (this.options.headers == null)
    this.options.headers = this.options.spv;

  if (!this.options.witness)
    this.services &= ~constants.services.WITNESS;

  if (this.options.port != null)
    this.port = this.options.port;

  this.address.ts = util.now();
  this.address.services = this.services;
  this.address.setPort(this.port);

  if (this.options.maxOutbound != null)
    this.maxOutbound = this.options.maxOutbound;

  if (this.options.maxInbound != null)
    this.maxInbound = this.options.maxInbound;

  this.createServer = this.options.createServer;
  this.proxyServer = this.options.proxyServer;

  if (this.options.bip150) {
    this.options.bip151 = true;
    this.auth = new BIP150.AuthDB();

    if (this.options.authPeers)
      this.auth.setAuthorized(this.options.authPeers);

    if (this.options.knownPeers)
      this.auth.setKnown(this.options.knownPeers);

    this.identityKey = this.options.identityKey || ec.generatePrivateKey();

    assert(Buffer.isBuffer(this.identityKey), 'Identity key must be a buffer.');
    assert(ec.privateKeyVerify(this.identityKey),
      'Invalid identity key.');
  }

  if (this.options.loadTimeout != null)
    this.loadTimeout = this.options.loadTimeout;

  if (this.options.feeRate != null)
    this.feeRate = this.options.feeRate;

  if (this.options.seeds)
    this.hosts.setSeeds(this.options.seeds);

  if (this.options.preferredSeed)
    this.hosts.addSeed(this.options.preferredSeed);

  if (this.options.witness) {
    this.blockType |= constants.WITNESS_MASK;
    this.txType |= constants.WITNESS_MASK;
  }

  // Note: No witness bit for merkleblocks.
  if (this.options.spv)
    this.blockType = constants.inv.FILTERED_BLOCK;

  if (this.options.spv)
    this.spvFilter = Bloom.fromRate(10000, 0.001, constants.bloom.ALL);

  if (!this.options.mempool)
    this.txFilter = new Bloom.Rolling(50000, 0.000001);

  if (this.options.requestTimeout != null)
    this.requestTimeout = this.options.requestTimeout;

  if (this.options.invTimeout != null)
    this.invTimeout = this.options.invTimeout;
};

/**
 * Initialize the pool.
 * @private
 */

Pool.prototype._init = function _init() {
  var self = this;

  this.chain.on('block', function(block, entry) {
    self.emit('block', block, entry);
  });

  this.chain.on('competitor', function(block, entry) {
    self.emit('competitor', block, entry);
  });

  this.chain.on('fork', function(block, height, expected) {
    self.emit('fork', block, height, expected);
  });

  this.chain.on('invalid', function(block, height) {
    self.emit('invalid', block, height);
  });

  this.chain.on('exists', function(block, height) {
    self.emit('exists', block, height);
  });

  this.chain.on('orphan', function(block, height) {
    self.emit('orphan', block, height);
  });

  this.chain.on('reset', function() {
    self.forceSync();
  });

  this.chain.on('full', function() {
    self.stopTimeout();
    self.stopInterval();
    self.sync();
    self.emit('full');
    self.logger.info('Chain is fully synced (height=%d).', self.chain.height);
  });
};

/**
 * Open the pool, wait for the chain to load.
 * @alias Pool#open
 * @returns {Promise}
 */

Pool.prototype._open = co(function* _open() {
  var ip, key;

  try {
    ip = yield this.getIP();
  } catch (e) {
    this.logger.error(e);
  }

  if (ip) {
    this.address.setHost(ip);
    this.logger.info('External IP found: %s.', ip);
  }

  if (this.mempool)
    yield this.mempool.open();
  else
    yield this.chain.open();

  this.logger.info('Pool loaded (maxpeers=%d).', this.maxOutbound);

  if (this.identityKey) {
    key = ec.publicKeyCreate(this.identityKey, true);
    this.logger.info('Identity public key: %s.', key.toString('hex'));
    this.logger.info('Identity address: %s.', BIP150.address(key));
  }
});

/**
 * Close and destroy the pool.
 * @alias Pool#close
 * @returns {Promise}
 */

Pool.prototype._close = co(function* close() {
  var i, items, hashes, hash;

  this.stopSync();

  items = this.invItems.slice();

  for (i = 0; i < items.length; i++)
    items[i].finish();

  hashes = Object.keys(this.requestMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    this.requestMap[hash].finish(new Error('Pool closed.'));
  }

  this.peers.destroy();

  this.stopInterval();
  this.stopTimeout();

  if (this.pendingWatch != null) {
    clearTimeout(this.pendingWatch);
    this.pendingWatch = null;
  }

  yield this.unlisten();
});

/**
 * Connect to the network.
 */

Pool.prototype.connect = function connect() {
  var self = this;

  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  if (!this.options.selfish && !this.options.spv) {
    if (this.mempool) {
      this.mempool.on('tx', function(tx) {
        self.announce(tx);
      });
    }

    // Normally we would also broadcast
    // competing chains, but we want to
    // avoid getting banned if an evil
    // miner sends us an invalid competing
    // chain that we can't connect and
    // verify yet.
    this.chain.on('block', function(block) {
      if (!self.chain.synced)
        return;
      self.announce(block);
    });
  }

  assert(this.hosts.seeds.length !== 0, 'No seeds available.');

  this.addLoader();

  this.connected = true;
};

/**
 * Start listening on a server socket.
 * @returns {Promise}
 */

Pool.prototype.listen = function listen() {
  var self = this;

  if (this.server)
    return Promise.resolve();

  if (this.createServer) {
    this.server = this.createServer();
  } else {
    if (!tcp.Server)
      return;
    this.server = new tcp.Server();
  }

  this.server.on('connection', function(socket) {
    self._handleLeech(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    self.logger.info(
      'Pool server listening on %s (port=%d).',
      data.address, data.port);
  });

  return new Promise(function(resolve, reject) {
    self.server.listen(self.port, '0.0.0.0', co.wrap(resolve, reject));
  });
};

/**
 * Stop listening on server socket.
 * @returns {Promise}
 */

Pool.prototype.unlisten = function unlisten() {
  var self = this;

  if (util.isBrowser)
    return Promise.resolve();

  if (!this.server)
    return Promise.resolve();

  return new Promise(function(resolve, reject) {
    self.server.close(co.wrap(resolve, reject));
    self.server = null;
  });
};

/**
 * Handle incoming connection.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype._handleLeech = function _handleLeech(socket) {
  var addr;

  if (!socket.remoteAddress) {
    this.logger.debug('Ignoring disconnected leech.');
    socket.destroy();
    return;
  }

  addr = NetworkAddress.fromSocket(socket, this.network);

  if (this.peers.inbound.length >= this.maxInbound) {
    this.logger.debug('Ignoring leech: too many inbound (%s).', addr.hostname);
    socket.destroy();
    return;
  }

  if (this.hosts.isMisbehaving(addr)) {
    this.logger.debug('Ignoring misbehaving leech (%s).', addr.hostname);
    socket.destroy();
    return;
  }

  if (this.hosts.isIgnored(addr)) {
    this.logger.debug('Ignoring leech (%s).', addr.hostname);
    socket.destroy();
    return;
  }

  // Some kind of weird port collision
  // between inbound ports and outbound ports.
  if (this.peers.get(addr)) {
    this.logger.debug('Port collision (%s).', addr.hostname);
    socket.destroy();
    return;
  }

  this.addLeech(addr, socket);
};

/**
 * Start timeout to detect stalling.
 * @private
 */

Pool.prototype.startTimeout = function startTimeout() {
  var self = this;

  function destroy() {
    if (!self.syncing)
      return;

    if (self.chain.synced)
      return;

    if (self.peers.load) {
      self.peers.load.destroy();
      self.logger.debug('Timer ran out. Finding new loader peer.');
    }
  }

  this.stopTimeout();

  this.timeout = setTimeout(destroy, this.loadTimeout);
};

/**
 * Stop the stall timeout (done on chain sync).
 * @private
 */

Pool.prototype.stopTimeout = function stopTimeout() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/**
 * Start the stall interval (shorter than the
 * stall timeout, inteded to give warnings and
 * reset the stall *timeout* if the chain is
 * busy). Stopped on chain sync.
 * @private
 */

Pool.prototype.startInterval = function startInterval() {
  var self = this;

  function load() {
    var peer = self.peers.load;
    var hostname = peer ? peer.hostname : null;

    if (!self.syncing)
      return;

    if (self.chain.synced)
      return self.stopInterval();

    if (self.chain.isBusy())
      return self.startTimeout();

    self.logger.warning('Loader peer is stalling (%s).', hostname);
  }

  this.stopInterval();

  this.interval = setInterval(load, this.loadTimeout / 6 | 0);
};

/**
 * Stop the stall interval.
 * @private
 */

Pool.prototype.stopInterval = function stopInterval() {
  if (this.interval != null) {
    clearInterval(this.interval);
    this.interval = null;
  }
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.addLoader = function addLoader() {
  var self = this;
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.load) {
    this.fillPeers();
    return;
  }

  addr = this.getLoaderHost();
  peer = this.peers.get(addr);

  if (peer) {
    this.setLoader(peer);
    return;
  }

  if (this.syncing) {
    this.startTimeout();
    this.startInterval();
  }

  peer = this.createPeer(addr);

  this.logger.info('Added loader peer (%s).', peer.hostname);

  this.peers.addLoader(peer);
  this.fillPeers();

  util.nextTick(function() {
    self.emit('loader', peer);
  });
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.setLoader = function setLoader(peer) {
  var self = this;

  if (!this.loaded)
    return;

  if (this.syncing) {
    this.startTimeout();
    this.startInterval();
  }

  this.logger.info('Repurposing peer for loader (%s).', peer.hostname);
  this.peers.repurpose(peer);
  this.fillPeers();

  peer.trySync();

  util.nextTick(function() {
    self.emit('loader', peer);
  });
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  this.syncing = true;

  this.startInterval();
  this.startTimeout();

  this.connect();

  if (!this.peers.load) {
    this.addLoader();
    return;
  }

  this.sync();
};

/**
 * Send a sync to each peer.
 * @private
 */

Pool.prototype.sync = function sync() {
  var i;

  if (this.peers.load)
    this.peers.load.trySync();

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].trySync();
};

/**
 * Force sending a sync to each peer.
 * @private
 */

Pool.prototype.forceSync = function forceSync() {
  var i, peer;

  if (this.peers.load) {
    this.peers.load.syncSent = false;
    this.peers.load.trySync();
  }

  for (i = 0; i < this.peers.outbound.length; i++) {
    peer = this.peers.outbound[i];
    peer.syncSent = false;
    peer.trySync();
  }
};

/**
 * Stop the blockchain sync.
 */

Pool.prototype.stopSync = function stopSync() {
  var i;

  if (!this.syncing)
    return;

  this.syncing = false;

  if (!this.loaded)
    return;

  this.stopInterval();
  this.stopTimeout();

  if (this.peers.load)
    this.peers.load.syncSent = false;

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].syncSent = false;
};

/**
 * Handle `headers` packet from a given peer.
 * @private
 * @param {Headers[]} headers
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype._handleHeaders = co(function* _handleHeaders(headers, peer) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__handleHeaders(headers, peer);
  } finally {
    unlock();
  }
});

/**
 * Handle `headers` packet from
 * a given peer without a lock.
 * @private
 * @param {Headers[]} headers
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.__handleHeaders = co(function* _handleHeaders(headers, peer) {
  var i, now, ret, header, hash, last;

  if (!this.options.headers)
    return;

  now = this.network.now();
  ret = new VerifyResult();

  this.logger.debug(
    'Received %s headers from peer (%s).',
    headers.length,
    peer.hostname);

  this.emit('headers', headers);

  if (peer.isLoader()) {
    // Reset interval to avoid stall behavior.
    this.startInterval();
    // Reset timeout to avoid killing the loader.
    this.startTimeout();
  }

  for (i = 0; i < headers.length; i++) {
    header = headers[i];
    hash = header.hash('hex');

    if (last && header.prevBlock !== last) {
      peer.setMisbehavior(100);
      throw new Error('Bad header chain.');
    }

    if (!header.verify(now, ret)) {
      peer.reject(header, 'invalid', ret.reason, 100);
      throw new Error('Invalid header.');
    }

    last = hash;

    yield this.getBlock(peer, hash);
  }

  // Schedule the getdata's we just added.
  this.scheduleRequests(peer);

  // Restart the getheaders process
  // Technically `last` is not indexed yet so
  // the locator hashes will not be entirely
  // accurate. However, it shouldn't matter
  // that much since FindForkInGlobalIndex
  // simply tries to find the latest block in
  // the peer's chain.
  if (last && headers.length === 2000)
    yield peer.getHeaders(last);
});

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype._handleBlocks = co(function* _handleBlocks(hashes, peer) {
  var i, hash, exists;

  assert(!this.options.headers);

  this.logger.debug(
    'Received %s block hashes from peer (%s).',
    hashes.length,
    peer.hostname);

  this.emit('blocks', hashes);

  if (peer.isLoader()) {
    // Reset interval to avoid stall behavior.
    this.startInterval();
    // Reset timeout to avoid killing the loader.
    this.startTimeout();
  }

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    // Resolve orphan chain.
    if (this.chain.hasOrphan(hash)) {
      // There is a possible race condition here.
      // The orphan may get resolved by the time
      // we create the locator. In that case, we
      // should probably actually move to the
      // `exists` clause below if it is the last
      // hash.
      this.logger.debug('Received known orphan hash (%s).', peer.hostname);
      yield peer.resolveOrphan(null, hash);
      continue;
    }

    exists = yield this.getBlock(peer, hash);

    // Normally we request the hashContinue.
    // In the odd case where we already have
    // it, we can do one of two things: either
    // force re-downloading of the block to
    // continue the sync, or do a getblocks
    // from the last hash (this will reset
    // the hashContinue on the remote node).
    if (exists && i === hashes.length - 1) {
      // Make sure we _actually_ have this block.
      if (!this.requestMap[hash]) {
        this.logger.debug('Received existing hash (%s).', peer.hostname);
        yield peer.getBlocks(hash, null);
        continue;
      }
      // Otherwise, we're still requesting it. Ignore.
      this.logger.debug('Received requested hash (%s).', peer.hostname);
    }
  }

  this.scheduleRequests(peer);
});

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * Potentially request headers if headers mode is enabled.
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype._handleInv = co(function* _handleInv(hashes, peer) {
  var unlock = yield this.locker.lock();
  try {
    return yield this.__handleInv(hashes, peer);
  } finally {
    unlock();
  }
});

/**
 * Handle `inv` packet from peer without a lock.
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.__handleInv = co(function* _handleInv(hashes, peer) {
  var i, hash;

  // Ignore for now if we're still syncing
  if (!this.chain.synced && !peer.isLoader())
    return;

  if (this.options.witness && !peer.version.hasWitness())
    return;

  if (!this.options.headers) {
    yield this._handleBlocks(hashes, peer);
    return;
  }

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    yield peer.getHeaders(null, hash);
  }

  this.scheduleRequests(peer);
});

/**
 * Handle `block` packet. Attempt to add to chain.
 * @private
 * @param {MemBlock|MerkleBlock} block
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype._handleBlock = co(function* _handleBlock(block, peer) {
  var requested;

  // Fulfill the load request.
  requested = this.fulfill(block);

  // Someone is sending us blocks without
  // us requesting them.
  if (!requested) {
    peer.invFilter.add(block.hash());
    this.logger.warning(
      'Received unrequested block: %s (%s).',
      block.rhash, peer.hostname);
    return yield co.wait();
  }

  try {
    yield this.chain.add(block);
  } catch (err) {
    if (err.type !== 'VerifyError') {
      this.scheduleRequests(peer);
      throw err;
    }

    if (err.score !== -1)
      peer.reject(block, err.code, err.reason, err.score);

    if (err.reason === 'bad-prevblk') {
      if (this.options.headers) {
        peer.setMisbehavior(10);
        throw err;
      }
      this.logger.debug('Peer sent an orphan block. Resolving.');
      yield peer.resolveOrphan(null, block.hash('hex'));
      this.scheduleRequests(peer);
      throw err;
    }

    this.scheduleRequests(peer);
    throw err;
  }

  this.scheduleRequests(peer);

  this.emit('chain-progress', this.chain.getProgress(), peer);

  if (this.logger.level >= 4 && this.chain.total % 20 === 0) {
    this.logger.debug('Status:'
      + ' ts=%s height=%d highest=%d progress=%s'
      + ' blocks=%d orphans=%d active=%d'
      + ' queue=%d target=%s peers=%d'
      + ' pending=%d jobs=%d',
      util.date(block.ts),
      this.chain.height,
      this.chain.bestHeight,
      (this.chain.getProgress() * 100).toFixed(2) + '%',
      this.chain.total,
      this.chain.orphan.count,
      this.activeBlocks,
      peer.queueBlock.length,
      block.bits,
      this.peers.all.length,
      this.chain.locker.pending.length,
      this.chain.locker.jobs.length);
  }

  if (this.chain.total % 2000 === 0) {
    this.logger.info(
      'Received 2000 more blocks (height=%d, hash=%s).',
      this.chain.height,
      block.rhash);
  }
});

/**
 * Send `mempool` to all peers.
 */

Pool.prototype.sendMempool = function sendMempool() {
  var i;

  if (this.peers.load)
    this.peers.load.sendMempool();

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].sendMempool();
};

/**
 * Send `alert` to all peers.
 * @param {AlertPacket} alert
 */

Pool.prototype.sendAlert = function sendAlert(alert) {
  var i;

  if (this.peers.load)
    this.peers.load.sendAlert(alert);

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].sendAlert(alert);

  for (i = 0; i < this.peers.inbound.length; i++)
    this.peers.inbound[i].sendAlert(alert);
};

/**
 * Create a base peer with no special purpose.
 * @private
 * @param {Object} options
 * @returns {Peer}
 */

Pool.prototype.createPeer = function createPeer(addr, socket) {
  var self = this;
  var peer = new Peer(this, addr, socket);

  peer.once('open', function() {
    if (!peer.outbound)
      return;

    // Attempt to promote from pending->outbound
    self.peers.promote(peer);

    // If we don't have an ack'd loader yet, use this peer.
    if (!self.peers.load || !self.peers.load.ack)
      self.setLoader(peer);
  });

  peer.once('close', function() {
    if (!self.loaded) {
      self.removePeer(peer);
      return;
    }

    if (!peer.isLoader()) {
      self.removePeer(peer);
      self.fillPeers();
      return;
    }

    self.removePeer(peer);
    self.stopInterval();
    self.stopTimeout();

    if (self.peers.size() === 0) {
      self.logger.warning('%s %s %s',
        'Could not connect to any peers.',
        'Do you have a network connection?',
        'Retrying in 5 seconds.');
      setTimeout(function() {
        self.addLoader();
      }, 5000);
      return;
    }

    self.addLoader();
  });

  peer.on('merkleblock', co(function* (block) {
    if (!self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    try {
      yield self._handleBlock(block, peer);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    if (peer.isLoader()) {
      self.startInterval();
      self.startTimeout();
    }
  }));

  peer.on('block', co(function* (block) {
    if (self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    try {
      yield self._handleBlock(block, peer);
    } catch (e) {
      self.emit('error', e);
      return;
    }

    if (peer.isLoader()) {
      self.startInterval();
      self.startTimeout();
    }
  }));

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('reject', function(payload) {
    var data, code;

    if (payload.data)
      data = util.revHex(payload.data);

    code = constants.rejectByVal[payload.code];

    if (code)
      code = code.toLowerCase();

    self.logger.warning(
      'Received reject (%s): msg=%s code=%s reason=%s data=%s.',
      peer.hostname,
      payload.message,
      code || payload.code,
      payload.reason,
      data || null);

    self.emit('reject', payload, peer);
  });

  peer.on('notfound', function(items) {
    var i, item, req;

    for (i = 0; i < items.length; i++) {
      item = items[i];
      req = self.requestMap[item.hash];
      if (req && req.peer === peer)
        req.finish(new Error('Not found.'));
    }
  });

  peer.on('tx', co(function* (tx) {
    try {
      yield self._handleTX(tx, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('addr', function(addrs) {
    var i, addr;

    if (self.options.ignoreDiscovery)
      return;

    for (i = 0; i < addrs.length; i++) {
      addr = addrs[i];

      if (!addr.hasNetwork())
        continue;

      if (self.options.spv) {
        if (!addr.hasBloom())
          continue;
      }

      if (self.options.witness) {
        if (!addr.hasWitness())
          continue;
      }

      if (self.hosts.add(addr))
        self.emit('host', addr, peer);
    }

    self.emit('addr', addrs, peer);
    self.fillPeers();
  });

  peer.on('txs', co(function* (txs) {
    var i, hash;

    self.emit('txs', txs, peer);

    if (self.syncing && !self.chain.synced)
      return;

    for (i = 0; i < txs.length; i++) {
      hash = txs[i];
      try {
        yield self.getTX(peer, hash);
      } catch (e) {
        self.emit('error', e);
      }
    }
  }));

  peer.on('version', function(version) {
    self.logger.info(
      'Received version (%s): version=%d height=%d services=%s agent=%s',
      peer.hostname,
      version.version,
      version.height,
      version.services.toString(2),
      version.agent);

    self.network.time.add(peer.hostname, version.ts);

    self.emit('version', version, peer);
  });

  peer.on('headers', co(function* (headers) {
    if (!self.syncing)
      return;

    try {
      yield self._handleHeaders(headers, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('blocks', co(function* (hashes) {
    if (!self.syncing)
      return;

    try {
      yield self._handleInv(hashes, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  return peer;
};

/**
 * Handle an alert packet.
 * @private
 * @param {AlertPacket} alert
 * @param {Peer} peer
 */

Pool.prototype._handleAlert = function _handleAlert(alert, peer) {
  var now = this.network.now();

  if (!alert.verify(this.network.alertKey)) {
    this.logger.warning('Peer sent a phony alert packet (%s).', peer.hostname);
    // Let's look at it because why not?
    this.logger.debug(alert);
    peer.setMisbehavior(100);
    return;
  }

  if (now >= alert.expiration) {
    this.logger.warning(
      'Peer sent an expired alert packet (%s).',
      peer.hostname);
    this.logger.debug(alert);
    return;
  }

  if (alert.id === 0x7fffffff) {
    if (!(alert.expiration === 0x7fffffff
        && alert.cancel === 0x7fffffff - 1
        && alert.minVer === 0
        && alert.maxVer === 0x7fffffff
        && alert.subVers.length === 0
        && alert.priority === 0x7fffffff
        && alert.statusBar === 'URGENT: Alert key compromised, upgrade required')) {
      this.logger.warning('Misuse of last alert ID (%s).', peer.hostname);
      this.logger.debug(alert);
      peer.setMisbehavior(100);
      return;
    }
  }

  // Keep alert disabled on main.
  if (this.network === Network.main) {
    // https://github.com/bitcoin/bitcoin/pull/7692#issuecomment-197967429
    this.logger.warning('The Japanese government sent an alert packet.');
    this.logger.warning('Here is their IP: %s.', peer.hostname);
    this.logger.info(alert);
    peer.setMisbehavior(100);
    return;
  }

  this.logger.warning('Received alert from peer (%s).', peer.hostname);
  this.logger.warning(alert);

  if (now < alert.relayUntil)
    this.sendAlert(alert);

  this.emit('alert', alert, peer);
};

/**
 * Test the mempool to see if it
 * contains a recent reject.
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.hasReject = function hasReject(hash) {
  if (!this.mempool)
    return false;
  return this.mempool.hasReject(hash);
};

/**
 * Handle a transaction. Attempt to add to mempool.
 * @private
 * @param {TX} tx
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype._handleTX = co(function* _handleTX(tx, peer) {
  var i, requested, missing;

  // Fulfill the load request.
  requested = this.fulfill(tx);

  if (!requested) {
    peer.invFilter.add(tx.hash());

    if (!this.mempool)
      this.txFilter.add(tx.hash());

    this.logger.warning('Peer sent unrequested tx: %s (%s).',
      tx.rhash, peer.hostname);

    if (this.hasReject(tx.hash())) {
      throw new VerifyError(tx,
        'alreadyknown',
        'txn-already-in-mempool',
        0);
    }
  }

  if (!this.mempool) {
    this.emit('tx', tx, peer);
    return;
  }

  try {
    missing = yield this.mempool.addTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError') {
      if (err.score !== -1)
        peer.reject(tx, err.code, err.reason, err.score);
    }
    throw err;
  }

  if (this.options.requestMissing && missing) {
    for (i = 0; i < missing.length; i++)
      yield this.getTX(peer, missing[i]);
  }

  this.emit('tx', tx, peer);
});

/**
 * Create a leech peer from an existing socket.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype.addLeech = function addLeech(addr, socket) {
  var self = this;
  var peer;

  if (!this.loaded)
    return socket.destroy();

  peer = this.createPeer(addr, socket);

  this.logger.info('Added leech peer (%s).', peer.hostname);

  this.peers.addLeech(peer);

  util.nextTick(function() {
    self.emit('leech', peer);
  });
};

/**
 * Create a outbound non-loader peer. These primarily
 * exist for transaction relaying.
 * @private
 */

Pool.prototype.addPeer = function addPeer() {
  var self = this;
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.isFull())
    return;

  // Hang back if we don't have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this.hosts.getHost();

  if (!addr)
    return;

  peer = this.createPeer(addr);

  this.peers.addPending(peer);

  util.nextTick(function() {
    self.emit('peer', peer);
  });
};

/**
 * Attempt to refill the pool with peers.
 * @private
 */

Pool.prototype.fillPeers = function fillPeers() {
  var i;

  this.logger.debug('Refilling peers (%d/%d).',
    this.peers.all.length - this.peers.inbound.length,
    this.maxOutbound);

  for (i = 0; i < this.maxOutbound - 1; i++)
    this.addPeer();
};

/**
 * Remove a peer from any list. Drop all load requests.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.removePeer = function removePeer(peer) {
  var i, hashes, hash, item;

  if (peer.isLoader() && this.syncing) {
    this.stopTimeout();
    this.stopInterval();
  }

  this.peers.remove(peer);

  hashes = Object.keys(this.requestMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.requestMap[hash];
    if (item.peer === peer)
      item.finish(new Error('Peer closed.'));
  }
};

/**
 * Set the spv filter.
 * @param {Bloom} filter
 * @param {String?} enc
 */

Pool.prototype.setFilter = function setFilter(filter) {
  if (!this.options.spv)
    return;
  this.spvFilter = filter;
  this.updateWatch();
};

/**
 * Watch a an address hash (filterload, SPV-only).
 * @param {Buffer|Hash} data
 * @param {String?} enc
 */

Pool.prototype.watch = function watch(data, enc) {
  if (!this.options.spv)
    return;
  this.spvFilter.add(data, enc);
  this.updateWatch();
};

/**
 * Reset the spv filter (filterload, SPV-only).
 */

Pool.prototype.unwatch = function unwatch() {
  if (!this.options.spv)
    return;
  this.spvFilter.reset();
  this.updateWatch();
};

/**
 * Resend the bloom filter to peers.
 */

Pool.prototype.updateWatch = function updateWatch() {
  var self = this;
  var i;

  if (this.pendingWatch != null)
    return;

  this.pendingWatch = setTimeout(function() {
    self.pendingWatch = null;

    if (self.peers.load)
      self.peers.load.updateWatch();

    for (i = 0; i < self.peers.outbound.length; i++)
      self.peers.outbound[i].updateWatch();
  }, 50);
};

/**
 * Add an address to the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.watchAddress = function watchAddress(address) {
  this.watch(Address.getHash(address));
};

/**
 * Queue a `getdata` request to be sent. Checks existence
 * in the chain before requesting.
 * @param {Peer} peer
 * @param {Hash} hash - Block hash.
 * @returns {Promise}
 */

Pool.prototype.getBlock = co(function* getBlock(peer, hash) {
  var item;

  if (!this.loaded)
    return;

  if (peer.destroyed)
    throw new Error('Peer is already destroyed (getdata).');

  if (yield this.hasBlock(hash))
    return true;

  item = new LoadRequest(this, peer, this.blockType, hash);

  peer.queueBlock.push(item);

  return false;
});

/**
 * Test whether the chain has or has seen an item.
 * @param {Peer} peer
 * @param {InvType} type
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Pool.prototype.hasBlock = co(function* hasBlock(hash) {
  // Check the chain.
  if (yield this.chain.has(hash))
    return true;

  // Check the pending requests.
  if (this.requestMap[hash])
    return true;

  return false;
});

/**
 * Queue a `getdata` request to be sent. Checks existence
 * in the mempool before requesting.
 * @param {Peer} peer
 * @param {Hash} hash - TX hash.
 * @returns {Promise}
 */

Pool.prototype.getTX = co(function* getTX(peer, hash) {
  var self = this;
  var item;

  if (!this.loaded)
    return;

  if (peer.destroyed)
    throw new Error('Peer is already destroyed (getdata).');

  if (this.hasTX(hash))
    return true;

  item = new LoadRequest(this, peer, this.txType, hash);

  if (peer.queueTX.length === 0) {
    util.nextTick(function() {
      self.logger.debug(
        'Requesting %d/%d txs from peer with getdata (%s).',
        peer.queueTX.length,
        self.activeTX,
        peer.hostname);

      peer.getData(peer.queueTX);
      peer.queueTX.length = 0;
    });
  }

  peer.queueTX.push(item.start());

  return false;
});

/**
 * Test whether the mempool has or has seen an item.
 * @param {Peer} peer
 * @param {InvType} type
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Pool.prototype.hasTX = function hasTX(hash) {
  if (!this.mempool) {
    // Check the TX filter if
    // we don't have a mempool.
    if (!this.txFilter.added(hash, 'hex'))
      return true;
  } else {
    // Check the mempool.
    if (this.mempool.has(hash))
      return true;
  }

  // If we recently rejected this item. Ignore.
  if (this.hasReject(hash)) {
    this.logger.spam('Saw known reject of %s.', util.revHex(hash));
    return true;
  }

  // Check the pending requests.
  if (this.requestMap[hash])
    return true;

  return false;
};

/**
 * Schedule next batch of `getdata` requests for peer.
 * @param {Peer} peer
 */

Pool.prototype.scheduleRequests = co(function* scheduleRequests(peer) {
  if (this.scheduled)
    return;

  this.scheduled = true;

  yield this.chain.onDrain();

  this.sendRequests(peer);
  this.scheduled = false;
});

/**
 * Send scheduled requests in the request queues.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.sendRequests = function sendRequests(peer) {
  var i, size, items;

  if (peer.queueBlock.length === 0)
    return;

  if (this.options.spv) {
    if (this.activeBlocks >= 500)
      return;

    items = peer.queueBlock.slice();
    peer.queueBlock.length = 0;
  } else {
    size = this.network.getBatchSize(this.chain.height);

    if (this.activeBlocks >= size)
      return;

    items = peer.queueBlock.slice(0, size);
    peer.queueBlock = peer.queueBlock.slice(size);
  }

  for (i = 0; i < items.length; i++)
    items[i] = items[i].start();

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.activeBlocks,
    peer.hostname);

  peer.getData(items);
};

/**
 * Fulfill a requested block.
 * @param {Hash}
 * @returns {LoadRequest|null}
 */

Pool.prototype.fulfill = function fulfill(data) {
  var hash = data.hash('hex');
  var item = this.requestMap[hash];

  if (!item)
    return false;

  item.finish();

  return item;
};

/**
 * Broadcast a transaction or block.
 * @param {TX|Block|InvItem} msg
 * @returns {Promise}
 * or timeout.
 * @returns {BroadcastItem}
 */

Pool.prototype.broadcast = function broadcast(msg) {
  var hash = msg.hash;
  var item;

  if (msg.toInv)
    hash = msg.toInv().hash;

  item = this.invMap[hash];

  if (item) {
    item.refresh();
    item.announce();
  } else {
    item = new BroadcastItem(this, msg);
    item.start();
    item.announce();
  }

  return new Promise(function(resolve, reject) {
    item.addCallback(co.wrap(resolve, reject));
  });
};

/**
 * Announce an item by sending an inv to all
 * peers. This does not add it to the broadcast
 * queue.
 * @param {TX|Block} tx
 */

Pool.prototype.announce = function announce(msg) {
  var i;

  if (this.peers.load)
    this.peers.load.tryAnnounce(msg);

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].tryAnnounce(msg);
};

/**
 * Set a fee rate filter for all peers.
 * @param {Rate} rate
 */

Pool.prototype.setFeeRate = function setFeeRate(rate) {
  var i;

  this.feeRate = rate;

  if (this.peers.load)
    this.peers.load.sendFeeRate(rate);

  for (i = 0; i < this.peers.outbound.length; i++)
    this.peers.outbound[i].sendFeeRate(rate);
};

/**
 * Allocate a new loader host.
 * @returns {NetworkAddress}
 */

Pool.prototype.getLoaderHost = function getLoaderHost() {
  if (!this.connected && this.options.preferredSeed)
    return this.hosts.seeds[0];

  return this.hosts.getLoaderHost();
};

/**
 * Increase peer's ban score.
 * @param {Peer} peer
 * @param {Number} score
 * @returns {Boolean} Whether the peer was banned.
 */

Pool.prototype.setMisbehavior = function setMisbehavior(peer, score) {
  peer.banScore += score;

  if (peer.banScore >= constants.BAN_SCORE) {
    this.logger.debug('Ban threshold exceeded (%s).', peer.hostname);
    this.ban(peer);
    return true;
  }

  return false;
};

/**
 * Ban a peer.
 * @param {NetworkAddress} addr
 */

Pool.prototype.ban = function ban(addr) {
  var peer = this.peers.get(addr);

  this.logger.debug('Banning peer (%s).', addr.hostname);
  this.hosts.ban(addr);

  if (peer)
    peer.destroy();
};

/**
 * Unban a peer.
 * @param {String|NetworkAddress} addr
 */

Pool.prototype.unban = function unban(addr) {
  this.hosts.unban(addr);
};

/**
 * Test whether the host is banned.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

Pool.prototype.isMisbehaving = function isMisbehaving(addr) {
  return this.hosts.isMisbehaving(addr);
};

/**
 * Ignore peer.
 * @param {Peer} peer
 */

Pool.prototype.ignore = function ignore(addr) {
  var peer = this.peers.get(addr);

  this.logger.debug('Ignoring peer (%s).', addr.hostname);
  this.hosts.ignore(addr);

  if (peer)
    peer.destroy();
};

/**
 * Test whether the host is ignored.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

Pool.prototype.isIgnored = function isIgnored(addr) {
  return this.hosts.isIgnored(addr);
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @returns {Promise}
 */

Pool.prototype.getIP = co(function* getIP() {
  var res, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  try {
    res = yield request.promise({
      method: 'GET',
      uri: 'http://icanhazip.com',
      expect: 'text',
      timeout: 3000
    });
  } catch (e) {
    return yield this.getIP2();
  }

  ip = res.body.trim();

  if (IP.version(ip) === -1)
    return yield this.getIP2();

  return IP.normalize(ip);
});

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @returns {Promise}
 */

Pool.prototype.getIP2 = co(function* getIP2() {
  var res, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  res = yield request.promise({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 3000
  });

  ip = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!ip || IP.version(ip[1]) === -1)
    throw new Error('Could not find IP.');

  return IP.normalize(ip[1]);
});

/**
 * Peer List
 * @constructor
 */

function PeerList(pool) {
  this.pool = pool;
  // Peers that are loading blocks themselves
  this.outbound = [];
  // Peers that are still connecting
  this.pending = [];
  // Peers that connected to us
  this.inbound = [];
  // Peers that are loading block ids
  this.load = null;
  // All peers
  this.all = [];
  // Map of hostnames
  this.map = {};
}

PeerList.prototype.addLoader = function addLoader(peer) {
  this.load = peer;
  this.all.push(peer);
  assert(!this.map[peer.hostname]);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.addPending = function addPending(peer) {
  this.pending.push(peer);
  this.all.push(peer);
  assert(!this.map[peer.hostname]);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.addLeech = function addLeech(peer) {
  this.inbound.push(peer);
  this.all.push(peer);
  assert(!this.map[peer.hostname]);
  this.map[peer.hostname] = peer;
};

PeerList.prototype.promote = function promote(peer) {
  if (util.binaryRemove(this.pending, peer, compare))
    util.binaryInsert(this.outbound, peer, compare);
};

PeerList.prototype.remove = function remove(peer) {
  util.binaryRemove(this.pending, peer, compare);
  util.binaryRemove(this.outbound, peer, compare);
  util.binaryRemove(this.inbound, peer, compare);
  util.binaryRemove(this.all, peer, compare);

  assert(this.map[peer.hostname]);
  delete this.map[peer.hostname];

  if (peer.isLoader()) {
    this.pool.logger.info('Removed loader peer (%s).', peer.hostname);
    this.load = null;
  }
};

PeerList.prototype.demoteLoader = function demoteLoader() {
  var peer = this.load;
  assert(peer);
  this.load = null;
  if (peer.ack)
    util.binaryInsert(this.outbound, peer, compare);
  else
    util.binaryInsert(this.pending, peer, compare);
};

PeerList.prototype.repurpose = function repurpose(peer) {
  var r1, r2;

  assert(peer.outbound);

  if (this.load)
    this.demoteLoader();

  r1 = util.binaryRemove(this.pending, peer, compare);
  r2 = util.binaryRemove(this.outbound, peer, compare);

  assert(r1 || r2);

  this.load = peer;
};

PeerList.prototype.isFull = function isFull() {
  return this.size() >= this.pool.maxOutbound - 1;
};

PeerList.prototype.size = function size() {
  return this.outbound.length + this.pending.length;
};

PeerList.prototype.get = function get(addr) {
  return this.map[addr.hostname];
};

PeerList.prototype.destroy = function destroy() {
  var i, peers;

  if (this.load)
    this.load.destroy();

  peers = this.outbound.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.pending.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();

  peers = this.inbound.slice();

  for (i = 0; i < peers.length; i++)
    peers[i].destroy();
};

/**
 * Host List
 * @constructor
 */

function HostList(pool) {
  this.pool = pool;
  this.seeds = [];
  this.items = [];
  this.map = {};

  // Ignored hosts
  this.ignored = {};

  // Misbehaving hosts
  this.misbehaving = {};

  this.setSeeds(this.pool.network.seeds);
}

/**
 * Clear misbehaving and ignored.
 */

HostList.prototype.clear = function clear() {
  this.ignored = {};
  this.misbehaving = {};
};

/**
 * Allocate a new loader host.
 * @returns {NetworkAddress}
 */

HostList.prototype.getLoaderHost = function getLoaderHost() {
  var addr = this.getRandom(this.seeds);

  if (addr)
    return addr;

  addr = this.getRandom(this.items);

  if (addr)
    return addr;

  this.pool.logger.warning('All seeds banned or ignored. Clearing...');
  this.clear();

  return this.getRandom(this.seeds);
};

/**
 * Allocate a new host which is not currently being used.
 * @returns {NetworkAddress}
 */

HostList.prototype.getHost = function getHost() {
  var addr = this.getRandom(this.seeds, true);

  if (addr)
    return addr;

  return this.getRandom(this.items, true);
};

/**
 * Get a random host from collection of hosts.
 * @param {NetworkAddress[]} hosts
 * @param {Boolean} unique
 * @returns {NetworkAddress}
 */

HostList.prototype.getRandom = function getRandom(hosts, unique) {
  var index = Math.random() * hosts.length | 0;
  var last = -1;
  var i, addr;

  for (i = 0; i < hosts.length; i++) {
    addr = hosts[i];

    if (this.isMisbehaving(addr))
      continue;

    if (this.isIgnored(addr))
      continue;

    if (unique && this.pool.peers.get(addr))
      continue;

    if (i >= index)
      return addr;

    last = i;
  }

  if (last === -1)
    return;

  return hosts[last];
};

/**
 * Add host to host list.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.add = function add(addr) {
  if (this.items.length > 500)
    return;

  if (this.map[addr.hostname])
    return;

  util.binaryInsert(this.items, addr, compare);

  this.map[addr.hostname] = addr;

  return addr;
};

/**
 * Remove host from host list.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.remove = function remove(addr) {
  addr = this.map[addr.hostname];

  if (!addr)
    return;

  util.binaryRemove(this.items, addr, compare);

  delete this.map[addr.hostname];

  return addr;
};

/**
 * Increase peer's ban score.
 * @param {NetworkAddress} addr
 */

HostList.prototype.ban = function ban(addr) {
  this.misbehaving[addr.host] = util.now();
  this.remove(addr);
};

/**
 * Unban host.
 * @param {NetworkAddress} addr
 */

HostList.prototype.unban = function unban(addr) {
  delete this.misbehaving[addr.host];
  delete this.ignored[addr.host];
};

/**
 * Test whether the host is banned.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.isMisbehaving = function isMisbehaving(addr) {
  var time = this.misbehaving[addr.host];

  if (time != null) {
    if (util.now() > time + constants.BAN_TIME) {
      delete this.misbehaving[addr.host];
      return false;
    }
    return true;
  }

  return false;
};

/**
 * Ignore peer.
 * @param {NetworkAddress} addr
 */

HostList.prototype.ignore = function ignore(addr) {
  if (!this.remove(addr))
    this.ignored[addr.host] = true;
};

/**
 * Test whether the host/peer is ignored.
 * @param {NetworkAddress} addr
 * @returns {Boolean}
 */

HostList.prototype.isIgnored = function isIgnored(addr) {
  return this.ignored[addr.host] === true;
};

/**
 * Set initial seeds.
 * @param {String[]} seeds
 */

HostList.prototype.setSeeds = function setSeeds(seeds) {
  var i, hostname, seed;

  this.seeds.length = 0;

  for (i = 0; i < seeds.length; i++) {
    hostname = seeds[i];
    seed = NetworkAddress.fromHostname(hostname, this.pool.network);
    this.seeds.push(seed);
  }
};

/**
 * Add a preferred seed.
 * @param {String} hostname
 */

HostList.prototype.addSeed = function addSeed(hostname) {
  var seed = NetworkAddress.fromHostname(hostname, this.pool.network);
  this.seeds.unshift(seed);
};

/**
 * Represents an in-flight block or transaction.
 * @exports LoadRequest
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {Peer} peer
 * @param {Number} type - `getdata` type (see {@link constants.inv}).
 * @param {Hash} hash
 * @returns {Promise}
 */

function LoadRequest(pool, peer, type, hash) {
  if (!(this instanceof LoadRequest))
    return new LoadRequest(pool, peer, type, hash);

  this.pool = pool;
  this.peer = peer;
  this.type = type;
  this.hash = hash;
  this.active = false;
  this.id = this.pool.uid++;
  this.timeout = null;
  this.onTimeout = this._onTimeout.bind(this);

  assert(!this.pool.requestMap[this.hash]);
  this.pool.requestMap[this.hash] = this;
}

/**
 * Destroy load request with an error.
 */

LoadRequest.prototype.destroy = function destroy() {
  return this.finish();
};

/**
 * Handle timeout. Potentially kill loader.
 * @private
 */

LoadRequest.prototype._onTimeout = function _onTimeout() {
  if (this.type !== this.pool.txType && this.peer.isLoader()) {
    this.pool.logger.debug(
      'Loader took too long serving a block. Finding a new one.');
    this.peer.destroy();
  }
  return this.finish();
};

/**
 * Mark the request as in-flight. Start timeout.
 */

LoadRequest.prototype.start = function start() {
  this.timeout = setTimeout(this.onTimeout, this.pool.requestTimeout);

  this.active = true;
  this.pool.activeRequest++;

  if (this.type === this.pool.txType)
    this.pool.activeTX++;
  else
    this.pool.activeBlocks++;

  return this;
};

/**
 * Mark the request as completed.
 * Remove from queue and map. Clear timeout.
 */

LoadRequest.prototype.finish = function finish() {
  if (this.pool.requestMap[this.hash] === this) {
    delete this.pool.requestMap[this.hash];
    if (this.active) {
      this.active = false;
      this.pool.activeRequest--;
      if (this.type === this.pool.txType)
        this.pool.activeTX--;
      else
        this.pool.activeBlocks--;
    }
  }

  if (this.type === this.pool.txType)
    util.binaryRemove(this.peer.queueTX, this, compare);
  else
    util.binaryRemove(this.peer.queueBlock, this, compare);

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/**
 * Inspect the load request.
 * @returns {String}
 */

LoadRequest.prototype.inspect = function inspect() {
  return '<LoadRequest:'
    + ' id=' + this.id
    + ' type=' + (this.type === this.pool.txType ? 'tx' : 'block')
    + ' active=' + this.active
    + ' hash=' + util.revHex(this.hash)
    + '>';
};

/**
 * Convert load request to an inv item.
 * @returns {InvItem}
 */

LoadRequest.prototype.toInv = function toInv() {
  return new InvItem(this.type, this.hash);
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @exports BroadcastItem
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {TX|Block|InvItem} item
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

function BroadcastItem(pool, item) {
  if (!(this instanceof BroadcastItem))
    return new BroadcastItem(pool, item);

  this.pool = pool;
  this.callback = [];

  this.id = this.pool.uid++;
  this.msg = null;

  if (item instanceof TX)
    assert(!item.mutable, 'Cannot broadcast mutable TX.');

  if (item.toInv) {
    this.msg = item;
    item = item.toInv();
  }

  this.hash = item.hash;
  this.type = item.type;

  assert(this.type != null);
  assert(typeof this.hash === 'string');

  // INV does not set the witness
  // mask (only GETDATA does this).
  assert((this.type & constants.WITNESS_MASK) === 0);
}

util.inherits(BroadcastItem, EventEmitter);

/**
 * Add a callback to be executed on ack, timeout, or reject.
 * @returns {Promise}
 */

BroadcastItem.prototype.addCallback = function addCallback(callback) {
  this.callback.push(callback);
};

/**
 * Start the broadcast.
 */

BroadcastItem.prototype.start = function start() {
  assert(!this.timeout, 'Already started.');
  assert(!this.pool.invMap[this.hash], 'Already started.');

  this.pool.invMap[this.hash] = this;
  util.binaryInsert(this.pool.invItems, this, compare);

  this.refresh();

  return this;
};

/**
 * Refresh the timeout on the broadcast.
 */

BroadcastItem.prototype.refresh = function refresh() {
  var self = this;

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  this.timeout = setTimeout(function() {
    self.emit('timeout');
    self.finish(new Error('Timed out.'));
  }, this.pool.invTimeout);
};

/**
 * Announce the item.
 */

BroadcastItem.prototype.announce = function announce() {
  return this.pool.announce(this);
};

/**
 * Finish the broadcast, potentially with an error.
 * @param {Error?} err
 */

BroadcastItem.prototype.finish = function finish(err) {
  var i;

  assert(this.timeout, 'Already finished.');
  assert(this.pool.invMap[this.hash], 'Already finished.');

  clearTimeout(this.timeout);
  this.timeout = null;

  delete this.pool.invMap[this.hash];
  util.binaryRemove(this.pool.invItems, this, compare);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);

  this.callback.length = 0;
};

/**
 * Handle an ack from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.ack = function ack(peer) {
  var self = this;
  var i;

  setTimeout(function() {
    self.emit('ack', peer);

    for (i = 0; i < self.callback.length; i++)
      self.callback[i](null, true);

    self.callback.length = 0;
  }, 1000);
};

/**
 * Handle a reject from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.reject = function reject(peer) {
  var i;

  this.emit('reject', peer);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](null, false);

  this.callback.length = 0;
};

/**
 * Inspect the broadcast item.
 * @returns {String}
 */

BroadcastItem.prototype.inspect = function inspect() {
  return '<BroadcastItem:'
    + ' id=' + this.id
    + ' type=' + (this.type === constants.inv.TX ? 'tx' : 'block')
    + ' hash=' + util.revHex(this.hash)
    + '>';
};

/**
 * Convert broadcast item to an inv item.
 * @returns {InvItem}
 */

BroadcastItem.prototype.toInv = function toInv() {
  return new InvItem(this.type, this.hash);
};

/*
 * Helpers
 */

function compare(a, b) {
  return a.id - b.id;
}

/*
 * Expose
 */

module.exports = Pool;
