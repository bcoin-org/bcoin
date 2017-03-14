/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var AsyncObject = require('../utils/asyncobject');
var util = require('../utils/util');
var IP = require('../utils/ip');
var co = require('../utils/co');
var common = require('./common');
var chainCommon = require('../blockchain/common');
var Address = require('../primitives/address');
var BIP150 = require('./bip150');
var BIP151 = require('./bip151');
var BIP152 = require('./bip152');
var Bloom = require('../utils/bloom');
var ec = require('../crypto/ec');
var Lock = require('../utils/lock');
var Network = require('../protocol/network');
var Peer = require('./peer');
var request = require('../http/request');
var List = require('../utils/list');
var tcp = require('./tcp');
var dns = require('./dns');
var HostList = require('./hostlist');
var UPNP = require('./upnp');
var InvItem = require('../primitives/invitem');
var Map = require('../utils/map');
var packets = require('./packets');
var services = common.services;
var invTypes = InvItem.types;
var packetTypes = packets.types;
var scores = HostList.scores;

/**
 * A pool of peers for handling all network activity.
 * @alias module:net.Pool
 * @constructor
 * @param {Object} options
 * @param {Chain} options.chain
 * @param {Mempool?} options.mempool
 * @param {Number?} [options.maxOutbound=8] - Maximum number of peers.
 * @param {Boolean?} options.spv - Do an SPV sync.
 * @param {Boolean?} options.noRelay - Whether to ask
 * for relayed transactions.
 * @param {Number?} [options.feeRate] - Fee filter rate.
 * @param {Number?} [options.invTimeout=60000] - Timeout for broadcasted
 * objects.
 * @param {Boolean?} options.listen - Whether to spin up a server socket
 * and listen for peers.
 * @param {Boolean?} options.selfish - A selfish pool. Will not serve blocks,
 * headers, hashes, utxos, or transactions to peers.
 * @param {Boolean?} options.broadcast - Whether to automatically broadcast
 * transactions accepted to our mempool.
 * @param {String[]} options.seeds
 * @param {Function?} options.createSocket - Custom function to create a socket.
 * Must accept (port, host) and return a node-like socket.
 * @param {Function?} options.createServer - Custom function to create a server.
 * Must return a node-like server.
 * @emits Pool#block
 * @emits Pool#tx
 * @emits Pool#peer
 * @emits Pool#open
 * @emits Pool#close
 * @emits Pool#error
 * @emits Pool#reject
 */

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  AsyncObject.call(this);

  this.options = new PoolOptions(options);

  this.network = this.options.network;
  this.logger = this.options.logger.context('net');
  this.chain = this.options.chain;
  this.mempool = this.options.mempool;
  this.server = this.options.createServer();
  this.nonces = this.options.nonces;

  this.locker = new Lock(true);
  this.connected = false;
  this.disconnecting = false;
  this.syncing = false;
  this.spvFilter = null;
  this.txFilter = null;
  this.blockMap = new Map();
  this.txMap = new Map();
  this.compactBlocks = new Map();
  this.invMap = new Map();
  this.pendingFilter = null;
  this.pendingRefill = null;

  this.checkpoints = false;
  this.headerChain = new List();
  this.headerNext = null;
  this.headerTip = null;
  this.headerFails = 0;

  this.peers = new PeerList();
  this.authdb = new BIP150.AuthDB(this.options);
  this.hosts = new HostList(this.options);

  if (this.options.spv)
    this.spvFilter = Bloom.fromRate(20000, 0.001, Bloom.flags.ALL);

  if (!this.options.mempool)
    this.txFilter = new Bloom.Rolling(50000, 0.000001);

  this._init();
};

util.inherits(Pool, AsyncObject);

/**
 * Max number of header chain failures
 * before disabling checkpoints.
 * @const {Number}
 * @default
 */

Pool.MAX_HEADER_FAILS = 1000;

/**
 * Discovery interval for UPNP and DNS seeds.
 * @const {Number}
 * @default
 */

Pool.DISCOVERY_INTERVAL = 120000;

/**
 * Initialize the pool.
 * @private
 */

Pool.prototype._init = function _init() {
  var self = this;

  this.server.on('error', function(err) {
    self.emit('error', err);
  });

  this.server.on('connection', function(socket) {
    self.handleSocket(socket);
    self.emit('connection', socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    self.logger.info(
      'Pool server listening on %s (port=%d).',
      data.address, data.port);
    self.emit('listening', data);
  });

  this.chain.on('block', function(block, entry) {
    self.emit('block', block, entry);
  });

  this.chain.on('reset', function() {
    if (self.checkpoints)
      self.resetChain();
    self.forceSync();
  });

  this.chain.on('full', function() {
    self.sync();
    self.emit('full');
    self.logger.info('Chain is fully synced (height=%d).', self.chain.height);
  });

  if (this.mempool) {
    this.mempool.on('tx', function(tx) {
      self.emit('tx', tx);
    });
  }

  if (!this.options.selfish && !this.options.spv) {
    if (this.mempool) {
      this.mempool.on('tx', function(tx) {
        self.announceTX(tx);
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
      self.announceBlock(block);
    });
  }
};

/**
 * Open the pool, wait for the chain to load.
 * @method
 * @alias Pool#open
 * @returns {Promise}
 */

Pool.prototype._open = co(function* _open() {
  var key;

  if (this.mempool)
    yield this.mempool.open();
  else
    yield this.chain.open();

  this.logger.info('Pool loaded (maxpeers=%d).', this.options.maxOutbound);

  if (this.options.bip150) {
    key = ec.publicKeyCreate(this.options.identityKey, true);
    this.logger.info('Identity public key: %s.', key.toString('hex'));
    this.logger.info('Identity address: %s.', BIP150.address(key));
  }

  this.resetChain();
});

/**
 * Reset header chain.
 */

Pool.prototype.resetChain = function resetChain() {
  var tip = this.chain.tip;

  if (!this.options.checkpoints)
    return;

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  if (tip.height < this.network.lastCheckpoint) {
    this.checkpoints = true;
    this.chain.checkpoints = true;
    this.headerTip = this.getNextTip(tip.height);
    this.headerChain.push(new HeaderEntry(tip.hash, tip.height));
    this.logger.info(
      'Initialized header chain to height %d (checkpoint=%s).',
      tip.height, util.revHex(this.headerTip.hash));
  }
};

/**
 * Close and destroy the pool.
 * @method
 * @alias Pool#close
 * @returns {Promise}
 */

Pool.prototype._close = co(function* close() {
  yield this.disconnect();
});

/**
 * Connect to the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype.connect = co(function* connect() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._connect();
  } finally {
    unlock();
  }
});

/**
 * Connect to the network (no lock).
 * @method
 * @returns {Promise}
 */

Pool.prototype._connect = co(function* connect() {
  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  yield this.hosts.open();
  yield this.authdb.open();

  yield this.discoverGateway();
  yield this.discoverExternal();
  yield this.discoverSeeds();

  this.fillOutbound();

  yield this.listen();

  this.startTimer();

  this.connected = true;
});

/**
 * Disconnect from the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype.disconnect = co(function* disconnect() {
  var unlock = yield this.locker.lock();
  try {
    return yield this._disconnect();
  } finally {
    unlock();
  }
});

/**
 * Disconnect from the network.
 * @method
 * @returns {Promise}
 */

Pool.prototype._disconnect = co(function* disconnect() {
  var i, item, hashes, hash;

  assert(this.loaded, 'Pool is not loaded.');

  if (!this.connected)
    return;

  this.disconnecting = true;

  hashes = this.invMap.keys();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.invMap.get(hash);
    item.resolve();
  }

  this.peers.destroy();

  this.blockMap.reset();
  this.txMap.reset();

  if (this.pendingFilter != null) {
    clearTimeout(this.pendingFilter);
    this.pendingFilter = null;
  }

  if (this.pendingRefill != null) {
    clearTimeout(this.pendingRefill);
    this.pendingRefill = null;
  }

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  this.stopTimer();

  yield this.authdb.close();
  yield this.hosts.close();

  yield this.unlisten();

  this.disconnecting = false;
  this.syncing = false;
  this.connected = false;
});

/**
 * Start listening on a server socket.
 * @method
 * @private
 * @returns {Promise}
 */

Pool.prototype.listen = co(function* listen() {
  assert(this.server);
  assert(!this.connected, 'Already listening.');

  if (!this.options.listen)
    return;

  this.server.maxConnections = this.options.maxInbound;

  yield this.server.listen(this.options.port, this.options.host);
});

/**
 * Stop listening on server socket.
 * @method
 * @private
 * @returns {Promise}
 */

Pool.prototype.unlisten = co(function* unlisten() {
  assert(this.server);
  assert(this.connected, 'Not listening.');

  if (!this.options.listen)
    return;

  yield this.server.close();
});

/**
 * Start discovery timer.
 * @private
 */

Pool.prototype.startTimer = function startTimer() {
  assert(this.timer == null, 'Timer already started.');
  this.timer = co.setInterval(this.discover, Pool.DISCOVERY_INTERVAL, this);
};

/**
 * Stop discovery timer.
 * @private
 */

Pool.prototype.stopTimer = function stopTimer() {
  assert(this.timer != null, 'Timer already stopped.');
  co.clearInterval(this.timer);
  this.timer = null;
};

/**
 * Rediscover seeds and internet gateway.
 * Attempt to add port mapping once again.
 * @returns {Promise}
 */

Pool.prototype.discover = co(function* discover() {
  yield this.discoverGateway();
  yield this.discoverSeeds(true);
});

/**
 * Attempt to add port mapping (i.e.
 * remote:8333->local:8333) via UPNP.
 * @returns {Promise}
 */

Pool.prototype.discoverGateway = co(function* discoverGateway() {
  var src = this.options.publicPort;
  var dest = this.options.port;
  var wan, host;

  // Pointless if we're not listening.
  if (!this.options.listen)
    return;

  // UPNP is always optional, since
  // it's likely to not work anyway.
  if (!this.options.upnp)
    return;

  try {
    this.logger.debug('Discovering internet gateway (upnp).');
    wan = yield UPNP.discover();
  } catch (e) {
    this.logger.debug('Could not discover internet gateway (upnp).');
    this.logger.debug(e);
    return false;
  }

  try {
    host = yield wan.getExternalIP();
  } catch (e) {
    this.logger.debug('Could not find external IP (upnp).');
    this.logger.debug(e);
    return false;
  }

  if (this.hosts.addLocal(host, src, scores.UPNP))
    this.logger.info('External IP found (upnp): %s.', host);

  this.logger.debug(
    'Adding port mapping %d->%d.',
    src, dest);

  try {
    yield wan.addPortMapping(host, src, dest);
  } catch (e) {
    this.logger.debug('Could not add port mapping (upnp).');
    this.logger.debug(e);
    return false;
  }

  return true;
});

/**
 * Attempt to resolve DNS seeds if necessary.
 * @param {Boolean} checkPeers
 * @returns {Promise}
 */

Pool.prototype.discoverSeeds = co(function* discoverSeeds(checkPeers) {
  var max = Math.min(2, this.options.maxOutbound);
  var size = this.hosts.size();
  var total = 0;
  var peer;

  if (this.hosts.dnsSeeds.length === 0)
    return;

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (peer.connected) {
      if (++total > max)
        break;
    }
  }

  if (size === 0 || (checkPeers && total < max)) {
    this.logger.warning('Could not find enough peers.');
    this.logger.warning('Hitting DNS seeds...');

    yield this.hosts.discoverSeeds();

    this.logger.info(
      'Resolved %d hosts from DNS seeds.',
      this.hosts.size() - size);

    this.refill();
  }
});

/**
 * Attempt to discover external IP via HTTP.
 * @returns {Promise}
 */

Pool.prototype.discoverExternal = co(function* discoverExternal() {
  var port = this.options.publicPort;
  var host;

  // Pointless if we're not listening.
  if (!this.options.listen)
    return;

  // Never hit an HTTP server if
  // we're using an outbound proxy.
  if (this.options.proxy)
    return;

  // Try not to hit this if we can avoid it.
  if (this.hosts.local.size > 0)
    return;

  try {
    host = yield this.getIP();
  } catch (e) {
    this.logger.debug('Could not find external IP (http).');
    this.logger.debug(e);
    return;
  }

  if (this.hosts.addLocal(host, port, scores.HTTP))
    this.logger.info('External IP found (http): %s.', host);
});

/**
 * Handle incoming connection.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype.handleSocket = function handleSocket(socket) {
  var host;

  if (!socket.remoteAddress) {
    this.logger.debug('Ignoring disconnected peer.');
    socket.destroy();
    return;
  }

  host = IP.normalize(socket.remoteAddress);

  if (this.peers.inbound >= this.options.maxInbound) {
    this.logger.debug('Ignoring peer: too many inbound (%s).', host);
    socket.destroy();
    return;
  }

  if (this.hosts.isBanned(host)) {
    this.logger.debug('Ignoring banned peer (%s).', host);
    socket.destroy();
    return;
  }

  host = IP.toHostname(host, socket.remotePort);

  assert(!this.peers.map[host], 'Port collision.');

  this.addInbound(socket);
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.addLoader = function addLoader() {
  var peer, addr;

  if (!this.loaded)
    return;

  assert(!this.peers.load);

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    this.logger.info(
      'Repurposing peer for loader (%s).',
      peer.hostname());

    this.setLoader(peer);

    return;
  }

  addr = this.getHost();

  if (!addr)
    return;

  peer = this.createOutbound(addr);

  this.logger.info('Adding loader peer (%s).', peer.hostname());

  this.peers.add(peer);

  this.setLoader(peer);
};

/**
 * Add a loader peer. Necessary for
 * a sync to even begin.
 * @private
 */

Pool.prototype.setLoader = function setLoader(peer) {
  if (!this.loaded)
    return;

  assert(peer.outbound);
  assert(!this.peers.load);
  assert(!peer.loader);

  peer.loader = true;
  this.peers.load = peer;

  this.sendSync(peer);

  this.emit('loader', peer);
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  if (!this.loaded)
    return;

  assert(this.connected, 'Pool is not connected!');

  this.syncing = true;
  this.resync(false);
};

/**
 * Force sending of a sync to each peer.
 */

Pool.prototype.forceSync = function forceSync() {
  if (!this.loaded)
    return;

  assert(this.connected, 'Pool is not connected!');

  this.resync(true);
};

/**
 * Send a sync to each peer.
 */

Pool.prototype.sync = function* sync(force) {
  this.resync(false);
};

/**
 * Stop the sync.
 * @private
 */

Pool.prototype.stopSync = function stopSync() {
  var peer;

  if (!this.syncing)
    return;

  this.syncing = false;

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (!peer.syncing)
      continue;

    peer.syncing = false;
    peer.merkleBlock = null;
    peer.merkleTime = -1;
    peer.merkleMatches = 0;
    peer.merkleMap = null;
    peer.blockTime = -1;
    peer.blockMap.reset();
    peer.compactBlocks.reset();
  }

  this.blockMap.reset();
  this.compactBlocks.reset();
};

/**
 * Send a sync to each peer.
 * @private
 * @param {Boolean?} force
 * @returns {Promise}
 */

Pool.prototype.resync = co(function* resync(force) {
  var peer, locator;

  if (!this.syncing)
    return;

  try {
    locator = yield this.chain.getLocator();
  } catch (e) {
    this.emit('error', e);
    return;
  }

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;

    if (!force && peer.syncing)
      continue;

    this.sendLocator(locator, peer);
  }
});

/**
 * Test whether a peer is sync-worthy.
 * @param {Peer} peer
 * @returns {Boolean}
 */

Pool.prototype.isSyncable = function isSyncable(peer) {
  if (!this.syncing)
    return false;

  if (peer.destroyed)
    return false;

  if (!peer.handshake)
    return false;

  if (!(peer.services & services.NETWORK))
    return false;

  if (this.options.hasWitness() && !peer.hasWitness())
    return false;

  if (!peer.loader) {
    if (!this.chain.synced)
      return false;
  }

  return true;
};

/**
 * Start syncing from peer.
 * @method
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.sendSync = co(function* sendSync(peer) {
  var locator;

  if (peer.syncing)
    return false;

  if (!this.isSyncable(peer))
    return false;

  peer.syncing = true;
  peer.blockTime = util.ms();

  try {
    locator = yield this.chain.getLocator();
  } catch (e) {
    peer.syncing = false;
    peer.blockTime = -1;
    this.emit('error', e);
    return false;
  }

  return this.sendLocator(locator, peer);
});

/**
 * Send a chain locator and start syncing from peer.
 * @method
 * @param {Hash[]} locator
 * @param {Peer} peer
 * @returns {Boolean}
 */

Pool.prototype.sendLocator = function sendLocator(locator, peer) {
  if (!this.isSyncable(peer))
    return false;

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (peer.loader && this.chain.synced)
      peer.sendMempool();
  }

  peer.syncing = true;
  peer.blockTime = util.ms();

  if (this.checkpoints) {
    peer.sendGetHeaders(locator, this.headerTip.hash);
    return true;
  }

  peer.sendGetBlocks(locator);

  return true;
};

/**
 * Send `mempool` to all peers.
 */

Pool.prototype.sendMempool = function sendMempool() {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.sendMempool();
};

/**
 * Send `getaddr` to all peers.
 */

Pool.prototype.sendGetAddr = function sendGetAddr() {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.sendGetAddr();
};

/**
 * Request current header chain blocks.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.resolveHeaders = function resolveHeaders(peer) {
  var items = [];
  var node;

  for (node = this.headerNext; node; node = node.next) {
    this.headerNext = node.next;

    items.push(node.hash);

    if (items.length === 50000)
      break;
  }

  this.getBlock(peer, items);
};

/**
 * Update all peer heights by their best hash.
 * @param {Hash} hash
 * @param {Number} height
 */

Pool.prototype.resolveHeight = function resolveHeight(hash, height) {
  var total = 0;
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (peer.bestHash !== hash)
      continue;

    if (peer.bestHeight !== height) {
      peer.bestHeight = height;
      total++;
    }
  }

  if (total > 0)
    this.logger.debug('Resolved height for %d peers.', total);
};

/**
 * Find the next checkpoint.
 * @private
 * @param {Number} height
 * @returns {Object}
 */

Pool.prototype.getNextTip = function getNextTip(height) {
  var i, next;

  for (i = 0; i < this.network.checkpoints.length; i++) {
    next = this.network.checkpoints[i];
    if (next.height > height)
      return new HeaderEntry(next.hash, next.height);
  }

  throw new Error('Next checkpoint not found.');
};

/**
 * Announce broadcast list to peer.
 * @param {Peer} peer
 */

Pool.prototype.announceList = function announceList(peer) {
  var blocks = [];
  var txs = [];
  var hashes = this.invMap.keys();
  var i, hash, item;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.invMap.get(hash);

    switch (item.type) {
      case invTypes.BLOCK:
        blocks.push(item.msg);
        break;
      case invTypes.TX:
        txs.push(item.msg);
        break;
      default:
        assert(false, 'Bad item type.');
        break;
    }
  }

  if (blocks.length > 0)
    peer.announceBlock(blocks);

  if (txs.length > 0)
    peer.announceTX(txs);
};

/**
 * Get a block/tx from the broadcast map.
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Promise}
 */

Pool.prototype.getBroadcasted = function getBroadcasted(peer, item) {
  var type = item.isTX() ? invTypes.TX : invTypes.BLOCK;
  var entry = this.invMap.get(item.hash);

  if (!entry)
    return;

  if (type !== entry.type) {
    this.logger.debug(
      'Peer requested item with the wrong type (%s).',
      peer.hostname());
    return;
  }

  this.logger.debug(
    'Peer requested %s %s as a %s packet (%s).',
    item.isTX() ? 'tx' : 'block',
    item.rhash(),
    item.hasWitness() ? 'witness' : 'normal',
    peer.hostname());

  entry.handleAck(peer);

  return entry.msg;
};

/**
 * Get a block/tx either from the broadcast map, mempool, or blockchain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Promise}
 */

Pool.prototype.getItem = co(function* getItem(peer, item) {
  var entry = this.getBroadcasted(peer, item);

  if (entry)
    return entry;

  if (this.options.selfish)
    return;

  if (item.isTX()) {
    if (!this.mempool)
      return;
    return this.mempool.getTX(item.hash);
  }

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  return yield this.chain.db.getBlock(item.hash);
});

/**
 * Send a block from the broadcast list or chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Boolean}
 */

Pool.prototype.sendBlock = co(function* sendBlock(peer, item, witness) {
  var block = this.getBroadcasted(peer, item);

  // Check for a broadcasted item first.
  if (block) {
    peer.send(new packets.BlockPacket(block, witness));
    return true;
  }

  if (this.options.selfish
      || this.chain.options.spv
      || this.chain.options.prune) {
    return false;
  }

  // If we have the same serialization, we
  // can write the raw binary to the socket.
  if (witness || !this.options.hasWitness()) {
    block = yield this.chain.db.getRawBlock(item.hash);

    if (block) {
      peer.sendRaw('block', block);
      return true;
    }

    return false;
  }

  block = yield this.chain.db.getBlock(item.hash);

  if (block) {
    peer.send(new packets.BlockPacket(block, witness));
    return true;
  }

  return false;
});

/**
 * Create an outbound peer with no special purpose.
 * @private
 * @param {NetAddress} addr
 * @returns {Peer}
 */

Pool.prototype.createOutbound = function createOutbound(addr) {
  var cipher = BIP151.ciphers.CHACHAPOLY;
  var identity = this.options.identityKey;
  var peer = Peer.fromOutbound(this.options, addr);

  this.hosts.markAttempt(addr.hostname);

  if (this.options.bip151)
    peer.setCipher(cipher);

  if (this.options.bip150)
    peer.setAuth(this.authdb, identity);

  this.bindPeer(peer);

  this.logger.debug('Connecting to %s.', peer.hostname());

  peer.tryOpen();

  return peer;
};

/**
 * Accept an inbound socket.
 * @private
 * @param {net.Socket} socket
 * @returns {Peer}
 */

Pool.prototype.createInbound = function createInbound(socket) {
  var cipher = BIP151.ciphers.CHACHAPOLY;
  var identity = this.options.identityKey;
  var peer = Peer.fromInbound(this.options, socket);

  if (this.options.bip151)
    peer.setCipher(cipher);

  if (this.options.bip150)
    peer.setAuth(this.authdb, identity);

  this.bindPeer(peer);

  peer.tryOpen();

  return peer;
};

/**
 * Bind to peer events.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.bindPeer = function bindPeer(peer) {
  var self = this;

  peer.onPacket = function onPacket(packet) {
    return self.handlePacket(peer, packet);
  };

  peer.on('error', function(err) {
    self.logger.debug(err);
  });

  peer.once('connect', function() {
    self.handleConnect(peer);
  });

  peer.once('open', function() {
    self.handleOpen(peer);
  });

  peer.once('close', function(connected) {
    self.handleClose(peer, connected);
  });

  peer.once('ban', function() {
    self.handleBan(peer);
  });
};

/**
 * Handle peer packet event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Packet} packet
 * @returns {Promise}
 */

Pool.prototype.handlePacket = co(function* handlePacket(peer, packet) {
  switch (packet.type) {
    case packetTypes.VERSION:
      yield this.handleVersion(peer, packet);
      break;
    case packetTypes.VERACK:
      yield this.handleVerack(peer, packet);
      break;
    case packetTypes.PING:
      yield this.handlePing(peer, packet);
      break;
    case packetTypes.PONG:
      yield this.handlePong(peer, packet);
      break;
    case packetTypes.GETADDR:
      yield this.handleGetAddr(peer, packet);
      break;
    case packetTypes.ADDR:
      yield this.handleAddr(peer, packet);
      break;
    case packetTypes.INV:
      yield this.handleInv(peer, packet);
      break;
    case packetTypes.GETDATA:
      yield this.handleGetData(peer, packet);
      break;
    case packetTypes.NOTFOUND:
      yield this.handleNotFound(peer, packet);
      break;
    case packetTypes.GETBLOCKS:
      yield this.handleGetBlocks(peer, packet);
      break;
    case packetTypes.GETHEADERS:
      yield this.handleGetHeaders(peer, packet);
      break;
    case packetTypes.HEADERS:
      yield this.handleHeaders(peer, packet);
      break;
    case packetTypes.SENDHEADERS:
      yield this.handleSendHeaders(peer, packet);
      break;
    case packetTypes.BLOCK:
      yield this.handleBlock(peer, packet);
      break;
    case packetTypes.TX:
      yield this.handleTX(peer, packet);
      break;
    case packetTypes.REJECT:
      yield this.handleReject(peer, packet);
      break;
    case packetTypes.MEMPOOL:
      yield this.handleMempool(peer, packet);
      break;
    case packetTypes.FILTERLOAD:
      yield this.handleFilterLoad(peer, packet);
      break;
    case packetTypes.FILTERADD:
      yield this.handleFilterAdd(peer, packet);
      break;
    case packetTypes.FILTERCLEAR:
      yield this.handleFilterClear(peer, packet);
      break;
    case packetTypes.MERKLEBLOCK:
      yield this.handleMerkleBlock(peer, packet);
      break;
    case packetTypes.FEEFILTER:
      yield this.handleFeeFilter(peer, packet);
      break;
    case packetTypes.SENDCMPCT:
      yield this.handleSendCmpct(peer, packet);
      break;
    case packetTypes.CMPCTBLOCK:
      yield this.handleCmpctBlock(peer, packet);
      break;
    case packetTypes.GETBLOCKTXN:
      yield this.handleGetBlockTxn(peer, packet);
      break;
    case packetTypes.BLOCKTXN:
      yield this.handleBlockTxn(peer, packet);
      break;
    case packetTypes.ENCINIT:
      yield this.handleEncinit(peer, packet);
      break;
    case packetTypes.ENCACK:
      yield this.handleEncack(peer, packet);
      break;
    case packetTypes.AUTHCHALLENGE:
      yield this.handleAuthChallenge(peer, packet);
      break;
    case packetTypes.AUTHREPLY:
      yield this.handleAuthReply(peer, packet);
      break;
    case packetTypes.AUTHPROPOSE:
      yield this.handleAuthPropose(peer, packet);
      break;
    case packetTypes.UNKNOWN:
      yield this.handleUnknown(peer, packet);
      break;
    default:
      assert(false, 'Bad packet type.');
      break;
  }

  this.emit('packet', packet, peer);
});

/**
 * Handle peer connect event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleConnect = co(function* handleConnect(peer) {
  this.logger.info('Connected to %s.', peer.hostname());

  if (peer.outbound)
    this.hosts.markSuccess(peer.hostname());

  this.emit('peer connect', peer);
});

/**
 * Handle peer open event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleOpen = co(function* handleOpen(peer) {
  var addr;

  // Advertise our address.
  if (!this.options.selfish && this.options.listen) {
    addr = this.hosts.getLocal(peer.address);
    if (addr)
      peer.send(new packets.AddrPacket([addr]));
  }

  // We want compact blocks!
  if (this.options.compact)
    peer.sendCompact(this.options.blockMode);

  // Find some more peers.
  if (!this.hosts.isFull())
    peer.sendGetAddr();

  // Relay our spv filter if we have one.
  if (this.spvFilter)
    peer.sendFilterLoad(this.spvFilter);

  // Announce our currently broadcasted items.
  this.announceList(peer);

  // Set a fee rate filter.
  if (this.options.feeRate !== -1)
    peer.sendFeeRate(this.options.feeRate);

  // Start syncing the chain.
  if (peer.outbound)
    this.sendSync(peer);

  if (peer.outbound) {
    this.hosts.markAck(peer.hostname(), peer.services);

    // If we don't have an ack'd
    // loader yet consider it dead.
    if (!peer.loader) {
      if (this.peers.load && !this.peers.load.handshake) {
        assert(this.peers.load.loader);
        this.peers.load.loader = false;
        this.peers.load = null;
      }
    }

    // If we do not have a loader,
    // use this peer.
    if (!this.peers.load)
      this.setLoader(peer);
  }

  this.emit('peer open', peer);
});

/**
 * Handle peer close event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Boolean} connected
 */

Pool.prototype.handleClose = co(function* handleClose(peer, connected) {
  var outbound = peer.outbound;
  var loader = peer.loader;
  var size = peer.blockMap.size;

  this.removePeer(peer);

  if (loader) {
    this.logger.info('Removed loader peer (%s).', peer.hostname());
    if (this.checkpoints)
      this.resetChain();
  }

  this.nonces.remove(peer.hostname());

  this.emit('peer close', peer, connected);

  if (!this.loaded)
    return;

  if (this.disconnecting)
    return;

  if (this.chain.synced && size > 0) {
    this.logger.warning('Peer disconnected with requested blocks.');
    this.logger.warning('Resending sync...');
    this.forceSync();
  }

  if (!outbound)
    return;

  this.refill();
});

/**
 * Handle ban event.
 * @method
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleBan = co(function* handleBan(peer) {
  this.ban(peer.address);
  this.emit('ban', peer);
});

/**
 * Handle peer version event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {VersionPacket} packet
 */

Pool.prototype.handleVersion = co(function* handleVersion(peer, packet) {
  this.logger.info(
    'Received version (%s): version=%d height=%d services=%s agent=%s',
    peer.hostname(),
    packet.version,
    packet.height,
    packet.services.toString(2),
    packet.agent);

  this.network.time.add(peer.hostname(), packet.ts);
  this.nonces.remove(peer.hostname());

  if (!peer.outbound && packet.remote.isRoutable())
    this.hosts.markLocal(packet.remote);
});

/**
 * Handle `verack` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {VerackPacket} packet
 */

Pool.prototype.handleVerack = co(function* handleVerack(peer, packet) {
  ;
});

/**
 * Handle `ping` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {PingPacket} packet
 */

Pool.prototype.handlePing = co(function* handlePing(peer, packet) {
  ;
});

/**
 * Handle `pong` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {PongPacket} packet
 */

Pool.prototype.handlePong = co(function* handlePong(peer, packet) {
  ;
});

/**
 * Handle `getaddr` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetAddrPacket} packet
 */

Pool.prototype.handleGetAddr = co(function* handleGetAddr(peer, packet) {
  var items = [];
  var i, addrs, addr;

  if (this.options.selfish)
    return;

  if (peer.sentAddr) {
    this.logger.debug(
      'Ignoring repeated getaddr (%s).',
      peer.hostname());
    return;
  }

  peer.sentAddr = true;

  addrs = this.hosts.toArray();

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    if (!peer.addrFilter.added(addr.hostname, 'ascii'))
      continue;

    items.push(addr);

    if (items.length === 1000)
      break;
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Sending %d addrs to peer (%s)',
    items.length,
    peer.hostname());

  peer.send(new packets.AddrPacket(items));
});

/**
 * Handle peer addr event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AddrPacket} packet
 */

Pool.prototype.handleAddr = co(function* handleAddr(peer, packet) {
  var addrs = packet.items;
  var now = this.network.now();
  var services = this.options.getRequiredServices();
  var i, addr;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    peer.addrFilter.add(addr.hostname, 'ascii');

    if (!addr.isRoutable())
      continue;

    if (!addr.hasServices(services))
      continue;

    if (addr.ts <= 100000000 || addr.ts > now + 10 * 60)
      addr.ts = now - 5 * 24 * 60 * 60;

    if (addr.port === 0)
      continue;

    this.hosts.add(addr, peer.address);
  }

  this.logger.info(
    'Received %d addrs (hosts=%d, peers=%d) (%s).',
    addrs.length,
    this.hosts.size(),
    this.peers.size(),
    peer.hostname());

  this.fillOutbound();
});

/**
 * Handle `inv` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvPacket} packet
 */

Pool.prototype.handleInv = co(function* handleInv(peer, packet) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._handleInv(peer, packet);
  } finally {
    unlock();
  }
});

/**
 * Handle `inv` packet (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {InvPacket} packet
 */

Pool.prototype._handleInv = co(function* handleInv(peer, packet) {
  var items = packet.items;
  var blocks = [];
  var txs = [];
  var unknown = -1;
  var i, item;

  if (items.length > 50000) {
    peer.increaseBan(100);
    return;
  }

  for (i = 0; i < items.length; i++) {
    item = items[i];
    switch (item.type) {
      case invTypes.BLOCK:
        blocks.push(item.hash);
        break;
      case invTypes.TX:
        txs.push(item.hash);
        break;
      default:
        unknown = item.type;
        continue;
    }
    peer.invFilter.add(item.hash, 'hex');
  }

  this.logger.spam(
    'Received inv packet with %d items: blocks=%d txs=%d (%s).',
    items.length, blocks.length, txs.length, peer.hostname());

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown inv type: %d (%s).',
      unknown, peer.hostname());
  }

  if (blocks.length > 0)
    yield this.handleBlockInv(peer, blocks);

  if (txs.length > 0)
    yield this.handleTXInv(peer, txs);
});

/**
 * Handle `inv` packet from peer (containing only BLOCK types).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash[]} hashes
 * @returns {Promise}
 */

Pool.prototype.handleBlockInv = co(function* handleBlockInv(peer, hashes) {
  var items = [];
  var i, hash, exists, height;

  assert(hashes.length > 0);

  if (!this.syncing)
    return;

  // Always keep track of the peer's best hash.
  if (!peer.loader || this.chain.synced) {
    hash = hashes[hashes.length - 1];
    peer.bestHash = hash;
  }

  // Ignore for now if we're still syncing
  if (!this.chain.synced && !peer.loader)
    return;

  if (this.options.hasWitness() && !peer.hasWitness())
    return;

  // Request headers instead.
  if (this.checkpoints)
    return;

  this.logger.debug(
    'Received %s block hashes from peer (%s).',
    hashes.length,
    peer.hostname());

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    // Resolve orphan chain.
    if (this.chain.hasOrphan(hash)) {
      this.logger.debug('Received known orphan hash (%s).', peer.hostname());
      yield this.resolveOrphan(peer, hash);
      continue;
    }

    // Request the block if we don't have it.
    if (!(yield this.hasBlock(hash))) {
      items.push(hash);
      continue;
    }

    exists = hash;

    // Normally we request the hashContinue.
    // In the odd case where we already have
    // it, we can do one of two things: either
    // force re-downloading of the block to
    // continue the sync, or do a getblocks
    // from the last hash (this will reset
    // the hashContinue on the remote node).
    if (i === hashes.length - 1) {
      this.logger.debug('Received existing hash (%s).', peer.hostname());
      yield this.getBlocks(peer, hash);
    }
  }

  // Attempt to update the peer's best height
  // with the last existing hash we know of.
  if (exists && this.chain.synced) {
    height = yield this.chain.db.getHeight(exists);
    if (height !== -1)
      peer.bestHeight = height;
  }

  this.getBlock(peer, items);
});

/**
 * Handle peer inv packet (txs).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.handleTXInv = co(function* handleTXInv(peer, hashes) {
  assert(hashes.length > 0);

  if (this.syncing && !this.chain.synced)
    return;

  this.ensureTX(peer, hashes);
});

/**
 * Handle `getdata` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetDataPacket} packet
 */

Pool.prototype.handleGetData = co(function* handleGetData(peer, packet) {
  var items = packet.items;
  var notFound = [];
  var txs = 0;
  var blocks = 0;
  var compact = 0;
  var unknown = -1;
  var i, j, item, tx, block, result, height;

  if (items.length > 50000) {
    this.logger.warning('Peer sent inv with >50k items (%s).', peer.hostname());
    peer.increaseBan(100);
    peer.destroy();
    return;
  }

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (item.isTX()) {
      tx = yield this.getItem(peer, item);

      if (!tx) {
        notFound.push(item);
        continue;
      }

      // Coinbases are an insta-ban from any node.
      // This should technically never happen, but
      // it's worth keeping here just in case. A
      // 24-hour ban from any node is rough.
      if (tx.isCoinbase()) {
        notFound.push(item);
        this.logger.warning('Failsafe: tried to relay a coinbase.');
        continue;
      }

      peer.send(new packets.TXPacket(tx, item.hasWitness()));

      txs++;

      continue;
    }

    switch (item.type) {
      case invTypes.BLOCK:
      case invTypes.WITNESS_BLOCK:
        result = yield this.sendBlock(peer, item, item.hasWitness());
        if (!result) {
          notFound.push(item);
          continue;
        }
        blocks++;
        break;
      case invTypes.FILTERED_BLOCK:
      case invTypes.WITNESS_FILTERED_BLOCK:
        if (!this.options.bip37) {
          this.logger.debug(
            'Peer requested a merkleblock without bip37 enabled (%s).',
            peer.hostname());
          peer.destroy();
          return;
        }

        if (!peer.spvFilter) {
          notFound.push(item);
          continue;
        }

        block = yield this.getItem(peer, item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        block = block.toMerkle(peer.spvFilter);

        peer.send(new packets.MerkleBlockPacket(block));

        for (j = 0; j < block.txs.length; j++) {
          tx = block.txs[j];
          peer.send(new packets.TXPacket(tx, item.hasWitness()));
          txs++;
        }

        blocks++;

        break;
      case invTypes.CMPCT_BLOCK:
        height = yield this.chain.db.getHeight(item.hash);

        // Fallback to full block.
        if (height < this.chain.tip.height - 10) {
          result = yield this.sendBlock(peer, item, peer.compactWitness);
          if (!result) {
            notFound.push(item);
            continue;
          }
          blocks++;
          break;
        }

        block = yield this.getItem(peer, item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        peer.sendCompactBlock(block);

        blocks++;
        compact++;

        break;
      default:
        unknown = item.type;
        notFound.push(item);
        continue;
    }

    if (item.hash === peer.hashContinue) {
      peer.sendInv([new InvItem(invTypes.BLOCK, this.chain.tip.hash)]);
      peer.hashContinue = null;
    }

    // Wait for the peer to read
    // before we pull more data
    // out of the database.
    yield peer.drain();
  }

  if (notFound.length > 0)
    peer.send(new packets.NotFoundPacket(notFound));

  if (txs > 0) {
    this.logger.debug(
      'Served %d txs with getdata (notfound=%d) (%s).',
      txs, notFound.length, peer.hostname());
  }

  if (blocks > 0) {
    this.logger.debug(
      'Served %d blocks with getdata (notfound=%d, cmpct=%d) (%s).',
      blocks, notFound.length, compact, peer.hostname());
  }

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown getdata type: %s (%d).',
      unknown, peer.hostname());
  }
});

/**
 * Handle peer notfound packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {NotFoundPacket} packet
 */

Pool.prototype.handleNotFound = co(function* handleNotFound(peer, packet) {
  var items = packet.items;
  var i, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (!this.resolveItem(peer, item)) {
      this.logger.warning(
        'Peer sent notfound for unrequested item: %s (%s).',
        item.hash, peer.hostname());
      peer.destroy();
      return;
    }
  }
});

/**
 * Handle `getblocks` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetBlocksPacket} packet
 */

Pool.prototype.handleGetBlocks = co(function* handleGetBlocks(peer, packet) {
  var blocks = [];
  var hash;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  hash = yield this.chain.findLocator(packet.locator);

  if (hash)
    hash = yield this.chain.db.getNextHash(hash);

  while (hash) {
    blocks.push(new InvItem(invTypes.BLOCK, hash));

    if (hash === packet.stop)
      break;

    if (blocks.length === 500) {
      peer.hashContinue = hash;
      break;
    }

    hash = yield this.chain.db.getNextHash(hash);
  }

  peer.sendInv(blocks);
});

/**
 * Handle `getheaders` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetHeadersPacket} packet
 */

Pool.prototype.handleGetHeaders = co(function* handleGetHeaders(peer, packet) {
  var headers = [];
  var hash, entry;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  if (packet.locator.length > 0) {
    hash = yield this.chain.findLocator(packet.locator);
    if (hash)
      hash = yield this.chain.db.getNextHash(hash);
  } else {
    hash = packet.stop;
  }

  if (hash)
    entry = yield this.chain.db.getEntry(hash);

  while (entry) {
    headers.push(entry.toHeaders());

    if (entry.hash === packet.stop)
      break;

    if (headers.length === 2000)
      break;

    entry = yield entry.getNext();
  }

  peer.sendHeaders(headers);
});

/**
 * Handle `headers` packet from a given peer.
 * @method
 * @private
 * @param {Peer} peer
 * @param {HeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleHeaders = co(function* handleHeaders(peer, packet) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._handleHeaders(peer, packet);
  } finally {
    unlock();
  }
});

/**
 * Handle `headers` packet from
 * a given peer without a lock.
 * @method
 * @private
 * @param {Peer} peer
 * @param {HeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype._handleHeaders = co(function* handleHeaders(peer, packet) {
  var headers = packet.items;
  var checkpoint = false;
  var i, header, hash, height, last, node;

  if (!this.checkpoints)
    return;

  if (!this.syncing)
    return;

  if (!peer.loader)
    return;

  if (headers.length === 0)
    return;

  if (headers.length > 2000) {
    peer.increaseBan(100);
    return;
  }

  assert(this.headerChain.size > 0);

  for (i = 0; i < headers.length; i++) {
    header = headers[i];
    last = this.headerChain.tail;
    hash = header.hash('hex');
    height = last.height + 1;

    if (!header.verify()) {
      this.logger.warning(
        'Peer sent an invalid header (%s).',
        peer.hostname());
      peer.increaseBan(100);
      peer.destroy();
      return;
    }

    if (header.prevBlock !== last.hash) {
      this.logger.warning(
        'Peer sent a bad header chain (%s).',
        peer.hostname());

      if (++this.headerFails < Pool.MAX_HEADER_FAILS) {
        peer.destroy();
        return;
      }

      this.logger.warning(
        'Switching to getblocks (%s).',
        peer.hostname());

      yield this.switchSync(peer);
      return;
    }

    node = new HeaderEntry(hash, height);

    if (node.height === this.headerTip.height) {
      if (node.hash !== this.headerTip.hash) {
        this.logger.warning(
          'Peer sent an invalid checkpoint (%s).',
          peer.hostname());

        if (++this.headerFails < Pool.MAX_HEADER_FAILS) {
          peer.destroy();
          return;
        }

        this.logger.warning(
          'Switching to getblocks (%s).',
          peer.hostname());

        yield this.switchSync(peer);
        return;
      }
      checkpoint = true;
    }

    if (!this.headerNext)
      this.headerNext = node;

    this.headerChain.push(node);
  }

  this.logger.debug(
    'Received %s headers from peer (%s).',
    headers.length,
    peer.hostname());

  // If we received a valid header
  // chain, consider this a "block".
  peer.blockTime = util.ms();

  // Request the blocks we just added.
  if (checkpoint) {
    this.headerChain.shift();
    this.resolveHeaders(peer);
    return;
  }

  // Request more headers.
  peer.sendGetHeaders([node.hash], this.headerTip.hash);
});

/**
 * Handle `sendheaders` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {SendHeadersPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleSendHeaders = co(function* handleSendHeaders(peer, packet) {
  ;
});

/**
 * Handle `block` packet. Attempt to add to chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {BlockPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleBlock = co(function* handleBlock(peer, packet) {
  var flags = chainCommon.flags.DEFAULT_FLAGS;

  if (this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited block (%s).',
      peer.hostname());
    return;
  }

  return yield this.addBlock(peer, packet.block, flags);
});

/**
 * Attempt to add block to chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Block} block
 * @returns {Promise}
 */

Pool.prototype.addBlock = co(function* addBlock(peer, block, flags) {
  var hash = block.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._addBlock(peer, block, flags);
  } finally {
    unlock();
  }
});

/**
 * Attempt to add block to chain (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {Block} block
 * @returns {Promise}
 */

Pool.prototype._addBlock = co(function* addBlock(peer, block, flags) {
  var hash = block.hash('hex');
  var entry, height;

  if (!this.syncing)
    return;

  if (!this.resolveBlock(peer, hash)) {
    this.logger.warning(
      'Received unrequested block: %s (%s).',
      block.rhash(), peer.hostname());
    peer.destroy();
    return;
  }

  peer.blockTime = util.ms();

  try {
    entry = yield this.chain.add(block, flags);
  } catch (err) {
    if (err.type === 'VerifyError') {
      peer.reject(block, err.code, err.reason, err.score);
      this.logger.warning(err);
      return;
    }
    throw err;
  }

  // Block was orphaned.
  if (!entry) {
    if (this.checkpoints) {
      this.logger.warning(
        'Peer sent orphan block with getheaders (%s).',
        peer.hostname());
      return;
    }

    // During a getblocks sync, peers send
    // their best tip frequently. We can grab
    // the height commitment from the coinbase.
    height = block.getCoinbaseHeight();

    if (height !== -1) {
      peer.bestHash = hash;
      peer.bestHeight = height;
      this.resolveHeight(hash, height);
    }

    this.logger.debug('Peer sent an orphan block. Resolving.');

    yield this.resolveOrphan(peer, hash);

    return;
  }

  if (this.chain.synced) {
    peer.bestHash = entry.hash;
    peer.bestHeight = entry.height;
    this.resolveHeight(entry.hash, entry.height);
  }

  this.logStatus(block);

  yield this.resolveChain(peer, hash);
});

/**
 * Resolve header chain.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Promise}
 */

Pool.prototype.resolveChain = co(function* resolveChain(peer, hash) {
  var node = this.headerChain.head;

  if (!this.checkpoints)
    return;

  if (!peer.loader)
    return;

  if (peer.destroyed)
    throw new Error('Peer was destroyed (header chain resolution).');

  assert(node);

  if (hash !== node.hash) {
    this.logger.warning(
      'Header hash mismatch %s != %s (%s).',
      util.revHex(hash),
      util.revHex(node.hash),
      peer.hostname());

    peer.destroy();

    return;
  }

  if (node.height < this.network.lastCheckpoint) {
    if (node.height === this.headerTip.height) {
      this.logger.info(
        'Received checkpoint %s (%d).',
        util.revHex(node.hash), node.height);

      this.headerTip = this.getNextTip(node.height);

      peer.sendGetHeaders([hash], this.headerTip.hash);

      return;
    }

    this.headerChain.shift();
    this.resolveHeaders(peer);

    return;
  }

  this.logger.info(
    'Switching to getblocks (%s).',
    peer.hostname());

  yield this.switchSync(peer, hash);
});

/**
 * Switch to getblocks.
 * @method
 * @private
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Promise}
 */

Pool.prototype.switchSync = co(function* switchSync(peer, hash) {
  assert(this.checkpoints);

  this.checkpoints = false;
  this.chain.checkpoints = false;
  this.headerTip = null;
  this.headerChain.reset();
  this.headerNext = null;

  yield this.getBlocks(peer, hash);
});

/**
 * Log sync status.
 * @private
 * @param {Block} block
 */

Pool.prototype.logStatus = function logStatus(block) {
  if (this.chain.total % 20 === 0) {
    this.logger.debug('Status:'
      + ' ts=%s height=%d progress=%s'
      + ' blocks=%d orphans=%d active=%d'
      + ' target=%s peers=%d jobs=%d',
      util.date(block.ts),
      this.chain.height,
      (this.chain.getProgress() * 100).toFixed(2) + '%',
      this.chain.total,
      this.chain.orphanCount,
      this.blockMap.size,
      block.bits,
      this.peers.size(),
      this.locker.jobs.length);
  }

  if (this.chain.total % 2000 === 0) {
    this.logger.info(
      'Received 2000 more blocks (height=%d, hash=%s).',
      this.chain.height,
      block.rhash());
  }
};

/**
 * Handle a transaction. Attempt to add to mempool.
 * @method
 * @private
 * @param {Peer} peer
 * @param {TXPacket} packet
 * @returns {Promise}
 */

Pool.prototype.handleTX = co(function* handleTX(peer, packet) {
  var hash = packet.tx.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._handleTX(peer, packet);
  } finally {
    unlock();
  }
});

/**
 * Handle a transaction. Attempt to add to mempool (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {TXPacket} packet
 * @returns {Promise}
 */

Pool.prototype._handleTX = co(function* handleTX(peer, packet) {
  var tx = packet.tx;
  var hash = tx.hash('hex');
  var flags = chainCommon.flags.VERIFY_NONE;
  var block = peer.merkleBlock;
  var missing;

  if (block) {
    assert(peer.merkleMatches > 0);
    assert(peer.merkleMap);

    if (block.hasTX(hash)) {
      if (peer.merkleMap.has(hash)) {
        this.logger.warning(
          'Peer sent duplicate merkle tx: %s (%s).',
          tx.txid(), peer.hostname());
        peer.increaseBan(100);
        return;
      }

      peer.merkleMap.insert(hash);

      block.addTX(tx);

      if (--peer.merkleMatches === 0) {
        peer.merkleBlock = null;
        peer.merkleTime = -1;
        peer.merkleMatches = 0;
        peer.merkleMap = null;
        yield this._addBlock(peer, block, flags);
      }

      return;
    }
  }

  if (!this.resolveTX(peer, hash)) {
    this.logger.warning(
      'Peer sent unrequested tx: %s (%s).',
      tx.txid(), peer.hostname());
    peer.destroy();
    return;
  }

  if (!this.mempool) {
    this.emit('tx', tx);
    return;
  }

  try {
    missing = yield this.mempool.addTX(tx);
  } catch (err) {
    if (err.type === 'VerifyError') {
      peer.reject(tx, err.code, err.reason, err.score);
      this.logger.info(err);
      return;
    }
    throw err;
  }

  if (missing && missing.length > 0) {
    this.logger.debug(
      'Requesting %d missing transactions (%s).',
      missing.length, peer.hostname());

    this.ensureTX(peer, missing);
  }
});

/**
 * Handle peer reject event.
 * @method
 * @private
 * @param {Peer} peer
 * @param {RejectPacket} packet
 */

Pool.prototype.handleReject = co(function* handleReject(peer, packet) {
  var entry;

  this.logger.warning(
    'Received reject (%s): msg=%s code=%s reason=%s hash=%s.',
    peer.hostname(),
    packet.message,
    packet.getCode(),
    packet.reason,
    packet.rhash());

  if (!packet.hash)
    return;

  entry = this.invMap.get(packet.hash);

  if (!entry)
    return;

  entry.handleReject(peer);
});

/**
 * Handle `mempool` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {MempoolPacket} packet
 */

Pool.prototype.handleMempool = co(function* handleMempool(peer, packet) {
  var items = [];
  var i, hash, hashes;

  if (!this.mempool)
    return;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (!this.options.bip37) {
    this.logger.debug(
      'Peer requested mempool without bip37 enabled (%s).',
      peer.hostname());
    peer.destroy();
    return;
  }

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    items.push(new InvItem(invTypes.TX, hash));
  }

  this.logger.debug(
    'Sending mempool snapshot (%s).',
    peer.hostname());

  peer.queueInv(items);
});

/**
 * Handle `filterload` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterLoadPacket} packet
 */

Pool.prototype.handleFilterLoad = co(function* handleFilterLoad(peer, packet) {
  ;
});

/**
 * Handle `filteradd` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterAddPacket} packet
 */

Pool.prototype.handleFilterAdd = co(function* handleFilterAdd(peer, packet) {
  ;
});

/**
 * Handle `filterclear` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FilterClearPacket} packet
 */

Pool.prototype.handleFilterClear = co(function* handleFilterClear(peer, packet) {
  ;
});

/**
 * Handle `merkleblock` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {MerkleBlockPacket} block
 */

Pool.prototype.handleMerkleBlock = co(function* handleMerkleBlock(peer, packet) {
  var hash = packet.block.hash('hex');
  var unlock = yield this.locker.lock(hash);
  try {
    return yield this._handleMerkleBlock(peer, packet);
  } finally {
    unlock();
  }
});

/**
 * Handle `merkleblock` packet (without a lock).
 * @method
 * @private
 * @param {Peer} peer
 * @param {MerkleBlockPacket} block
 */

Pool.prototype._handleMerkleBlock = co(function* handleMerkleBlock(peer, packet) {
  var block = packet.block;
  var hash = block.hash('hex');
  var flags = chainCommon.flags.VERIFY_NONE;

  if (!this.syncing)
    return;

  // Potential DoS.
  if (!this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited merkleblock (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!peer.blockMap.has(hash)) {
    this.logger.warning(
      'Peer sent an unrequested merkleblock (%s).',
      peer.hostname());
    peer.destroy();
    return;
  }

  if (peer.merkleBlock) {
    this.logger.warning(
      'Peer sent a merkleblock prematurely (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!block.verify()) {
    this.logger.warning(
      'Peer sent an invalid merkleblock (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (block.tree.matches.length === 0) {
    yield this._addBlock(peer, block, flags);
    return;
  }

  peer.merkleBlock = block;
  peer.merkleTime = util.ms();
  peer.merkleMatches = block.tree.matches.length;
  peer.merkleMap = new Map();
});

/**
 * Handle `sendcmpct` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {FeeFilterPacket} packet
 */

Pool.prototype.handleFeeFilter = co(function* handleFeeFilter(peer, packet) {
  ;
});

/**
 * Handle `sendcmpct` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {SendCmpctPacket} packet
 */

Pool.prototype.handleSendCmpct = co(function* handleSendCmpct(peer, packet) {
  ;
});

/**
 * Handle `cmpctblock` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {CompactBlockPacket} packet
 */

Pool.prototype.handleCmpctBlock = co(function* handleCmpctBlock(peer, packet) {
  var block = packet.block;
  var hash = block.hash('hex');
  var witness = peer.compactWitness;
  var flags = chainCommon.flags.VERIFY_BODY;
  var result;

  if (!this.syncing)
    return;

  if (!this.options.compact) {
    this.logger.info(
      'Peer sent unsolicited cmpctblock (%s).',
      peer.hostname());
    this.destroy();
    return;
  }

  if (!peer.hasCompactSupport() || !peer.hasCompact()) {
    this.logger.info(
      'Peer sent unsolicited cmpctblock (%s).',
      peer.hostname());
    this.destroy();
    return;
  }

  if (peer.compactBlocks.has(hash)) {
    this.logger.debug(
      'Peer sent us a duplicate compact block (%s).',
      peer.hostname());
    return;
  }

  if (this.compactBlocks.has(hash)) {
    this.logger.debug(
      'Already waiting for compact block %s (%s).',
      hash, peer.hostname());
    return;
  }

  if (!peer.blockMap.has(hash)) {
    if (this.options.blockMode !== 1) {
      this.logger.warning(
        'Peer sent us an unrequested compact block (%s).',
        peer.hostname());
      peer.destroy();
      return;
    }
    peer.blockMap.set(hash, util.ms());
    assert(!this.blockMap.has(hash));
    this.blockMap.insert(hash);
  }

  if (!this.mempool) {
    this.logger.warning('Requesting compact blocks without a mempool!');
    return;
  }

  if (!block.verify()) {
    this.logger.debug(
      'Peer sent an invalid compact block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  try {
    result = block.init();
  } catch (e) {
    this.logger.debug(
      'Peer sent an invalid compact block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  if (!result) {
    this.logger.warning(
      'Siphash collision for %s. Requesting full block (%s).',
      block.rhash(), peer.hostname());
    peer.getFullBlock(hash);
    peer.increaseBan(10);
    return;
  }

  result = block.fillMempool(witness, this.mempool);

  if (result) {
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash(), peer.hostname());
    yield this.addBlock(peer, block.toBlock(), flags);
    return;
  }

  if (this.options.blockMode === 1) {
    if (peer.compactBlocks.size >= 15) {
      this.logger.warning('Compact block DoS attempt (%s).', peer.hostname());
      peer.destroy();
      return;
    }
  }

  block.now = util.ms();

  assert(!peer.compactBlocks.has(hash));
  peer.compactBlocks.set(hash, block);

  this.compactBlocks.insert(hash);

  this.logger.debug(
    'Received non-full compact block %s tx=%d/%d (%s).',
    block.rhash(), block.count, block.totalTX, peer.hostname());

  peer.send(new packets.GetBlockTxnPacket(block.toRequest()));
});

/**
 * Handle `getblocktxn` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {GetBlockTxnPacket} packet
 */

Pool.prototype.handleGetBlockTxn = co(function* handleGetBlockTxn(peer, packet) {
  var req = packet.request;
  var res, item, block, height;

  if (this.chain.options.spv)
    return;

  if (this.chain.options.prune)
    return;

  if (this.options.selfish)
    return;

  item = new InvItem(invTypes.BLOCK, req.hash);

  block = yield this.getItem(peer, item);

  if (!block) {
    this.logger.debug(
      'Peer sent getblocktxn for non-existent block (%s).',
      peer.hostname());
    peer.increaseBan(100);
    return;
  }

  height = yield this.chain.db.getHeight(req.hash);

  if (height < this.chain.tip.height - 15) {
    this.logger.debug(
      'Peer sent a getblocktxn for a block > 15 deep (%s)',
      peer.hostname());
    return;
  }

  this.logger.debug(
    'Sending blocktxn for %s to peer (%s).',
    block.rhash(),
    peer.hostname());

  res = BIP152.TXResponse.fromBlock(block, req);

  peer.send(new packets.BlockTxnPacket(res, peer.compactWitness));
});

/**
 * Handle `blocktxn` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {BlockTxnPacket} packet
 */

Pool.prototype.handleBlockTxn = co(function* handleBlockTxn(peer, packet) {
  var res = packet.response;
  var block = peer.compactBlocks.get(res.hash);
  var flags = chainCommon.flags.VERIFY_BODY;

  if (!block) {
    this.logger.debug(
      'Peer sent unsolicited blocktxn (%s).',
      peer.hostname());
    return;
  }

  peer.compactBlocks.remove(res.hash);

  assert(this.compactBlocks.has(res.hash));
  this.compactBlocks.remove(res.hash);

  if (!block.fillMissing(res)) {
    this.logger.warning(
      'Peer sent non-full blocktxn for %s. Requesting full block (%s).',
      block.rhash(),
      peer.hostname());
    peer.getFullBlock(res.hash);
    peer.increaseBan(10);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash(), peer.hostname());

  yield this.addBlock(peer, block.toBlock(), flags);
});

/**
 * Handle `encinit` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {EncinitPacket} packet
 */

Pool.prototype.handleEncinit = co(function* handleEncinit(peer, packet) {
  ;
});

/**
 * Handle `encack` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {EncackPacket} packet
 */

Pool.prototype.handleEncack = co(function* handleEncack(peer, packet) {
  ;
});

/**
 * Handle `authchallenge` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthChallengePacket} packet
 */

Pool.prototype.handleAuthChallenge = co(function* handleAuthChallenge(peer, packet) {
  ;
});

/**
 * Handle `authreply` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthReplyPacket} packet
 */

Pool.prototype.handleAuthReply = co(function* handleAuthReply(peer, packet) {
  ;
});

/**
 * Handle `authpropose` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {AuthProposePacket} packet
 */

Pool.prototype.handleAuthPropose = co(function* handleAuthPropose(peer, packet) {
  ;
});

/**
 * Handle `unknown` packet.
 * @method
 * @private
 * @param {Peer} peer
 * @param {UnknownPacket} packet
 */

Pool.prototype.handleUnknown = co(function* handleUnknown(peer, packet) {
  this.logger.warning(
    'Unknown packet: %s (%s).',
    packet.cmd, peer.hostname());
});

/**
 * Create an inbound peer from an existing socket.
 * @private
 * @param {net.Socket} socket
 */

Pool.prototype.addInbound = function addInbound(socket) {
  var peer;

  if (!this.loaded) {
    socket.destroy();
    return;
  }

  peer = this.createInbound(socket);

  this.logger.info('Added inbound peer (%s).', peer.hostname());

  this.peers.add(peer);
};

/**
 * Allocate a host from the host list.
 * @returns {NetAddress}
 */

Pool.prototype.getHost = function getHost() {
  var services = this.options.getRequiredServices();
  var now = this.network.now();
  var i, entry, addr;

  for (i = 0; i < this.hosts.nodes.length; i++) {
    addr = this.hosts.nodes[i];

    if (this.peers.has(addr.hostname))
      continue;

    return addr;
  }

  for (i = 0; i < 100; i++) {
    entry = this.hosts.getHost();

    if (!entry)
      break;

    addr = entry.addr;

    if (this.peers.has(addr.hostname))
      continue;

    if (!addr.isValid())
      continue;

    if (!addr.hasServices(services))
      continue;

    if (!this.options.onion && addr.isOnion())
      continue;

    if (i < 30 && now - entry.lastAttempt < 600)
      continue;

    if (i < 50 && addr.port !== this.network.port)
      continue;

    if (i < 95 && this.hosts.isBanned(addr.host))
      continue;

    return entry.addr;
  }
};

/**
 * Create an outbound non-loader peer. These primarily
 * exist for transaction relaying.
 * @private
 */

Pool.prototype.addOutbound = function addOutbound() {
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.outbound >= this.options.maxOutbound)
    return;

  // Hang back if we don't
  // have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this.getHost();

  if (!addr)
    return;

  peer = this.createOutbound(addr);

  this.peers.add(peer);

  this.emit('peer', peer);
};

/**
 * Attempt to refill the pool with peers (no lock).
 * @private
 */

Pool.prototype.fillOutbound = function fillOutbound() {
  var need = this.options.maxOutbound - this.peers.outbound;
  var i;

  if (!this.peers.load)
    this.addLoader();

  if (need <= 0)
    return;

  this.logger.debug('Refilling peers (%d/%d).',
    this.peers.outbound,
    this.options.maxOutbound);

  for (i = 0; i < need; i++)
    this.addOutbound();
};

/**
 * Attempt to refill the pool with peers (no lock).
 * @private
 */

Pool.prototype.refill = function refill() {
  var self = this;

  if (this.pendingRefill != null)
    return;

  this.pendingRefill = setTimeout(function() {
    self.pendingRefill = null;
    self.fillOutbound();
  }, 3000);
};

/**
 * Remove a peer from any list. Drop all load requests.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.removePeer = function removePeer(peer) {
  var i, hashes, hash;

  this.peers.remove(peer);

  hashes = peer.blockMap.keys();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    this.resolveBlock(peer, hash);
  }

  hashes = peer.txMap.keys();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    this.resolveTX(peer, hash);
  }

  hashes = peer.compactBlocks.keys();

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    assert(this.compactBlocks.has(hash));
    this.compactBlocks.remove(hash);
  }

  peer.compactBlocks.reset();
};

/**
 * Ban peer.
 * @param {NetAddress} addr
 */

Pool.prototype.ban = function ban(addr) {
  var peer = this.peers.get(addr.hostname);

  this.logger.debug('Banning peer (%s).', addr.hostname);

  this.hosts.ban(addr.host);
  this.hosts.remove(addr.hostname);

  if (peer)
    peer.destroy();
};

/**
 * Unban peer.
 * @param {NetAddress} addr
 */

Pool.prototype.unban = function unban(addr) {
  this.hosts.unban(addr.host);
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
  this.queueFilterLoad();
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
  this.queueFilterLoad();
};

/**
 * Reset the spv filter (filterload, SPV-only).
 */

Pool.prototype.unwatch = function unwatch() {
  if (!this.options.spv)
    return;

  this.spvFilter.reset();
  this.queueFilterLoad();
};

/**
 * Queue a resend of the bloom filter.
 */

Pool.prototype.queueFilterLoad = function queueFilterLoad() {
  var self = this;

  if (!this.options.spv)
    return;

  if (this.pendingFilter != null)
    return;

  this.pendingFilter = setTimeout(function() {
    self.pendingFilter = null;
    self.sendFilterLoad();
  }, 100);
};

/**
 * Resend the bloom filter to peers.
 */

Pool.prototype.sendFilterLoad = function sendFilterLoad() {
  var peer;

  if (!this.options.spv)
    return;

  assert(this.spvFilter);

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.sendFilterLoad(this.spvFilter);
};

/**
 * Add an address to the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.watchAddress = function watchAddress(address) {
  var hash = Address.getHash(address);
  assert(hash, 'Bad address.');
  this.watch(hash);
};

/**
 * Add an outpoint to the bloom filter (SPV-only).
 * @param {Outpoint} outpoint
 */

Pool.prototype.watchOutpoint = function watchOutpoint(outpoint) {
  this.watch(outpoint.toRaw());
};

/**
 * Send `getblocks` to peer after building
 * locator and resolving orphan root.
 * @method
 * @param {Peer} peer
 * @param {Hash} orphan - Orphan hash to resolve.
 * @returns {Promise}
 */

Pool.prototype.resolveOrphan = co(function* resolveOrphan(peer, orphan) {
  var locator = yield this.chain.getLocator();
  var root = this.chain.getOrphanRoot(orphan);

  assert(root);

  peer.sendGetBlocks(locator, root);
});

/**
 * Send `getheaders` to peer after building locator.
 * @method
 * @param {Peer} peer
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Pool.prototype.getHeaders = co(function* getHeaders(peer, tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  peer.sendGetHeaders(locator, stop);
});

/**
 * Send `getblocks` to peer after building locator.
 * @method
 * @param {Peer} peer
 * @param {Hash} tip - Tip hash to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Pool.prototype.getBlocks = co(function* getBlocks(peer, tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  peer.sendGetBlocks(locator, stop);
});

/**
 * Queue a `getdata` request to be sent.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.getBlock = function getBlock(peer, hashes) {
  var now = util.ms();
  var items = [];
  var i, hash;

  if (!this.loaded)
    return;

  if (!peer.handshake)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is destroyed (getdata).');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (this.blockMap.has(hash))
      continue;

    this.blockMap.insert(hash);
    peer.blockMap.set(hash, now);

    if (this.chain.synced)
      now += 100;

    items.push(hash);
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.blockMap.size,
    peer.hostname());

  peer.getBlock(items);
};

/**
 * Queue a `getdata` request to be sent.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.getTX = function getTX(peer, hashes) {
  var now = util.ms();
  var items = [];
  var i, hash;

  if (!this.loaded)
    return;

  if (!peer.handshake)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is destroyed (getdata).');

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (this.txMap.has(hash))
      continue;

    this.txMap.insert(hash);
    peer.txMap.set(hash, now);

    now += 50;

    items.push(hash);
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Requesting %d/%d txs from peer with getdata (%s).',
    items.length,
    this.txMap.size,
    peer.hostname());

  peer.getTX(items);
};

/**
 * Test whether the chain has or has seen an item.
 * @method
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Pool.prototype.hasBlock = co(function* hasBlock(hash) {
  // Check the lock.
  if (this.locker.has(hash))
    return true;

  // Check the chain.
  if (yield this.chain.has(hash))
    return true;

  return false;
});

/**
 * Test whether the mempool has or has seen an item.
 * @param {Hash} hash
 * @returns {Promise} - Returns Boolean.
 */

Pool.prototype.hasTX = function hasTX(hash) {
  // Check the lock queue.
  if (this.locker.has(hash))
    return true;

  if (!this.mempool) {
    // Check the TX filter if
    // we don't have a mempool.
    if (!this.txFilter.added(hash, 'hex'))
      return true;
  } else {
    // Check the mempool.
    if (this.mempool.has(hash))
      return true;

    // If we recently rejected this item. Ignore.
    if (this.mempool.hasReject(hash)) {
      this.logger.spam('Saw known reject of %s.', util.revHex(hash));
      return true;
    }
  }

  return false;
};

/**
 * Queue a `getdata` request to be sent.
 * Check tx existence before requesting.
 * @param {Peer} peer
 * @param {Hash[]} hashes
 */

Pool.prototype.ensureTX = function ensureTX(peer, hashes) {
  var items = [];
  var i, hash;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (this.hasTX(hash))
      continue;

    items.push(hash);
  }

  this.getTX(peer, items);
};

/**
 * Fulfill a requested tx.
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.resolveTX = function resolveTX(peer, hash) {
  if (!peer.txMap.has(hash))
    return false;

  peer.txMap.remove(hash);

  assert(this.txMap.has(hash));
  this.txMap.remove(hash);

  return true;
};

/**
 * Fulfill a requested block.
 * @param {Peer} peer
 * @param {Hash} hash
 * @returns {Boolean}
 */

Pool.prototype.resolveBlock = function resolveBlock(peer, hash) {
  if (!peer.blockMap.has(hash))
    return false;

  peer.blockMap.remove(hash);

  assert(this.blockMap.has(hash));
  this.blockMap.remove(hash);

  return true;
};

/**
 * Fulfill a requested item.
 * @param {Peer} peer
 * @param {InvItem} item
 * @returns {Boolean}
 */

Pool.prototype.resolveItem = function resolveItem(peer, item) {
  if (item.isBlock())
    return this.resolveBlock(peer, item.hash);

  if (item.isTX())
    return this.resolveTX(peer, item.hash);

  return false;
};

/**
 * Broadcast a transaction or block.
 * @param {TX|Block} msg
 * @returns {Promise}
 */

Pool.prototype.broadcast = function broadcast(msg) {
  var hash = msg.hash('hex');
  var item = this.invMap.get(hash);

  if (item) {
    item.refresh();
    item.announce();
  } else {
    item = new BroadcastItem(this, msg);
    item.start();
    item.announce();
  }

  return new Promise(function(resolve, reject) {
    item.addJob(resolve, reject);
  });
};

/**
 * Announce a block to all peers.
 * @param {Block} tx
 */

Pool.prototype.announceBlock = function announceBlock(msg) {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.announceBlock(msg);
};

/**
 * Announce a transaction to all peers.
 * @param {TX} tx
 */

Pool.prototype.announceTX = function announceTX(msg) {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.announceTX(msg);
};

/**
 * Attempt to retrieve external IP from icanhazip.com.
 * @method
 * @returns {Promise}
 */

Pool.prototype.getIP = co(function* getIP() {
  var res, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  try {
    res = yield request({
      method: 'GET',
      uri: 'http://icanhazip.com',
      expect: 'txt',
      timeout: 2000
    });
  } catch (e) {
    return yield this.getIP2();
  }

  ip = res.body.trim();

  try {
    ip = IP.normalize(ip);
  } catch (e) {
    return yield this.getIP2();
  }

  return ip;
});

/**
 * Attempt to retrieve external IP from dyndns.org.
 * @method
 * @returns {Promise}
 */

Pool.prototype.getIP2 = co(function* getIP2() {
  var res, match, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  res = yield request({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 2000
  });

  match = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!match)
    throw new Error('Could not find IP.');

  ip = match[1];

  return IP.normalize(ip);
});

/**
 * PoolOptions
 * @alias module:net.PoolOptions
 * @constructor
 */

function PoolOptions(options) {
  if (!(this instanceof PoolOptions))
    return new PoolOptions(options);

  this.network = Network.primary;
  this.logger = null;
  this.chain = null;
  this.mempool = null;

  this.nonces = new NonceList();

  this.prefix = null;
  this.checkpoints = true;
  this.spv = false;
  this.bip37 = false;
  this.listen = false;
  this.compact = true;
  this.noRelay = false;
  this.host = '0.0.0.0';
  this.port = this.network.port;
  this.publicHost = '0.0.0.0';
  this.publicPort = this.network.port;
  this.maxOutbound = 8;
  this.maxInbound = 8;
  this.createSocket = this._createSocket.bind(this);
  this.createServer = tcp.createServer;
  this.resolve = this._resolve.bind(this);
  this.proxy = null;
  this.onion = false;
  this.upnp = false;
  this.selfish = false;
  this.version = common.PROTOCOL_VERSION;
  this.agent = common.USER_AGENT;
  this.bip151 = false;
  this.bip150 = false;
  this.authPeers = [];
  this.knownPeers = {};
  this.identityKey = ec.generatePrivateKey();
  this.banScore = common.BAN_SCORE;
  this.banTime = common.BAN_TIME;
  this.feeRate = -1;
  this.seeds = this.network.seeds;
  this.nodes = [];
  this.invTimeout = 60000;
  this.blockMode = 0;
  this.services = common.LOCAL_SERVICES;
  this.requiredServices = common.REQUIRED_SERVICES;
  this.persistent = false;

  this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {PoolOptions}
 */

PoolOptions.prototype.fromOptions = function fromOptions(options) {
  var raw;

  assert(options, 'Pool requires options.');
  assert(options.chain && typeof options.chain === 'object',
    'Pool options require a blockchain.');

  this.chain = options.chain;
  this.network = options.chain.network;
  this.logger = options.chain.logger;

  this.port = this.network.port;
  this.seeds = this.network.seeds;
  this.port = this.network.port;
  this.publicPort = this.network.port;

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.mempool != null) {
    assert(typeof options.mempool === 'object');
    this.mempool = options.mempool;
  }

  if (options.prefix != null) {
    assert(typeof options.prefix === 'string');
    this.prefix = options.prefix;
  }

  if (options.checkpoints != null) {
    assert(typeof options.checkpoints === 'boolean');
    assert(options.checkpoints === this.chain.options.checkpoints);
    this.checkpoints = options.checkpoints;
  } else {
    this.checkpoints = this.chain.options.checkpoints;
  }

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    assert(options.spv === this.chain.options.spv);
    this.spv = options.spv;
  } else {
    this.spv = this.chain.options.spv;
  }

  if (options.bip37 != null) {
    assert(typeof options.bip37 === 'boolean');
    this.bip37 = options.bip37;
  }

  if (options.listen != null) {
    assert(typeof options.listen === 'boolean');
    this.listen = options.listen;
  }

  if (options.compact != null) {
    assert(typeof options.compact === 'boolean');
    this.compact = options.compact;
  }

  if (options.noRelay != null) {
    assert(typeof options.noRelay === 'boolean');
    this.noRelay = options.noRelay;
  }

  if (options.host != null) {
    assert(typeof options.host === 'string');
    raw = IP.toBuffer(options.host);
    this.host = IP.toString(raw);
    if (IP.isRoutable(raw))
      this.publicHost = this.host;
  }

  if (options.port != null) {
    assert(typeof options.port === 'number');
    assert(options.port > 0 && options.port <= 0xffff);
    this.port = options.port;
    this.publicPort = options.port;
  }

  if (options.publicHost != null) {
    assert(typeof options.publicHost === 'string');
    this.publicHost = IP.normalize(options.publicHost);
  }

  if (options.publicPort != null) {
    assert(typeof options.publicPort === 'number');
    assert(options.publicPort > 0 && options.publicPort <= 0xffff);
    this.publicPort = options.publicPort;
  }

  if (options.maxOutbound != null) {
    assert(typeof options.maxOutbound === 'number');
    assert(options.maxOutbound > 0);
    this.maxOutbound = options.maxOutbound;
  }

  if (options.maxInbound != null) {
    assert(typeof options.maxInbound === 'number');
    this.maxInbound = options.maxInbound;
  }

  if (options.createSocket) {
    assert(typeof options.createSocket === 'function');
    this.createSocket = options.createSocket;
  }

  if (options.createServer) {
    assert(typeof options.createServer === 'function');
    this.createServer = options.createServer;
  }

  if (options.resolve) {
    assert(typeof options.resolve === 'function');
    this.resolve = options.resolve;
  }

  if (options.proxy) {
    assert(typeof options.proxy === 'string');
    this.proxy = options.proxy;
  }

  if (options.onion != null) {
    assert(typeof options.onion === 'boolean');
    this.onion = options.onion;
  }

  if (options.upnp != null) {
    assert(typeof options.upnp === 'boolean');
    this.upnp = options.upnp;
  }

  if (options.selfish) {
    assert(typeof options.selfish === 'boolean');
    this.selfish = options.selfish;
  }

  if (options.version) {
    assert(typeof options.version === 'number');
    this.version = options.version;
  }

  if (options.agent) {
    assert(typeof options.agent === 'string');
    assert(options.agent.length <= 255);
    this.agent = options.agent;
  }

  if (options.bip151 != null) {
    assert(typeof options.bip151 === 'boolean');
    this.bip151 = options.bip151;
  }

  if (options.bip150 != null) {
    assert(typeof options.bip150 === 'boolean');
    assert(this.bip151, 'Cannot enable bip150 without bip151.');

    if (options.knownPeers) {
      assert(typeof options.knownPeers === 'object');
      assert(!Array.isArray(options.knownPeers));
      this.knownPeers = options.knownPeers;
    }

    if (options.authPeers) {
      assert(Array.isArray(options.authPeers));
      this.authPeers = options.authPeers;
    }

    if (options.identityKey) {
      assert(Buffer.isBuffer(options.identityKey),
        'Identity key must be a buffer.');
      assert(ec.privateKeyVerify(options.identityKey),
        'Invalid identity key.');
      this.identityKey = options.identityKey;
    }
  }

  if (options.banScore != null) {
    assert(typeof this.options.banScore === 'number');
    this.banScore = this.options.banScore;
  }

  if (options.banTime != null) {
    assert(typeof this.options.banTime === 'number');
    this.banTime = this.options.banTime;
  }

  if (options.feeRate != null) {
    assert(typeof this.options.feeRate === 'number');
    this.feeRate = this.options.feeRate;
  }

  if (options.seeds) {
    assert(Array.isArray(options.seeds));
    this.seeds = options.seeds;
  }

  if (options.nodes) {
    assert(Array.isArray(options.nodes));
    this.nodes = options.nodes;
  }

  if (options.invTimeout != null) {
    assert(typeof options.invTimeout === 'number');
    this.invTimeout = options.invTimeout;
  }

  if (options.blockMode != null) {
    assert(typeof options.blockMode === 'number');
    this.blockMode = options.blockMode;
  }

  if (options.persistent != null) {
    assert(typeof options.persistent === 'boolean');
    this.persistent = options.persistent;
  }

  if (this.spv) {
    this.requiredServices |= common.services.BLOOM;
    this.services &= ~common.services.NETWORK;
    this.noRelay = true;
    this.checkpoints = true;
    this.compact = false;
    this.bip37 = false;
    this.listen = false;
  }

  if (this.selfish) {
    this.services &= ~common.services.NETWORK;
    this.bip37 = false;
  }

  if (this.bip37)
    this.services |= common.services.BLOOM;

  if (this.proxy)
    this.listen = false;

  if (options.services != null) {
    assert(util.isUInt32(options.services));
    this.services = options.services;
  }

  if (options.requiredServices != null) {
    assert(util.isUInt32(options.requiredServices));
    this.requiredServices = options.requiredServices;
  }

  return this;
};

/**
 * Instantiate options from object.
 * @param {Object} options
 * @returns {PoolOptions}
 */

PoolOptions.fromOptions = function fromOptions(options) {
  return new PoolOptions().fromOptions(options);
};

/**
 * Get the chain height.
 * @private
 * @returns {Number}
 */

PoolOptions.prototype.getHeight = function getHeight() {
  return this.chain.height;
};

/**
 * Test whether the chain is synced.
 * @private
 * @returns {Boolean}
 */

PoolOptions.prototype.isFull = function isFull() {
  return this.chain.synced;
};

/**
 * Get required services for outbound peers.
 * @private
 * @returns {Number}
 */

PoolOptions.prototype.getRequiredServices = function getRequiredServices() {
  var services = this.requiredServices;
  if (this.hasWitness())
    services |= common.services.WITNESS;
  return services;
};

/**
 * Whether segwit is enabled.
 * @private
 * @returns {Boolean}
 */

PoolOptions.prototype.hasWitness = function hasWitness() {
  return this.chain.state.hasWitness();
};

/**
 * Create a version packet nonce.
 * @private
 * @param {String} hostname
 * @returns {Buffer}
 */

PoolOptions.prototype.createNonce = function createNonce(hostname) {
  return this.nonces.alloc(hostname);
};

/**
 * Test whether version nonce is ours.
 * @private
 * @param {Buffer} nonce
 * @returns {Boolean}
 */

PoolOptions.prototype.hasNonce = function hasNonce(nonce) {
  return this.nonces.has(nonce);
};

/**
 * Get fee rate for txid.
 * @private
 * @param {Hash} hash
 * @returns {Rate}
 */

PoolOptions.prototype.getRate = function getRate(hash) {
  var entry;

  if (!this.mempool)
    return -1;

  entry = this.mempool.getEntry(hash);

  if (!entry)
    return -1;

  return entry.getRate();
};

/**
 * Default createSocket call.
 * @private
 * @param {Number} port
 * @param {String} host
 * @returns {net.Socket}
 */

PoolOptions.prototype._createSocket = function createSocket(port, host) {
  return tcp.createSocket(port, host, this.proxy);
};

/**
 * Default resolve call.
 * @private
 * @param {String} name
 * @returns {String[]}
 */

PoolOptions.prototype._resolve = function resolve(name) {
  if (this.onion)
    return dns.lookup(name, this.proxy);

  return dns.lookup(name);
};

/**
 * Peer List
 * @alias module:net.PeerList
 * @constructor
 * @param {Object} options
 */

function PeerList() {
  this.map = {};
  this.list = new List();
  this.load = null;
  this.inbound = 0;
  this.outbound = 0;
}

/**
 * Get the list head.
 * @returns {Peer}
 */

PeerList.prototype.head = function head() {
  return this.list.head;
};

/**
 * Get the list tail.
 * @returns {Peer}
 */

PeerList.prototype.tail = function tail() {
  return this.list.tail;
};

/**
 * Get list size.
 * @returns {Number}
 */

PeerList.prototype.size = function size() {
  return this.list.size;
};

/**
 * Add peer to list.
 * @param {Peer} peer
 */

PeerList.prototype.add = function add(peer) {
  assert(this.list.push(peer));

  assert(!this.map[peer.hostname()]);
  this.map[peer.hostname()] = peer;

  if (peer.outbound)
    this.outbound++;
  else
    this.inbound++;
};

/**
 * Remove peer from list.
 * @param {Peer} peer
 */

PeerList.prototype.remove = function remove(peer) {
  assert(this.list.remove(peer));

  assert(this.map[peer.hostname()]);
  delete this.map[peer.hostname()];

  if (peer === this.load) {
    assert(peer.loader);
    peer.loader = false;
    this.load = null;
  }

  if (peer.outbound)
    this.outbound--;
  else
    this.inbound--;
};

/**
 * Get peer by hostname.
 * @param {String} hostname
 * @returns {Peer}
 */

PeerList.prototype.get = function get(hostname) {
  return this.map[hostname];
};

/**
 * Test whether a peer exists.
 * @param {String} hostname
 * @returns {Boolean}
 */

PeerList.prototype.has = function has(hostname) {
  return this.map[hostname] != null;
};

/**
 * Destroy peer list (kills peers).
 */

PeerList.prototype.destroy = function destroy() {
  var peer, next;

  for (peer = this.list.head; peer; peer = next) {
    next = peer.next;
    peer.destroy();
  }
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @alias module:net.BroadcastItem
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {TX|Block} msg
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

function BroadcastItem(pool, msg) {
  var item;

  if (!(this instanceof BroadcastItem))
    return new BroadcastItem(pool, msg);

  assert(!msg.mutable, 'Cannot broadcast mutable item.');

  item = msg.toInv();

  this.pool = pool;
  this.hash = item.hash;
  this.type = item.type;
  this.msg = msg;
  this.jobs = [];
}

util.inherits(BroadcastItem, EventEmitter);

/**
 * Add a job to be executed on ack, timeout, or reject.
 * @returns {Promise}
 */

BroadcastItem.prototype.addJob = function addJob(resolve, reject) {
  this.jobs.push(co.job(resolve, reject));
};

/**
 * Start the broadcast.
 */

BroadcastItem.prototype.start = function start() {
  assert(!this.timeout, 'Already started.');
  assert(!this.pool.invMap.has(this.hash), 'Already started.');

  this.pool.invMap.set(this.hash, this);

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
    self.reject(new Error('Timed out.'));
  }, this.pool.options.invTimeout);
};

/**
 * Announce the item.
 */

BroadcastItem.prototype.announce = function announce() {
  switch (this.type) {
    case invTypes.TX:
      this.pool.announceTX(this.msg);
      break;
    case invTypes.BLOCK:
      this.pool.announceBlock(this.msg);
      break;
    default:
      assert(false, 'Bad type.');
      break;
  }
};

/**
 * Finish the broadcast.
 */

BroadcastItem.prototype.cleanup = function cleanup() {
  assert(this.timeout != null, 'Already finished.');
  assert(this.pool.invMap.has(this.hash), 'Already finished.');

  clearTimeout(this.timeout);
  this.timeout = null;

  this.pool.invMap.remove(this.hash);
};

/**
 * Finish the broadcast, return with an error.
 * @param {Error} err
 */

BroadcastItem.prototype.reject = function reject(err) {
  var i, job;

  this.cleanup();

  for (i = 0; i < this.jobs.length; i++) {
    job = this.jobs[i];
    job.reject(err);
  }

  this.jobs.length = 0;
};

/**
 * Finish the broadcast successfully.
 */

BroadcastItem.prototype.resolve = function resolve() {
  var i, job;

  this.cleanup();

  for (i = 0; i < this.jobs.length; i++) {
    job = this.jobs[i];
    job.resolve(false);
  }

  this.jobs.length = 0;
};

/**
 * Handle an ack from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.handleAck = function handleAck(peer) {
  var self = this;
  var i, job;

  setTimeout(function() {
    self.emit('ack', peer);

    for (i = 0; i < self.jobs.length; i++) {
      job = self.jobs[i];
      job.resolve(true);
    }

    self.jobs.length = 0;
  }, 1000);
};

/**
 * Handle a reject from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.handleReject = function handleReject(peer) {
  var i, job;

  this.emit('reject', peer);

  for (i = 0; i < this.jobs.length; i++) {
    job = this.jobs[i];
    job.resolve(false);
  }

  this.jobs.length = 0;
};

/**
 * Inspect the broadcast item.
 * @returns {String}
 */

BroadcastItem.prototype.inspect = function inspect() {
  return '<BroadcastItem:'
    + ' type=' + (this.type === invTypes.TX ? 'tx' : 'block')
    + ' hash=' + util.revHex(this.hash)
    + '>';
};

/**
 * NonceList
 * @constructor
 * @ignore
 */

function NonceList() {
  this.map = {};
  this.hosts = {};
}

NonceList.prototype.alloc = function alloc(hostname) {
  var nonce, key;

  for (;;) {
    nonce = util.nonce();
    key = nonce.toString('hex');
    if (!this.map[key]) {
      this.map[key] = hostname;
      assert(!this.hosts[hostname]);
      this.hosts[hostname] = key;
      break;
    }
  }

  return nonce;
};

NonceList.prototype.has = function has(nonce) {
  var key = nonce.toString('hex');
  return this.map[key] != null;
};

NonceList.prototype.remove = function remove(hostname) {
  var key = this.hosts[hostname];

  if (!key)
    return false;

  delete this.hosts[hostname];

  assert(this.map[key]);
  delete this.map[key];

  return true;
};

/**
 * HeaderEntry
 * @constructor
 * @ignore
 */

function HeaderEntry(hash, height) {
  this.hash = hash;
  this.height = height;
  this.prev = null;
  this.next = null;
}

/*
 * Expose
 */

module.exports = Pool;
