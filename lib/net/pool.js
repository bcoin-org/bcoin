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
var NetAddress = require('../primitives/netaddress');
var Address = require('../primitives/address');
var BIP150 = require('./bip150');
var Bloom = require('../utils/bloom');
var ec = require('../crypto/ec');
var InvItem = require('../primitives/invitem');
var Locker = require('../utils/locker');
var Network = require('../protocol/network');
var Peer = require('./peer');
var request = require('../http/request');
var List = require('../utils/list');
var tcp = require('./tcp');
var dns = require('./dns');
var murmur3 = require('../utils/murmur3');
var StaticWriter = require('../utils/staticwriter');
var invTypes = constants.inv;
var VerifyError = errors.VerifyError;
var VerifyResult = errors.VerifyResult;

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

  this.server = null;
  this.maxOutbound = 8;
  this.maxInbound = 8;
  this.connected = false;
  this.uid = 0;
  this.createSocket = tcp.createSocket;
  this.createServer = tcp.createServer;
  this.resolve = dns.resolve;
  this.locker = new Locker();
  this.proxyServer = null;
  this.auth = null;
  this.identityKey = null;
  this.banTime = constants.BAN_TIME;
  this.banScore = constants.BAN_SCORE;

  // Required services.
  this.needed = constants.services.NETWORK;
  this.needed |= constants.services.WITNESS;

  this.syncing = false;

  this.loadTimeout = 120000;

  this.feeRate = -1;

  this.address = new NetAddress();
  this.address.ts = this.network.now();
  this.address.services = constants.LOCAL_SERVICES;
  this.address.setPort(this.network.port);

  this.hosts = new HostList(this);
  this.peers = new PeerList(this);

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
  this.invItems = new List();
  this.invTimeout = 60000;

  this.scheduled = false;
  this.pendingWatch = null;
  this.timeout = null;
  this.interval = null;

  this._onTimeout = this.onTimeout.bind(this);
  this._onInterval = this.onInterval.bind(this);

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

  if (!this.options.witness) {
    this.address.services &= ~constants.services.WITNESS;
    this.needed &= ~constants.services.WITNESS;
  }

  if (this.options.host != null) {
    assert(typeof this.options.host === 'string');
    this.address.setHost(this.options.host);
  }

  if (this.options.port != null) {
    assert(typeof this.options.port === 'number');
    this.address.setPort(this.options.port);
  }

  if (this.options.maxOutbound != null) {
    assert(typeof this.options.maxOutbound === 'number');
    this.maxOutbound = this.options.maxOutbound;
  }

  if (this.options.maxInbound != null) {
    assert(typeof this.options.maxInbound === 'number');
    this.maxInbound = this.options.maxInbound;
  }

  if (this.options.createSocket) {
    assert(typeof this.options.createSocket === 'function');
    this.createSocket = this.options.createSocket;
  }

  if (this.options.createServer) {
    assert(typeof this.options.createServer === 'function');
    this.createServer = this.options.createServer;
  }

  if (this.options.resolve) {
    assert(typeof this.options.resolve === 'function');
    this.resolve = this.options.resolve;
  }

  if (this.options.proxyServer) {
    assert(typeof this.options.proxyServer === 'string');
    this.proxyServer = this.options.proxyServer;
  }

  if (this.options.bip150) {
    assert(typeof this.options.bip151 === 'boolean');

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

  if (this.options.banScore != null) {
    assert(typeof this.options.banScore === 'number');
    this.banScore = this.options.banScore;
  }

  if (this.options.banTime != null) {
    assert(typeof this.options.banTime === 'number');
    this.banTime = this.options.banTime;
  }

  if (this.options.loadTimeout != null) {
    assert(typeof this.options.loadTimeout === 'number');
    this.loadTimeout = this.options.loadTimeout;
  }

  if (this.options.feeRate != null) {
    assert(typeof this.options.feeRate === 'number');
    this.feeRate = this.options.feeRate;
  }

  if (this.options.seeds)
    this.hosts.setSeeds(this.options.seeds);

  if (this.options.preferredSeed)
    this.hosts.setSeeds([this.options.preferredSeed]);

  if (this.options.spv) {
    this.spvFilter = Bloom.fromRate(10000, 0.001, constants.bloom.ALL);
    this.needed |= constants.services.BLOOM;
  }

  if (!this.options.mempool)
    this.txFilter = new Bloom.Rolling(50000, 0.000001);

  if (this.options.requestTimeout != null) {
    assert(typeof this.options.requestTimeout === 'number');
    this.requestTimeout = this.options.requestTimeout;
  }

  if (this.options.invTimeout != null) {
    assert(typeof this.options.invTimeout === 'number');
    this.invTimeout = this.options.invTimeout;
  }
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
 * @alias Pool#open
 * @returns {Promise}
 */

Pool.prototype._open = co(function* _open() {
  var key;

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
  var i, next, item, hashes, hash;

  this.stopSync();

  for (item = this.invItems.head; item; item = next) {
    next = item.next;
    item.finish();
  }

  hashes = Object.keys(this.requestMap);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.requestMap[hash];
    item.finish(new Error('Pool closed.'));
  }

  this.peers.destroy();
  this.hosts.reset();

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
 * @returns {Promise}
 */

Pool.prototype._connect = co(function* connect() {
  var ip;

  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  if (this.address.isNull()) {
    try {
      ip = yield this.getIP();
    } catch (e) {
      this.logger.error(e);
    }
    if (ip) {
      this.address.setHost(ip);
      this.logger.info('External IP found: %s.', ip);
    }
  }

  yield this.hosts.discover();

  if (this.hosts.size() === 0)
    throw new Error('No hosts available. Do you have an internet connection?');

  this.logger.info('Resolved %d hosts from DNS seeds.', this.hosts.size());

  this.addLoader();

  this.connected = true;
});

/**
 * Start listening on a server socket.
 * @returns {Promise}
 */

Pool.prototype.listen = function listen() {
  var self = this;

  if (this.server)
    return Promise.resolve();

  if (!this.createServer)
    return;

  this.server = this.createServer();

  this.server.on('connection', function(socket) {
    self.handleInbound(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    self.logger.info(
      'Pool server listening on %s (port=%d).',
      data.address, data.port);
  });

  return new Promise(function(resolve, reject) {
    self.server.listen(self.address.port, '0.0.0.0', co.wrap(resolve, reject));
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

Pool.prototype.handleInbound = function handleInbound(socket) {
  var host;

  if (!socket.remoteAddress) {
    this.logger.debug('Ignoring disconnected leech.');
    socket.destroy();
    return;
  }

  host = IP.normalize(socket.remoteAddress);

  if (this.peers.inbound >= this.maxInbound) {
    this.logger.debug('Ignoring leech: too many inbound (%s).', host);
    socket.destroy();
    return;
  }

  if (this.hosts.isBanned(host)) {
    this.logger.debug('Ignoring banned leech (%s).', host);
    socket.destroy();
    return;
  }

  host = IP.hostname(host, socket.remotePort);

  assert(!this.peers.map[host], 'Port collision.');

  this.addInbound(socket);
};

/**
 * Start timeout to detect stalling.
 * @private
 */

Pool.prototype.startTimeout = function startTimeout() {
  this.stopTimeout();
  this.timeout = setTimeout(this._onTimeout, this.loadTimeout);
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
 * Potentially kill a stalling peer.
 * @private
 */

Pool.prototype.onTimeout = function onTimeout() {
  if (!this.syncing)
    return;

  if (this.chain.synced)
    return;

  if (this.peers.load) {
    this.peers.load.destroy();
    this.logger.debug('Timer ran out. Finding new loader peer.');
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
  this.stopInterval();
  this.interval = setInterval(this._onInterval, this.loadTimeout / 6 | 0);
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
 * Warn that the loader peer is stalling.
 * @private
 */

Pool.prototype.onInterval = function onInterval() {
  var peer = this.peers.load;
  var hostname = peer ? peer.hostname : null;

  if (!this.syncing)
    return;

  if (this.chain.synced)
    return this.stopInterval();

  if (this.chain.isBusy())
    return this.startTimeout();

  this.logger.warning('Loader peer is stalling (%s).', hostname);
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

  if (this.peers.load) {
    this.fillPeers();
    return;
  }

  addr = this.getHost(false);

  if (!addr)
    return;

  peer = this.peers.get(addr.hostname);

  if (peer) {
    this.logger.info('Repurposing peer for loader (%s).', peer.hostname);
    this.setLoader(peer);
    return;
  }

  peer = this.createPeer(addr);

  this.logger.info('Setting loader peer (%s).', peer.hostname);

  this.peers.add(peer);

  this.setLoader(peer);
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

  assert(peer.outbound);
  this.peers.load = peer;

  this.fillPeers();

  peer.sync();

  util.nextTick(function() {
    self.emit('loader', peer);
  });
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = co(function* startSync() {
  this.syncing = true;

  this.startInterval();
  this.startTimeout();

  yield this.connect();

  if (!this.peers.load) {
    this.addLoader();
    return;
  }

  this.sync();
});

/**
 * Send a sync to each peer.
 * @private
 */

Pool.prototype.sync = function sync() {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;
    peer.sync();
  }
};

/**
 * Force sending a sync to each peer.
 * @private
 */

Pool.prototype.forceSync = function forceSync() {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;
    peer.syncSent = false;
    peer.sync();
  }
};

/**
 * Stop the blockchain sync.
 */

Pool.prototype.stopSync = co(function* stopSync() {
  var peer;

  if (!this.syncing)
    return;

  this.syncing = false;

  if (!this.loaded)
    return;

  this.stopInterval();
  this.stopTimeout();

  for (peer = this.peers.head(); peer; peer = peer.next) {
    if (!peer.outbound)
      continue;
    peer.syncSent = false;
  }
});

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
 * Send `alert` to all peers.
 * @param {AlertPacket} alert
 */

Pool.prototype.sendAlert = function sendAlert(alert) {
  var peer;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.sendAlert(alert);
};

/**
 * Create a base peer with no special purpose.
 * @private
 * @param {Number} port
 * @param {String} host
 * @returns {Peer}
 */

Pool.prototype.createPeer = function createPeer(addr) {
  var peer = new Peer(this);

  this.bindPeer(peer);

  peer.connect(addr);
  peer.tryOpen();

  return peer;
};

/**
 * Accept an inbound socket.
 * @private
 * @param {net.Socket} socket
 * @returns {Peer}
 */

Pool.prototype.acceptPeer = function acceptPeer(socket) {
  var peer = new Peer(this);

  this.bindPeer(peer);

  peer.accept(socket);
  peer.tryOpen();

  return peer;
};

/**
 * Bind to peer events.
 * @private
 */

Pool.prototype.bindPeer = function bindPeer(peer) {
  var self = this;

  peer.once('open', function() {
    self.handleOpen(peer);
  });

  peer.once('close', function() {
    self.handleClose(peer);
  });

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('version', function(version) {
    self.handleVersion(version, peer);
  });

  peer.on('addr', function(addrs) {
    self.handleAddr(addrs, peer);
  });

  peer.on('merkleblock', co(function* (block) {
    if (!self.options.spv)
      return;

    try {
      yield self.handleBlock(block, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('block', co(function* (block) {
    if (self.options.spv)
      return;

    try {
      yield self.handleBlock(block, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('tx', co(function* (tx) {
    try {
      yield self.handleTX(tx, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('headers', co(function* (headers) {
    try {
      yield self.handleHeaders(headers, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('blocks', co(function* (hashes) {
    try {
      yield self.handleBlockInv(hashes, peer);
    } catch (e) {
      self.emit('error', e);
    }
  }));

  peer.on('txs', function(hashes) {
    self.handleTXInv(hashes, peer);
  });

  peer.on('reject', function(reject) {
    self.handleReject(reject, peer);
  });

  peer.on('notfound', function(items) {
    self.handleNotFound(items, peer);
  });

  peer.on('alert', function(alert) {
    self.handleAlert(alert, peer);
  });
};

/**
 * Handle peer open event.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleOpen = function handleOpen(peer) {
  if (!peer.outbound)
    return;

  // If we don't have an ack'd loader yet, use this peer.
  if (!this.peers.load || !this.peers.load.ack)
    this.setLoader(peer);
};

/**
 * Handle peer close event.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.handleClose = function handleClose(peer) {
  var self = this;

  if (!this.loaded) {
    this.removePeer(peer);
    return;
  }

  if (this.peers.outbound === 0) {
    this.logger.warning('%s %s %s',
      'Could not connect to any peers.',
      'Do you have a network connection?',
      'Retrying in 5 seconds.');
    setTimeout(function() {
      self.addLoader();
    }, 5000);
  }

  if (!peer.isLoader()) {
    this.removePeer(peer);
    this.fillPeers();
    return;
  }

  this.removePeer(peer);
  this.stopInterval();
  this.stopTimeout();

  this.addLoader();
};

/**
 * Handle peer version event.
 * @private
 * @param {VersionPacket} version
 * @param {Peer} peer
 */

Pool.prototype.handleVersion = function handleVersion(version, peer) {
  this.logger.info(
    'Received version (%s): version=%d height=%d services=%s agent=%s',
    peer.hostname,
    version.version,
    version.height,
    version.services.toString(2),
    version.agent);

  this.network.time.add(peer.hostname, version.ts);

  this.emit('version', version, peer);
};

/**
 * Handle peer addr event.
 * @private
 * @param {NetAddress[]} addrs
 * @param {Peer} peer
 */

Pool.prototype.handleAddr = function handleAddr(addrs, peer) {
  var i, addr;

  if (this.options.ignoreDiscovery)
    return;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    if (!addr.isRoutable())
      continue;

    if (!addr.hasServices(this.needed))
      continue;

    if (this.hosts.add(addr, peer.address))
      this.emit('host', addr, peer);
  }

  this.emit('addr', addrs, peer);
  this.fillPeers();
};

/**
 * Handle `block` packet. Attempt to add to chain.
 * @private
 * @param {MemBlock|MerkleBlock} block
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.handleBlock = co(function* handleBlock(block, peer) {
  var requested;

  if (!this.syncing)
    return;

  requested = this.fulfill(block);

  // Someone is sending us blocks without
  // us requesting them.
  if (!requested) {
    peer.invFilter.add(block.hash());
    this.logger.warning(
      'Received unrequested block: %s (%s).',
      block.rhash(), peer.hostname);
    return;
  }

  try {
    yield this.chain.add(block);
  } catch (err) {
    if (err.type !== 'VerifyError') {
      this.scheduleRequests(peer);
      throw err;
    }

    peer.reject(block, err.code, err.reason, err.score);

    if (err.reason === 'bad-prevblk') {
      if (this.options.headers) {
        peer.increaseBan(10);
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

  // If the peer sent us a block that was added
  // to the chain (not orphans), reset the timeout.
  if (peer.isLoader()) {
    this.startInterval();
    this.startTimeout();
  }

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
      this.chain.orphanCount,
      this.activeBlocks,
      peer.queueBlock.size,
      block.bits,
      this.peers.size(),
      this.chain.locker.pending,
      this.chain.locker.jobs.length);
  }

  if (this.chain.total % 2000 === 0) {
    this.logger.info(
      'Received 2000 more blocks (height=%d, hash=%s).',
      this.chain.height,
      block.rhash());
  }
});


/**
 * Handle a transaction. Attempt to add to mempool.
 * @private
 * @param {TX} tx
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.handleTX = co(function* handleTX(tx, peer) {
  var requested = this.fulfill(tx);
  var i, missing;

  if (!requested) {
    peer.invFilter.add(tx.hash());

    if (!this.mempool)
      this.txFilter.add(tx.hash());

    this.logger.warning('Peer sent unrequested tx: %s (%s).',
      tx.txid(), peer.hostname);

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
    if (err.type === 'VerifyError')
      peer.reject(tx, err.code, err.reason, err.score);
    throw err;
  }

  if (missing) {
    this.logger.debug(
      'Requesting %d missing transactions (%s).',
      missing.length, peer.hostname);

    try {
      for (i = 0; i < missing.length; i++)
        this.getTX(peer, missing[i]);
    } catch (e) {
      this.emit('error', e);
    }

    this.scheduleRequests(peer);
  }

  this.emit('tx', tx, peer);
});

/**
 * Handle `headers` packet from a given peer.
 * @private
 * @param {Headers[]} headers
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.handleHeaders = co(function* handleHeaders(headers, peer) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._handleHeaders(headers, peer);
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

Pool.prototype._handleHeaders = co(function* handleHeaders(headers, peer) {
  var i, ret, header, hash, last;

  if (!this.options.headers)
    return;

  if (!this.syncing)
    return;

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
      peer.increaseBan(100);
      throw new Error('Bad header chain.');
    }

    if (!header.verify(ret)) {
      peer.reject(header, 'invalid', ret.reason, 100);
      throw new Error('Invalid header.');
    }

    last = hash;

    if (yield this.chain.has(hash))
      continue;

    this.getBlock(peer, hash);
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
 * Potentially request headers if headers mode is enabled.
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.handleBlockInv = co(function* handleBlockInv(hashes, peer) {
  var unlock = yield this.locker.lock();
  try {
    return yield this._handleBlockInv(hashes, peer);
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

Pool.prototype._handleBlockInv = co(function* handleBlockInv(hashes, peer) {
  var i, hash;

  if (!this.syncing)
    return;

  // Ignore for now if we're still syncing
  if (!this.chain.synced && !peer.isLoader())
    return;

  if (this.options.witness && !peer.haveWitness)
    return;

  // Request headers instead.
  if (this.options.headers) {
    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];
      yield peer.getHeaders(null, hash);
    }

    this.scheduleRequests(peer);

    return;
  }

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

    // Request the block if we don't have it.
    if (!(yield this.chain.has(hash))) {
      this.getBlock(peer, hash);
      continue;
    }

    // Normally we request the hashContinue.
    // In the odd case where we already have
    // it, we can do one of two things: either
    // force re-downloading of the block to
    // continue the sync, or do a getblocks
    // from the last hash (this will reset
    // the hashContinue on the remote node).
    if (i === hashes.length - 1) {
      this.logger.debug('Received existing hash (%s).', peer.hostname);
      yield peer.getBlocks(hash, null);
    }
  }

  this.scheduleRequests(peer);
});

/**
 * Handle peer inv packet (txs).
 * @private
 * @param {Hash[]} hashes
 * @param {Peer} peer
 */

Pool.prototype.handleTXInv = function handleTXInv(hashes, peer) {
  var i, hash;

  this.emit('txs', hashes, peer);

  if (this.syncing && !this.chain.synced)
    return;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    try {
      this.getTX(peer, hash);
    } catch (e) {
      this.emit('error', e);
    }
  }

  this.scheduleRequests(peer);
};

/**
 * Handle peer reject event.
 * @private
 * @param {RejectPacket} reject
 * @param {Peer} peer
 */

Pool.prototype.handleReject = function handleReject(reject, peer) {
  this.logger.warning(
    'Received reject (%s): msg=%s code=%s reason=%s hash=%s.',
    peer.hostname,
    reject.message,
    reject.getCode(),
    reject.reason,
    reject.rhash());

  this.emit('reject', reject, peer);
};

/**
 * Handle peer notfound packet.
 * @private
 * @param {InvItem[]} items
 * @param {Peer} peer
 */

Pool.prototype.handleNotFound = function handleNotFound(items, peer) {
  var i, item, req;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    req = this.requestMap[item.hash];
    if (req && req.peer === peer)
      req.finish(new Error('Not found.'));
  }
};

/**
 * Handle an alert packet.
 * @private
 * @param {AlertPacket} alert
 * @param {Peer} peer
 */

Pool.prototype.handleAlert = function handleAlert(alert, peer) {
  var now = this.network.now();

  if (!alert.verify(this.network.alertKey)) {
    this.logger.warning('Peer sent a phony alert packet (%s).', peer.hostname);
    // Let's look at it because why not?
    this.logger.debug(alert);
    peer.increaseBan(100);
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
      peer.increaseBan(100);
      return;
    }
  }

  // Keep alert disabled on main.
  if (this.network === Network.main) {
    // https://github.com/bitcoin/bitcoin/pull/7692#issuecomment-197967429
    this.logger.warning('The Japanese government sent an alert packet.');
    this.logger.warning('Here is their IP: %s.', peer.hostname);
    this.logger.info(alert);
    peer.increaseBan(100);
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
 * Create an inbound peer from an existing socket.
 * @private
 * @param {NetAddress} addr
 * @param {net.Socket} socket
 */

Pool.prototype.addInbound = function addInbound(socket) {
  var self = this;
  var peer;

  if (!this.loaded)
    return socket.destroy();

  peer = this.acceptPeer(socket);

  this.logger.info('Added inbound peer (%s).', peer.hostname);

  this.peers.add(peer);

  util.nextTick(function() {
    self.emit('peer', peer);
  });
};

/**
 * Allocate a host from the host list.
 * @param {Boolean} unique
 * @returns {NetAddress}
 */

Pool.prototype.getHost = function getHost(unique) {
  var now = this.network.now();
  var i, entry, addr;

  for (i = 0; i < 100; i++) {
    entry = this.hosts.getHost();

    if (!entry)
      break;

    addr = entry.addr;

    if (unique) {
      if (this.peers.has(addr.hostname))
        continue;
    }

    if (!addr.isValid())
      continue;

    if (!addr.hasServices(this.needed))
      continue;

    if (now - entry.lastAttempt < 600 && i < 30)
      continue;

    if (addr.port !== this.network.port && i < 50)
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
  var self = this;
  var peer, addr;

  if (!this.loaded)
    return;

  if (this.peers.outbound >= this.maxOutbound)
    return;

  // Hang back if we don't have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this.getHost(true);

  if (!addr)
    return;

  peer = this.createPeer(addr);

  this.peers.add(peer);

  util.nextTick(function() {
    self.emit('peer', peer);
  });
};

/**
 * Attempt to refill the pool with peers (no lock).
 * @private
 */

Pool.prototype.fillPeers = function fillPeers() {
  var need = this.maxOutbound - this.peers.outbound;
  var i;

  if (need <= 0)
    return;

  this.logger.debug('Refilling peers (%d/%d).',
    this.peers.outbound,
    this.maxOutbound);

  for (i = 0; i < need; i++)
    this.addOutbound();
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
  var peer;

  if (this.pendingWatch != null)
    return;

  this.pendingWatch = setTimeout(function() {
    self.pendingWatch = null;
    for (peer = self.peers.head(); peer; peer = peer.next)
      peer.updateWatch();
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

Pool.prototype.getBlock = function getBlock(peer, hash) {
  var item;

  if (!this.loaded)
    return;

  if (!peer.ack)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is already destroyed (getdata).');

  if (this.requestMap[hash])
    return;

  item = new LoadRequest(this, peer, invTypes.BLOCK, hash);

  peer.queueBlock.push(item);
};

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
 * @returns {Boolean}
 */

Pool.prototype.getTX = function getTX(peer, hash) {
  var item;

  if (!this.loaded)
    return;

  if (!peer.ack)
    throw new Error('Peer handshake not complete (getdata).');

  if (peer.destroyed)
    throw new Error('Peer is already destroyed (getdata).');

  if (this.hasTX(hash))
    return true;

  item = new LoadRequest(this, peer, invTypes.TX, hash);

  peer.queueTX.push(item);

  return false;
};

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
 * @returns {Promise}
 */

Pool.prototype.scheduleRequests = co(function* scheduleRequests(peer) {
  if (this.scheduled)
    return;

  this.scheduled = true;

  yield this.chain.onDrain();

  this.sendBlockRequests(peer);
  this.sendTXRequests(peer);

  this.scheduled = false;
});

/**
 * Send scheduled requests in the request queues.
 * @private
 * @param {Peer} peer
 */

Pool.prototype.sendBlockRequests = function sendBlockRequests(peer) {
  var i, size, items, item;

  if (peer.queueBlock.size === 0)
    return;

  if (this.options.spv) {
    if (this.activeBlocks >= 2000)
      return;

    size = peer.queueBlock.size;
  } else {
    size = this.network.getBatchSize(this.chain.height);

    if (this.activeBlocks >= size)
      return;
  }

  items = peer.queueBlock.slice(size);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    item.start();
  }

  this.logger.debug(
    'Requesting %d/%d blocks from peer with getdata (%s).',
    items.length,
    this.activeBlocks,
    peer.hostname);

  peer.getData(items);
};

/**
 * Schedule next batch of `getdata` tx requests for peer.
 * @param {Peer} peer
 * @returns {Promise}
 */

Pool.prototype.sendTXRequests = function sendTXRequests(peer) {
  var size = peer.queueTX.size;
  var i, items, item;

  if (size === 0)
    return;

  items = peer.queueTX.slice(size);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    item.start();
  }

  this.logger.debug(
    'Requesting %d/%d txs from peer with getdata (%s).',
    size, this.activeTX, peer.hostname);

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
 * @param {TX|Block} msg
 * @returns {Promise}
 */

Pool.prototype.broadcast = function broadcast(msg) {
  var hash = msg.hash('hex');
  var item = this.invMap[hash];

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
 * Set a fee rate filter for all peers.
 * @param {Rate} rate
 */

Pool.prototype.setFeeRate = function setFeeRate(rate) {
  var peer;

  this.feeRate = rate;

  for (peer = this.peers.head(); peer; peer = peer.next)
    peer.sendFeeRate(rate);
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
      expect: 'txt',
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
  var res, match, ip;

  if (request.unsupported)
    throw new Error('Could not find IP.');

  res = yield request.promise({
    method: 'GET',
    uri: 'http://checkip.dyndns.org',
    expect: 'html',
    timeout: 3000
  });

  match = /IP Address:\s*([0-9a-f.:]+)/i.exec(res.body);

  if (!match)
    throw new Error('Could not find IP.');

  ip = match[1];

  if (IP.version(ip) === -1)
    throw new Error('Could not parse IP.');

  return IP.normalize(ip);
});

/**
 * Peer List
 * @constructor
 * @param {Object} options
 */

function PeerList(options) {
  this.logger = options.logger;
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

  assert(!this.map[peer.hostname]);
  this.map[peer.hostname] = peer;

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

  assert(this.map[peer.hostname]);
  delete this.map[peer.hostname];

  if (peer.isLoader()) {
    this.logger.info('Removed loader peer (%s).', peer.hostname);
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
 * Get peers by host.
 * @param {String} host
 * @returns {Peer[]}
 */

PeerList.prototype.getByHost = function getByHost(host) {
  var peers = [];
  var peer;

  for (peer = this.list.head; peer; peer = peer.next) {
    if (peer.host !== host)
      continue;
    peers.push(peer);
  }

  return peers;
};

/**
 * Destroy peer list (kills peers).
 */

PeerList.prototype.destroy = function destroy() {
  var peer, next;

  this.map = {};
  this.load = null;
  this.inbound = 0;
  this.outbound = 0;

  for (peer = this.list.head; peer; peer = next) {
    next = peer.next;
    peer.destroy();
  }
};

/**
 * Host List
 * @constructor
 * @param {Object} options
 */

function HostList(options) {
  this.address = options.address;
  this.network = options.network;
  this.logger = options.logger;
  this.proxyServer = options.proxyServer;
  this.resolve = options.resolve;
  this.banTime = options.banTime;

  this.seeds = [];
  this.banned = {};

  this.map = {};
  this.fresh = [];
  this.used = [];

  this.totalFresh = 0;
  this.totalUsed = 0;

  this.maxBuckets = 20;
  this.maxEntries = 50;
  this.maxAddresses = this.maxBuckets * this.maxEntries;

  this.horizonDays = 30;
  this.retries = 3;
  this.minFailDays = 7;
  this.maxFailures = 10;
  this.maxRefs = 8;

  this._init();
}

/**
 * Initialize list.
 * @private
 */

HostList.prototype._init = function init() {
  var i;

  for (i = 0; i < this.maxBuckets; i++)
    this.fresh.push(new MapBucket());

  for (i = 0; i < this.maxBuckets; i++)
    this.used.push(new List());

  this.setSeeds(this.network.seeds);
};

/**
 * Get list size.
 * @returns {Number}
 */

HostList.prototype.size = function size() {
  return this.totalFresh + this.totalUsed;
};

/**
 * Test whether the host list is full.
 * @returns {Boolean}
 */

HostList.prototype.isFull = function isFull() {
  return this.size() >= this.maxAddresses;
};

/**
 * Reset host list.
 */

HostList.prototype.reset = function reset() {
  var i, bucket;

  this.map = {};

  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    bucket.reset();
  }

  for (i = 0; i < this.used.length; i++) {
    bucket = this.used[i];
    bucket.reset();
  }

  this.totalFresh = 0;
  this.totalUsed = 0;
};

/**
 * Mark a peer as banned.
 * @param {String} host
 */

HostList.prototype.ban = function ban(host) {
  this.banned[host] = util.now();
};

/**
 * Unban host.
 * @param {String} host
 */

HostList.prototype.unban = function unban(host) {
  delete this.banned[host];
};

/**
 * Clear banned hosts.
 */

HostList.prototype.clearBanned = function clearBanned() {
  this.banned = {};
};

/**
 * Test whether the host is banned.
 * @param {String} host
 * @returns {Boolean}
 */

HostList.prototype.isBanned = function isBanned(host) {
  var time = this.banned[host];

  if (time == null)
    return false;

  if (util.now() > time + this.banTime) {
    delete this.banned[host];
    return false;
  }

  return true;
};

/**
 * Allocate a new host.
 * @returns {HostEntry}
 */

HostList.prototype.getHost = function getHost() {
  var now = this.network.now();
  var buckets = null;
  var factor = 1;
  var index, key, bucket, entry, num;

  if (this.totalFresh > 0)
    buckets = this.fresh;

  if (this.totalUsed > 0) {
    if (this.totalFresh === 0 || util.random(0, 2) === 0)
      buckets = this.used;
  }

  if (!buckets)
    return;

  for (;;) {
    index = util.random(0, buckets.length);
    bucket = buckets[index];

    if (bucket.size === 0)
      continue;

    index = util.random(0, bucket.size);

    if (buckets === this.used) {
      entry = bucket.head;
      while (index--)
        entry = entry.next;
    } else {
      key = bucket.keys()[index];
      entry = bucket.get(key);
    }

    num = util.random(0, 1 << 30);

    if (num < factor * entry.chance(now) * (1 << 30))
      return entry;

    factor *= 1.2;
  }
};

/**
 * Get fresh bucket for host.
 * @private
 * @param {HostEntry} entry
 * @returns {MapBucket}
 */

HostList.prototype.freshBucket = function freshBucket(entry) {
  var size = 0;
  var bw, hash, index;

  size += entry.addr.host.length;
  size += entry.src.host.length;

  bw = new StaticWriter(size);
  bw.writeString(entry.addr.host, 'ascii');
  bw.writeString(entry.src.host, 'ascii');

  hash = murmur3(bw.render(), 0xfba4c795);
  index = hash % this.fresh.length;

  return this.fresh[index];
};

/**
 * Get used bucket for host.
 * @private
 * @param {HostEntry} entry
 * @returns {List}
 */

HostList.prototype.usedBucket = function usedBucket(entry) {
  var data = new Buffer(entry.addr.host, 'ascii');
  var hash = murmur3(data, 0xfba4c795);
  var index = hash % this.used.length;
  return this.used[index];
};

/**
 * Add host to host list.
 * @param {NetAddress} addr
 * @param {NetAddress?} src
 * @returns {Boolean}
 */

HostList.prototype.add = function add(addr, src) {
  var now = this.network.now();
  var penalty = 2 * 60 * 60;
  var interval = 24 * 60 * 60;
  var factor = 1;
  var i, entry, bucket;

  if (this.isFull())
    return false;

  entry = this.map[addr.hostname];

  if (entry) {
    // No source means we're inserting
    // this ourselves. No penalty.
    if (!src)
      penalty = 0;

    // Update services.
    entry.addr.services |= addr.services;

    // Online?
    if (now - addr.ts < 24 * 60 * 60)
      interval = 60 * 60;

    // Periodically update time.
    if (entry.addr.ts < addr.ts - interval - penalty)
      entry.addr.ts = addr.ts;

    // Do not update if no new
    // information is present.
    if (entry.addr.ts && addr.ts <= entry.addr.ts)
      return false;

    // Do not update if the entry was
    // already in the "used" table.
    if (entry.used)
      return false;

    assert(entry.refCount > 0);

    // Do not update if the max
    // reference count is reached.
    if (entry.refCount === this.maxRefs)
      return false;

    assert(entry.refCount < this.maxRefs);

    // Stochastic test: previous refCount
    // N: 2^N times harder to increase it.
    for (i = 0; i < entry.refCount; i++)
      factor *= 2;

    if (util.random(0, factor) !== 0)
      return false;
  } else {
    if (!src)
      src = this.address;

    entry = new HostEntry(addr, src);

    this.totalFresh++;
  }

  bucket = this.freshBucket(entry);

  if (bucket.has(entry.key()))
    return false;

  if (bucket.size >= this.maxEntries)
    this.evictFresh(bucket);

  bucket.set(entry.key(), entry);
  entry.refCount++;

  this.map[entry.key()] = entry;

  return true;
};

/**
 * Evict a host from fresh bucket.
 * @param {MapBucket} bucket
 */

HostList.prototype.evictFresh = function evictFresh(bucket) {
  var keys = bucket.keys();
  var i, key, entry, old;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = bucket.get(key);

    if (this.isStale(entry)) {
      bucket.remove(entry.key());

      if (--entry.refCount === 0) {
        delete this.map[entry.key()];
        this.totalFresh--;
      }

      continue;
    }

    if (!old) {
      old = entry;
      continue;
    }

    if (entry.addr.ts < old.addr.ts)
      old = entry;
  }

  if (!old)
    return;

  bucket.remove(old.key());

  if (--old.refCount === 0) {
    delete this.map[old.key()];
    this.totalFresh--;
  }
};

/**
 * Test whether a host is evictable.
 * @param {HostEntry} entry
 * @returns {Boolean}
 */

HostList.prototype.isStale = function isStale(entry) {
  var now = this.network.now();

  if (entry.lastAttempt && entry.lastAttempt >= now - 60)
    return false;

  if (entry.addr.ts > now + 10 * 60)
    return true;

  if (entry.addr.ts === 0)
    return true;

  if (now - entry.addr.ts > this.horizonDays * 24 * 60 * 60)
    return true;

  if (entry.lastSuccess === 0 && entry.attempts >= this.retries)
    return true;

  if (now - entry.lastSuccess > this.minFailDays * 24 * 60 * 60) {
    if (entry.attempts >= this.maxFailures)
      return true;
  }

  return false;
};

/**
 * Remove host from host list.
 * @param {String} hostname
 * @returns {NetAddress}
 */

HostList.prototype.remove = function remove(hostname) {
  var entry = this.map[hostname];
  var i, head, bucket;

  if (!entry)
    return;

  if (entry.used) {
    assert(entry.refCount === 0);

    head = entry;
    while (head.prev)
      head = head.prev;

    for (i = 0; i < this.used.length; i++) {
      bucket = this.used[i];
      if (bucket.head === head) {
        bucket.remove(entry);
        this.totalUsed--;
        break;
      }
    }

    assert(i < this.used.length);
  } else {
    for (i = 0; i < this.fresh.length; i++) {
      bucket = this.fresh[i];
      if (bucket.remove(entry.key()))
        entry.refCount--;
    }

    this.totalFresh--;
    assert(entry.refCount === 0);
  }

  delete this.map[entry.key()];

  return entry.addr;
};

/**
 * Mark host as failed.
 * @param {String} hostname
 */

HostList.prototype.markAttempt = function markAttempt(hostname) {
  var entry = this.map[hostname];
  var now = this.network.now();

  if (!entry)
    return;

  entry.attempts++;
  entry.lastAttempt = now;
};

/**
 * Mark host as successfully connected.
 * @param {String} hostname
 */

HostList.prototype.markSuccess = function markSuccess(hostname) {
  var entry = this.map[hostname];
  var now = this.network.now();

  if (!entry)
    return;

  if (now - entry.addr.ts > 20 * 60)
    entry.addr.ts = now;
};

/**
 * Mark host as successfully connected.
 * @param {String} hostname
 * @param {Number} services
 */

HostList.prototype.markAck = function markAck(hostname, services) {
  var entry = this.map[hostname];
  var now = this.network.now();
  var i, bucket, evicted, old, fresh;

  if (!entry)
    return;

  entry.addr.services |= services;
  entry.lastSuccess = now;
  entry.lastAttempt = now;
  entry.attempts = 0;

  if (entry.used)
    return;

  assert(entry.refCount > 0);

  // Remove from fresh.
  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    if (bucket.remove(entry.key())) {
      entry.refCount--;
      old = bucket;
    }
  }

  assert(old);
  assert(entry.refCount === 0);
  this.totalFresh--;

  // Find room in used bucket.
  bucket = this.usedBucket(entry);

  if (bucket.size < this.maxEntries) {
    entry.used = true;
    bucket.push(entry);
    this.totalUsed++;
    return;
  }

  // No room. Evict.
  evicted = this.evictUsed(bucket);
  fresh = this.freshBucket(evicted);

  // Move to entry's old bucket if no room.
  if (fresh.size >= this.maxEntries)
    fresh = old;

  // Swap to evicted's used bucket.
  entry.used = true;
  bucket.replace(evicted, entry);

  // Move evicted to fresh bucket.
  evicted.used = false;
  fresh.set(evicted.key(), evicted);
  assert(evicted.refCount === 0);
  evicted.refCount++;
  this.totalFresh++;
};

/**
 * Pick used for eviction.
 * @param {List} bucket
 */

HostList.prototype.evictUsed = function evictUsed(bucket) {
  var old = bucket.head;
  var entry;

  for (entry = bucket.head; entry; entry = entry.next) {
    if (entry.addr.ts < old.addr.ts)
      old = entry;
  }

  return old;
};

/**
 * Convert address list to array.
 * @returns {NetAddress[]}
 */

HostList.prototype.toArray = function toArray() {
  var keys = Object.keys(this.map);
  var out = [];
  var i, key, entry;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    out.push(entry.addr);
  }

  assert.equal(out.length, this.size());

  return out;
};

/**
 * Set initial seeds.
 * @param {String[]} seeds
 */

HostList.prototype.setSeeds = function setSeeds(seeds) {
  var i, seed;

  this.seeds.length = 0;

  for (i = 0; i < seeds.length; i++) {
    seed = seeds[i];
    this.addSeed(seed);
  }
};

/**
 * Add a preferred seed.
 * @param {String} hostname
 */

HostList.prototype.addSeed = function addSeed(host) {
  var addr = IP.parseHost(host, this.network.port);
  return this.seeds.push(addr);
};

/**
 * Discover hosts from seeds.
 * @returns {Promise}
 */

HostList.prototype.discover = co(function* discover() {
  var jobs = [];
  var i, seed;

  for (i = 0; i < this.seeds.length; i++) {
    seed = this.seeds[i];
    jobs.push(this.populate(seed));
  }

  yield Promise.all(jobs);
});

/**
 * Populate from seed.
 * @param {Object} seed
 * @returns {Promise}
 */

HostList.prototype.populate = co(function* populate(seed) {
  var i, addr, hosts, host;

  if (seed.version !== -1) {
    addr = NetAddress.fromHost(seed.host, seed.port, this.network);
    this.add(addr);
    return;
  }

  this.logger.info('Resolving hosts from seed: %s.', seed.host);

  try {
    hosts = yield this.resolve(seed.host, this.proxyServer);
  } catch (e) {
    this.logger.error(e);
    return;
  }

  for (i = 0; i < hosts.length; i++) {
    host = hosts[i];
    addr = NetAddress.fromHost(host, seed.port, this.network);
    this.add(addr);
  }
});

/**
 * Convert host list to json-friendly object.
 * @returns {Object}
 */

HostList.prototype.toJSON = function toJSON() {
  var addrs = [];
  var fresh = [];
  var used = [];
  var i, keys, key, bucket, entry;

  keys = Object.keys(this.map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    addrs.push(entry.toJSON());
  }

  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    keys = bucket.keys();
    fresh.push(keys);
  }

  for (i = 0; i < this.used.length; i++) {
    bucket = this.used[i];
    keys = [];
    for (entry = bucket.head; entry; entry = entry.next)
      keys.push(entry.key());
    used.push(keys);
  }

  return {
    version: 1,
    addrs: addrs,
    fresh: fresh,
    used: used
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @returns {HostList}
 */

HostList.prototype.fromJSON = function fromJSON(json) {
  var sources = {};
  var i, j, bucket, keys, key, addr, entry, src;

  assert(json && typeof json === 'object');
  assert(json.version === 1, 'Bad address serialization version.');

  assert(Array.isArray(json.addrs));

  for (i = 0; i < json.addrs.length; i++) {
    addr = json.addrs[i];
    entry = HostEntry.fromJSON(addr, this.network);
    src = sources[entry.src.hostname];

    // Save some memory.
    if (!src) {
      src = entry.src;
      sources[src.hostname] = src;
    }

    entry.src = src;

    this.map[entry.key()] = entry;
  }

  assert(Array.isArray(json.fresh));

  for (i = 0; i < json.fresh.length; i++) {
    keys = json.fresh[i];
    bucket = this.fresh[i];
    assert(bucket, 'No bucket available.');
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = this.map[key];
      assert(entry);
      if (entry.refCount === 0)
        this.totalFresh++;
      entry.refCount++;
      bucket.set(key, entry);
    }
  }

  assert(Array.isArray(json.used));

  for (i = 0; i < json.used.length; i++) {
    keys = json.used[i];
    bucket = this.used[i];
    assert(bucket, 'No bucket available.');
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = this.map[key];
      assert(entry);
      assert(entry.refCount === 0);
      assert(!entry.used);
      entry.used = true;
      this.totalUsed++;
      bucket.push(entry);
    }
  }

  keys = Object.keys(this.map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    assert(entry.used || entry.refCount > 0);
  }

  return this;
};

/**
 * Instantiate host list from json object.
 * @param {Object} options
 * @param {Object} json
 * @returns {HostList}
 */

HostList.fromJSON = function fromJSON(options, json) {
  return new HostEntry(options).fromJSON(json);
};

/**
 * MapBucket
 * @constructor
 */

function MapBucket() {
  this.map = {};
  this.size = 0;
}

/**
 * Get map keys.
 * @returns {String[]}
 */

MapBucket.prototype.keys = function keys() {
  return Object.keys(this.map);
};

/**
 * Get item from map.
 * @param {String} key
 * @returns {Object|null}
 */

MapBucket.prototype.get = function get(key) {
  return this.map[key];
};

/**
 * Test whether map has an item.
 * @param {String} key
 * @returns {Boolean}
 */

MapBucket.prototype.has = function has(key) {
  return this.map[key] !== undefined;
};

/**
 * Set a key to value in map.
 * @param {String} key
 * @param {Object} value
 * @returns {Boolean}
 */

MapBucket.prototype.set = function set(key, value) {
  var item = this.map[key];

  assert(value !== undefined);

  this.map[key] = value;

  if (item === undefined) {
    this.size++;
    return true;
  }

  return false;
};

/**
 * Remove an item from map.
 * @param {String} key
 * @returns {Object|null}
 */

MapBucket.prototype.remove = function remove(key) {
  var item = this.map[key];

  if (item === undefined)
    return;

  delete this.map[key];
  this.size--;

  return item;
};

/**
 * Reset the map.
 */

MapBucket.prototype.reset = function reset() {
  this.map = {};
  this.size = 0;
};

/**
 * HostEntry
 * @constructor
 * @param {NetAddress} addr
 * @param {NetAddress} src
 */

function HostEntry(addr, src) {
  if (!(this instanceof HostEntry))
    return new HostEntry(addr, src);

  this.addr = addr || new NetAddress();
  this.src = src || new NetAddress();
  this.prev = null;
  this.next = null;
  this.used = false;
  this.refCount = 0;
  this.attempts = 0;
  this.lastSuccess = 0;
  this.lastAttempt = 0;

  if (addr)
    this.fromOptions(addr, src);
}

/**
 * Inject properties from options.
 * @private
 * @param {NetAddress} addr
 * @param {NetAddress} src
 * @returns {HostEntry}
 */

HostEntry.prototype.fromOptions = function fromOptions(addr, src) {
  assert(addr instanceof NetAddress);
  assert(src instanceof NetAddress);
  this.addr = addr;
  this.src = src;
  return this;
};

/**
 * Instantiate host entry from options.
 * @param {NetAddress} addr
 * @param {NetAddress} src
 * @returns {HostEntry}
 */

HostEntry.fromOptions = function fromOptions(addr, src) {
  return new HostEntry().fromOptions(addr, src);
};

/**
 * Get key suitable for a hash table (hostname).
 * @returns {String}
 */

HostEntry.prototype.key = function key() {
  return this.addr.hostname;
};

/**
 * Get host priority.
 * @param {Number} now
 * @returns {Number}
 */

HostEntry.prototype.chance = function _chance(now) {
  var attempts = this.attempts;
  var chance = 1;

  if (now - this.lastAttempt < 60 * 10)
    chance *= 0.01;

  chance *= Math.pow(0.66, Math.min(attempts, 8));

  return chance;
};

/**
 * Inspect host address.
 * @returns {Object}
 */

HostEntry.prototype.inspect = function inspect() {
  return {
    addr: this.addr,
    src: this.src,
    used: this.used,
    refCount: this.refCount,
    attempts: this.attempts,
    lastSuccess: util.date(this.lastSuccess),
    lastAttempt: util.date(this.lastAttempt)
  };
};

/**
 * Convert host entry to json-friendly object.
 * @returns {Object}
 */

HostEntry.prototype.toJSON = function toJSON() {
  return {
    addr: this.addr.hostname,
    src: this.src.hostname,
    services: this.addr.services.toString(2),
    ts: this.addr.ts,
    attempts: this.attempts,
    lastSuccess: this.lastSuccess,
    lastAttempt: this.lastAttempt
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @param {Network} network
 * @returns {HostEntry}
 */

HostEntry.prototype.fromJSON = function fromJSON(json, network) {
  assert(json && typeof json === 'object');
  assert(typeof json.addr === 'string');
  assert(typeof json.src === 'string');

  this.addr.fromHostname(json.addr, network);

  if (json.services != null) {
    assert(typeof json.services === 'string');
    assert(json.services.length > 0);
    assert(json.services.length < 64);
    this.addr.services = parseInt(json.services, 2);
  }

  if (json.ts != null) {
    assert(util.isNumber(json.ts));
    this.addr.ts = json.ts;
  }

  if (json.src != null) {
    assert(typeof json.src === 'string');
    this.src.fromHostname(json.src, network);
  }

  if (json.attempts != null) {
    assert(util.isNumber(json.attempts));
    this.attempts = json.attempts;
  }

  if (json.lastSuccess != null) {
    assert(util.isNumber(json.lastSuccess));
    this.lastSuccess = json.lastSuccess;
  }

  if (json.lastAttempt != null) {
    assert(util.isNumber(json.lastAttempt));
    this.lastAttempt = json.lastAttempt;
  }

  return this;
};

/**
 * Instantiate host entry from json object.
 * @param {Object} json
 * @param {Network} network
 * @returns {HostEntry}
 */

HostEntry.fromJSON = function fromJSON(json, network) {
  return new HostEntry().fromJSON(json, network);
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
  this.timeout = null;
  this.onTimeout = this._onTimeout.bind(this);

  this.prev = null;
  this.next = null;

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
  if (this.type === invTypes.BLOCK && this.peer.isLoader()) {
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

  if (this.type === invTypes.TX)
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
  var entry = this.pool.requestMap[this.hash];

  if (entry) {
    assert(entry === this);
    delete this.pool.requestMap[this.hash];
    if (this.active) {
      this.active = false;
      this.pool.activeRequest--;
      if (this.type === invTypes.TX)
        this.pool.activeTX--;
      else
        this.pool.activeBlocks--;
    }
  }

  if (this.type === invTypes.TX)
    this.peer.queueTX.remove(this);
  else
    this.peer.queueBlock.remove(this);

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
    + ' type=' + (this.type === invTypes.TX ? 'tx' : 'block')
    + ' active=' + this.active
    + ' hash=' + util.revHex(this.hash)
    + '>';
};

/**
 * Convert load request to an inv item.
 * @returns {InvItem}
 */

LoadRequest.prototype.toInv = function toInv() {
  var type = this.type === invTypes.BLOCK
    ? this.peer.blockType()
    : this.peer.txType();

  return new InvItem(type, this.hash);
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @exports BroadcastItem
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
  this.callback = [];

  this.prev = null;
  this.next = null;
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
  assert(this.pool.invItems.push(this));

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
  assert(this.pool.invItems.remove(this));

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
    + ' type=' + (this.type === invTypes.TX ? 'tx' : 'block')
    + ' hash=' + util.revHex(this.hash)
    + '>';
};

/*
 * Expose
 */

module.exports = Pool;
