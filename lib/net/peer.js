/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var co = require('../utils/co');
var Parser = require('./parser');
var Framer = require('./framer');
var packets = require('./packets');
var constants = require('../protocol/constants');
var InvItem = require('../primitives/invitem');
var Locker = require('../utils/locker');
var Bloom = require('../utils/bloom');
var BIP151 = require('./bip151');
var BIP150 = require('./bip150');
var BIP152 = require('./bip152');
var Block = require('../primitives/block');
var TX = require('../primitives/tx');
var errors = require('../btc/errors');
var NetAddress = require('../primitives/netaddress');
var invTypes = InvItem.types;
var packetTypes = packets.types;
var VerifyResult = errors.VerifyResult;

/**
 * Represents a remote peer.
 * @exports Peer
 * @constructor
 * @param {Pool} pool
 * @param {NetAddress} address
 * @param {net.Socket?} socket
 * @property {Pool} pool
 * @property {net.Socket?} socket
 * @property {String} host
 * @property {Number} port
 * @property {String} hostname
 * @property {Parser} parser
 * @property {Framer} framer
 * @property {Chain} chain
 * @property {Mempool} mempool
 * @property {Object?} version - Version packet payload.
 * @property {Boolean} destroyed
 * @property {Boolean} ack - Whether verack has been received.
 * @property {Boolean} connected
 * @property {Number} ts
 * @property {Boolean} preferHeaders - Whether the peer has
 * requested getheaders.
 * @property {Boolean} haveWitness - Whether the peer supports segwit,
 * either notified via service bits or deprecated `havewitness` packet.
 * @property {Hash?} hashContinue - The block hash at which to continue
 * the sync for the peer.
 * @property {Bloom?} spvFilter - The _peer's_ bloom spvFilter.
 * @property {Boolean} noRelay - Whether to relay transactions
 * immediately to the peer.
 * @property {BN} challenge - Local nonce.
 * @property {Number} lastPong - Timestamp for last `pong`
 * received (unix time).
 * @property {Number} lastPing - Timestamp for last `ping`
 * sent (unix time).
 * @property {Number} minPing - Lowest ping time seen.
 * @property {Number} banScore
 * @emits Peer#ack
 */

function Peer(pool) {
  if (!(this instanceof Peer))
    return new Peer(pool);

  EventEmitter.call(this);

  this.pool = pool;
  this.options = pool.options;
  this.logger = pool.logger;
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.network = this.chain.network;
  this.locker = new Locker();
  this.next = null;
  this.prev = null;

  this.socket = null;
  this.outbound = false;
  this.address = new NetAddress();
  this.connected = false;
  this.destroyed = false;
  this.ack = false;
  this.ts = 0;
  this.lastSend = 0;
  this.lastRecv = 0;
  this.drainStart = 0;
  this.drainSize = 0;
  this.drainQueue = [];
  this.banScore = 0;
  this.invQueue = [];

  this.version = null;
  this.preferHeaders = false;
  this.haveWitness = false;
  this.hashContinue = null;
  this.spvFilter = null;
  this.noRelay = false;
  this.feeRate = -1;
  this.bip151 = null;
  this.bip150 = null;
  this.compactMode = -1;
  this.compactWitness = false;
  this.compactBlocks = {};
  this.compactAmount = 0;
  this.lastMerkle = null;
  this.waitingTX = 0;
  this.syncSent = false;
  this.sentAddr = false;
  this.sentGetAddr = false;
  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;
  this.lastBlock = -1;

  this.connectTimeout = null;
  this.pingTimer = null;
  this.invTimer = null;
  this.stallTimer = null;

  this.addrFilter = new Bloom.Rolling(5000, 0.001);
  this.invFilter = new Bloom.Rolling(50000, 0.000001);

  this.requestMap = {};
  this.queueMap = {};

  this.responseMap = {};

  if (this.options.bip151) {
    this.bip151 = new BIP151();
    if (this.options.bip150) {
      this.bip150 = new BIP150(
        this.bip151,
        this.hostname,
        this.outbound,
        this.pool.authdb,
        this.pool.identityKey);
      this.bip151.bip150 = this.bip150;
    }
  }

  this.parser = new Parser(this);
  this.framer = new Framer(this);

  this._init();
}

util.inherits(Peer, EventEmitter);

Peer.DRAIN_MAX = 5 << 20;
Peer.DRAIN_TIMEOUT = 10000;
Peer.STALL_INTERVAL = 5000;
Peer.PING_INTERVAL = 30000;
Peer.INV_INTERVAL = 5000;
Peer.RESPONSE_TIMEOUT = 30000;

Peer.prototype.__defineGetter__('host', function() {
  return this.address.host;
});

Peer.prototype.__defineGetter__('port', function() {
  return this.address.port;
});

Peer.prototype.__defineGetter__('hostname', function() {
  return this.address.hostname;
});

/**
 * Begin peer initialization.
 * @private
 */

Peer.prototype._init = function init() {
  var self = this;

  this.parser.on('packet', co(function* (packet) {
    try {
      yield self.handlePacket(packet);
    } catch (e) {
      self.error(e);
      self.destroy();
    }
  }));

  this.parser.on('error', function(err) {
    self.error(err);
    self.reject(null, 'malformed', 'error parsing message', 10);
  });

  if (this.bip151) {
    this.bip151.on('error', function(err) {
      self.error(err);
      self.reject(null, 'malformed', 'error parsing message', 10);
    });
    this.bip151.on('rekey', function() {
      self.logger.debug('Rekeying with peer (%s).', self.hostname);
      self.send(self.bip151.toRekey());
    });
  }
};

/**
 * Bind to socket.
 * @param {net.Socket} socket
 */

Peer.prototype.bind = function bind(socket) {
  var self = this;

  assert(!this.socket);

  this.socket = socket;

  this.socket.once('connect', function() {
    self.logger.info('Connected to %s.', self.hostname);
  });

  this.socket.once('error', function(err) {
    if (!self.connected)
      return;

    self.error(err);
    self.destroy();
  });

  this.socket.once('close', function() {
    self.error('socket hangup');
    self.destroy();
  });

  this.socket.on('drain', function() {
    self.drainSize = 0;
  });

  this.socket.on('data', function(chunk) {
    if (self.maybeStall())
      return;

    self.lastRecv = util.ms();
    self.parser.feed(chunk);
  });
};

/**
 * Accept an inbound socket.
 * @param {net.Socket} socket
 * @returns {net.Socket}
 */

Peer.prototype.accept = function accept(socket) {
  assert(!this.socket);

  this.address = NetAddress.fromSocket(socket, this.network);
  this.address.services = 0;
  this.ts = util.now();
  this.outbound = false;
  this.connected = true;

  this.bind(socket);
};

/**
 * Create the socket and begin connecting. This method
 * will use `options.createSocket` if provided.
 * @param {NetAddress} addr
 * @returns {net.Socket}
 */

Peer.prototype.connect = function connect(addr) {
  var proxy = this.pool.proxyServer;
  var socket;

  assert(!this.socket);

  socket = this.pool.createSocket(addr.port, addr.host, proxy);

  this.address = addr;
  this.ts = util.now();
  this.outbound = true;
  this.connected = false;

  this.bind(socket);

  this.logger.debug('Connecting to %s.', this.hostname);

  return socket;
};

/**
 * Open and perform initial handshake (without rejection).
 * @returns {Promise}
 */

Peer.prototype.tryOpen = co(function* tryOpen() {
  try {
    yield this.open();
  } catch (e) {
    ;
  }
});

/**
 * Open and perform initial handshake.
 * @returns {Promise}
 */

Peer.prototype.open = co(function* open() {
  try {
    yield this._open();
  } catch (e) {
    this.error(e);
    this.destroy();
    throw e;
  }
});

/**
 * Open and perform initial handshake.
 * @returns {Promise}
 */

Peer.prototype._open = co(function* open() {
  // Connect to peer.
  yield this.initConnect();
  yield this.initStall();
  yield this.initBIP151();
  yield this.initBIP150();
  yield this.initVersion();
  yield this.finalize();

  assert(!this.destroyed);

  // Finally we can let the pool know
  // that this peer is ready to go.
  this.emit('open');
});

/**
 * Wait for connection.
 * @private
 */

Peer.prototype.initConnect = function initConnect() {
  var self = this;

  if (this.connected) {
    assert(!this.outbound);
    return co.wait();
  }

  return new Promise(function(resolve, reject) {
    function cleanup() {
      if (self.connectTimeout != null) {
        clearTimeout(self.connectTimeout);
        self.connectTimeout = null;
      }
      self.socket.removeListener('error', onError);
    }

    function onError(err) {
      cleanup();
      reject(err);
    }

    self.socket.once('connect', function() {
      self.ts = util.now();
      self.connected = true;
      self.emit('connect');

      cleanup();
      resolve();
    });

    self.socket.once('error', onError);

    self.connectTimeout = setTimeout(function() {
      self.connectTimeout = null;
      cleanup();
      reject(new Error('Connection timed out.'));
    }, 10000);
  });
};

/**
 * Setup stall timer.
 * @private
 */

Peer.prototype.initStall = function initStall() {
  var self = this;
  assert(!this.stallTimer);
  assert(!this.destroyed);
  this.stallTimer = setInterval(function() {
    self.maybeStall();
    self.maybeTimeout();
  }, Peer.STALL_INTERVAL);
  return Promise.resolve();
};

/**
 * Handle `connect` event (called immediately
 * if a socket was passed into peer).
 * @private
 */

Peer.prototype.initBIP151 = co(function* initBIP151() {
  // Send encinit. Wait for handshake to complete.
  if (!this.bip151)
    return;

  assert(!this.bip151.completed);

  this.logger.info('Attempting BIP151 handshake (%s).', this.hostname);

  this.send(this.bip151.toEncinit());

  try {
    yield this.bip151.wait(3000);
  } catch (err) {
    this.error(err);
  }

  if (this.destroyed)
    throw new Error('Peer was destroyed during BIP151 handshake.');

  assert(this.bip151.completed);

  if (this.bip151.handshake) {
    this.logger.info('BIP151 handshake complete (%s).', this.hostname);
    this.logger.info('Connection is encrypted (%s).', this.hostname);
  }
});

/**
 * Handle post bip151-handshake.
 * @private
 */

Peer.prototype.initBIP150 = co(function* initBIP150() {
  if (!this.bip151 || !this.bip150)
    return;

  assert(!this.bip150.completed);

  if (!this.bip151.handshake)
    throw new Error('BIP151 handshake was not completed for BIP150.');

  this.logger.info('Attempting BIP150 handshake (%s).', this.hostname);

  if (this.bip150.outbound) {
    if (!this.bip150.peerIdentity)
      throw new Error('No known identity for peer.');
    this.send(this.bip150.toChallenge());
  }

  yield this.bip150.wait(3000);

  assert(!this.destroyed);
  assert(this.bip150.completed);

  if (this.bip150.auth) {
    this.logger.info('BIP150 handshake complete (%s).', this.hostname);
    this.logger.info('Peer is authed (%s): %s.',
      this.hostname, this.bip150.getAddress());
  }
});

/**
 * Handle post handshake.
 * @private
 */

Peer.prototype.initVersion = co(function* initVersion() {
  assert(!this.destroyed);

  // Say hello.
  this.sendVersion();

  // Advertise our address.
  if (!this.pool.address.isNull()
      && !this.options.selfish
      && this.pool.server) {
    this.send(new packets.AddrPacket([this.pool.address]));
  }

  if (!this.ack) {
    yield this.wait(packetTypes.VERACK, 10000);
    assert(this.ack);
  }

  // Wait for _their_ version.
  if (!this.version) {
    this.logger.debug(
      'Peer sent a verack without a version (%s).',
      this.hostname);

    yield this.wait(packetTypes.VERSION, 10000);

    assert(this.version);
  }

  this.logger.debug('Received verack (%s).', this.hostname);
});

/**
 * Handle `ack` event (called on verack).
 * @private
 */

Peer.prototype.finalize = co(function* finalize() {
  var self = this;

  assert(!this.destroyed);

  // Setup the ping interval.
  this.pingTimer = setInterval(function() {
    self.sendPing();
  }, Peer.PING_INTERVAL);

  // Setup the inv flusher.
  this.invTimer = setInterval(function() {
    self.flushInv();
  }, Peer.INV_INTERVAL);

  // Ask for headers-only.
  if (this.options.headers) {
    if (this.version.version >= 70012)
      this.send(new packets.SendHeadersPacket());
  }

  // Let them know we support segwit (old
  // segwit3 nodes require this instead
  // of service bits).
  if (this.options.witness && this.network.oldWitness) {
    if (this.version.version >= 70012)
      this.send(new packets.HaveWitnessPacket());
  }

  // We want compact blocks!
  if (this.options.compact) {
    if (this.version.version >= 70014)
      this.sendCompact();
  }

  // Find some more peers.
  if (!this.pool.hosts.isFull())
    this.sendGetAddr();

  // Relay our spv filter if we have one.
  this.updateWatch();

  // Announce our currently broadcasted items.
  this.announceList();

  // Set a fee rate filter.
  if (this.pool.feeRate !== -1)
    this.sendFeeRate(this.pool.feeRate);

  // Start syncing the chain.
  this.sync();
});

/**
 * Test whether the peer is the loader peer.
 * @returns {Boolean}
 */

Peer.prototype.isLoader = function isLoader() {
  return this === this.pool.peers.load;
};

/**
 * Broadcast blocks to peer.
 * @param {Block[]} blocks
 */

Peer.prototype.announceBlock = function announceBlock(blocks) {
  var inv = [];
  var i, block;

  if (!this.ack)
    return;

  if (this.destroyed)
    return;

  if (!Array.isArray(blocks))
    blocks = [blocks];

  for (i = 0; i < blocks.length; i++) {
    block = blocks[i];

    assert(block instanceof Block);

    // Don't send if they already have it.
    if (this.invFilter.test(block.hash()))
      continue;

    // Send them the block immediately if
    // they're using compact block mode 1.
    if (this.compactMode === 1) {
      this.invFilter.add(block.hash());
      this.sendCompactBlock(block, this.compactWitness);
      continue;
    }

    // Convert item to block headers
    // for peers that request it.
    if (this.preferHeaders) {
      inv.push(block.toHeaders());
      continue;
    }

    inv.push(block.toInv());
  }

  if (this.preferHeaders) {
    this.sendHeaders(inv);
    return;
  }

  this.sendInv(inv);
};

/**
 * Broadcast transactions to peer.
 * @param {TX[]} txs
 */

Peer.prototype.announceTX = function announceTX(txs) {
  var inv = [];
  var i, tx, hash, entry;

  if (!this.ack)
    return;

  if (this.destroyed)
    return;

  // Do not send txs to spv clients
  // that have relay unset.
  if (this.noRelay)
    return;

  if (!Array.isArray(txs))
    txs = [txs];

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    assert(tx instanceof TX);

    // Don't send if they already have it.
    if (this.invFilter.test(tx.hash()))
      continue;

    // Check the peer's bloom
    // filter if they're using spv.
    if (this.spvFilter) {
      if (!tx.isWatched(this.spvFilter))
        continue;
    }

    // Check the fee filter.
    if (this.feeRate !== -1 && this.mempool) {
      hash = tx.hash('hex');
      entry = this.mempool.getEntry(hash);
      if (entry && entry.getRate() < this.feeRate)
        continue;
    }

    inv.push(tx.toInv());
  }

  this.sendInv(inv);
};

/**
 * Announce broadcast list to peer.
 */

Peer.prototype.announceList = function announceList() {
  var blocks = [];
  var txs = [];
  var hashes = Object.keys(this.pool.invMap);
  var i, hash, item;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    item = this.pool.invMap[hash];

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
    this.announceBlock(blocks);

  if (txs.length > 0)
    this.announceTX(txs);
};

/**
 * Send inv to a peer.
 * @param {InvItem[]} items
 */

Peer.prototype.sendInv = function sendInv(items) {
  var hasBlock = false;
  var i, item;

  if (!this.ack)
    return;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];
    if (item.type === invTypes.BLOCK)
      hasBlock = true;
    this.invQueue.push(item);
  }

  if (this.invQueue.length >= 500 || hasBlock)
    this.flushInv();
};

/**
 * Flush inv queue.
 * @private
 */

Peer.prototype.flushInv = function flushInv() {
  var queue = this.invQueue.slice();
  var items = [];
  var i, item, chunk;

  if (queue.length === 0)
    return;

  this.invQueue.length = 0;

  this.logger.spam('Serving %d inv items to %s.',
    queue.length, this.hostname);

  for (i = 0; i < queue.length; i++) {
    item = queue[i];

    if (!this.invFilter.added(item.hash, 'hex'))
      continue;

    items.push(item);
  }

  for (i = 0; i < items.length; i += 1000) {
    chunk = items.slice(i, i + 1000);
    this.send(new packets.InvPacket(chunk));
  }
};

/**
 * Send headers to a peer.
 * @param {Headers[]} items
 */

Peer.prototype.sendHeaders = function sendHeaders(items) {
  var i, item, chunk;

  if (!this.ack)
    return;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];
    this.invFilter.add(item.hash());
  }

  if (items.length === 0)
    return;

  this.logger.spam('Serving %d headers to %s.',
    items.length, this.hostname);

  for (i = 0; i < items.length; i += 2000) {
    chunk = items.slice(i, i + 2000);
    this.send(new packets.HeadersPacket(chunk));
  }
};

/**
 * Send a `version` packet.
 */

Peer.prototype.sendVersion = function sendVersion() {
  var packet = new packets.VersionPacket();
  packet.version = constants.VERSION;
  packet.services = this.pool.address.services;
  packet.ts = this.network.now();
  packet.from = this.pool.address;
  packet.nonce = this.pool.localNonce;
  packet.agent = constants.USER_AGENT;
  packet.height = this.chain.height;
  packet.noRelay = this.options.noRelay;
  this.send(packet);
};

/**
 * Send a `getaddr` packet.
 */

Peer.prototype.sendGetAddr = function sendGetAddr() {
  if (this.sentGetAddr)
    return;

  this.sentGetAddr = true;
  this.send(new packets.GetAddrPacket());
};

/**
 * Send a `ping` packet.
 */

Peer.prototype.sendPing = function sendPing() {
  if (!this.version)
    return;

  if (this.version.version <= 60000) {
    this.send(new packets.PingPacket());
    return;
  }

  if (this.challenge) {
    this.logger.debug('Peer has not responded to ping (%s).', this.hostname);
    this.destroy();
    return;
  }

  this.lastPing = util.ms();
  this.challenge = util.nonce();

  this.send(new packets.PingPacket(this.challenge));
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.ack)
    return;

  if (!this.options.spv)
    return;

  this.send(new packets.FilterLoadPacket(this.pool.spvFilter));
};

/**
 * Set a fee rate filter for the peer.
 * @param {Rate} rate
 */

Peer.prototype.sendFeeRate = function sendFeeRate(rate) {
  if (!this.ack)
    return;

  this.send(new packets.FeeFilterPacket(rate));
};

/**
 * Disconnect from and destroy the peer.
 */

Peer.prototype.destroy = function destroy() {
  var connected = this.connected;
  var i, keys, cmd, entry;

  if (this.destroyed)
    return;

  this.drainSize = 0;

  this.destroyed = true;
  this.connected = false;

  this.socket.destroy();
  this.socket = null;

  if (this.bip151)
    this.bip151.destroy();

  if (this.bip150)
    this.bip150.destroy();

  if (this.pingTimer != null) {
    clearInterval(this.pingTimer);
    this.pingTimer = null;
  }

  if (this.invTimer != null) {
    clearInterval(this.invTimer);
    this.invTimer = null;
  }

  if (this.stallTimer != null) {
    clearInterval(this.stallTimer);
    this.stallTimer = null;
  }

  if (this.connectTimeout != null) {
    clearTimeout(this.connectTimeout);
    this.connectTimeout = null;
  }

  keys = Object.keys(this.responseMap);

  for (i = 0; i < keys.length; i++) {
    cmd = keys[i];
    entry = this.responseMap[cmd];
    delete this.responseMap[cmd];
    entry.reject(new Error('Peer was destroyed.'));
  }

  this.compactBlocks = {};
  this.compactAmount = 0;

  this.locker.destroy();

  this.emit('close', connected);
};

/**
 * Write data to the peer's socket.
 * @param {Buffer} data
 * @returns {Promise}
 */

Peer.prototype.write = function write(data) {
  if (this.destroyed)
    return;

  this.lastSend = util.ms();

  if (this.socket.write(data) === false)
    this.needsDrain(data.length);
};

/**
 * Add to drain counter.
 * @private
 * @param {Number} size
 */

Peer.prototype.needsDrain = function needsDrain(size) {
  if (this.maybeStall()) {
    this.error('Peer stalled (drain).');
    this.destroy();
    return;
  }

  this.drainStart = util.ms();
  this.drainSize += size;

  if (this.drainSize >= Peer.DRAIN_MAX) {
    this.logger.warning(
      'Peer is not reading: %dmb buffered (%s).',
      util.mb(this.drainSize),
      this.hostname);
    this.error('Peer stalled (drain).');
    this.destroy();
  }
};

/**
 * Potentially timeout peer if it hasn't read.
 * @private
 */

Peer.prototype.maybeStall = function maybeStall() {
  if (this.drainSize === 0)
    return false;

  if (util.ms() < this.drainStart + Peer.DRAIN_TIMEOUT)
    return false;

  this.drainSize = 0;
  this.error('Peer stalled (write).');
  this.destroy();

  return true;
};

/**
 * Potentially add response timeout.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.addTimeout = function addTimeout(packet) {
  var timeout = Peer.RESPONSE_TIMEOUT;

  switch (packet.type) {
    case packetTypes.MEMPOOL:
    case packetTypes.GETBLOCKS:
      this.request(packetTypes.INV, timeout);
      break;
    case packetTypes.GETHEADERS:
      this.request(packetTypes.HEADERS, timeout * 2);
      break;
    case packetTypes.GETDATA:
      this.request(packetTypes.DATA, timeout);
      break;
    case packetTypes.GETBLOCKTXN:
      this.request(packetTypes.BLOCKTXN, timeout);
      break;
  }
};

/**
 * Potentially finish response timeout.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.fulfill = function fulfill(packet) {
  var entry;

  switch (packet.type) {
    case packetTypes.BLOCK:
    case packetTypes.CMPCTBLOCK:
    case packetTypes.MERKLEBLOCK:
    case packetTypes.TX:
    case packetTypes.NOTFOUND:
      entry = this.response(packetTypes.DATA, packet);
      assert(!entry || entry.jobs.length === 0);
      break;
  }

  return this.response(packet.type, packet);
};

/**
 * Potentially timeout peer if it hasn't responded.
 * @private
 */

Peer.prototype.maybeTimeout = function maybeTimeout() {
  var keys = Object.keys(this.responseMap);
  var now = util.ms();
  var i, key, entry, name;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.responseMap[key];
    if (now > entry.timeout) {
      name = packets.typesByVal[key];
      this.error('Peer is stalling (%s).', name.toLowerCase());
      this.destroy();
      return;
    }
  }

  if (!this.pool.syncing || this.chain.synced)
    return;

  if (!this.isLoader())
    return;

  if (now > this.lastBlock + 60000) {
    this.error('Peer is stalling (block).');
    this.destroy();
  }
};

/**
 * Wait for a packet to be received from peer.
 * @private
 * @param {Number} type - Packet type.
 * @param {Number} timeout
 * @returns {RequestEntry}
 */

Peer.prototype.request = function request(type, timeout) {
  var entry = this.responseMap[type];

  if (this.destroyed)
    return;

  if (!entry) {
    entry = new RequestEntry();
    this.responseMap[type] = entry;
  }

  entry.setTimeout(timeout);

  return entry;
};

/**
 * Fulfill awaiting requests created with {@link Peer#request}.
 * @private
 * @param {Number} type - Packet type.
 * @param {Object} payload
 */

Peer.prototype.response = function response(type, payload) {
  var entry = this.responseMap[type];

  if (!entry)
    return;

  delete this.responseMap[type];

  return entry;
};

/**
 * Wait for a packet to be received from peer.
 * @private
 * @param {Number} type - Packet type.
 * @returns {Promise} - Returns Object(payload).
 * Executed on timeout or once packet is received.
 */

Peer.prototype.wait = function wait(type, timeout) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var entry;

    if (self.destroyed)
      return reject(new Error('Request destroyed.'));

    entry = self.request(type);

    entry.setTimeout(timeout);
    entry.addJob(resolve, reject);
  });
};

/**
 * Send a packet.
 * @param {Packet} packet
 * @returns {Promise}
 */

Peer.prototype.send = function send(packet) {
  var tx, checksum;

  // Used cached hashes as the
  // packet checksum for speed.
  if (packet.type === packetTypes.TX) {
    tx = packet.tx;
    if (packet.witness) {
      if (!tx.isCoinbase())
        checksum = tx.witnessHash();
    } else {
      checksum = tx.hash();
    }
  }

  this.addTimeout(packet);

  this.sendRaw(packet.cmd, packet.toRaw(), checksum);
};

/**
 * Send a packet.
 * @param {Packet} packet
 * @returns {Promise}
 */

Peer.prototype.sendRaw = function sendRaw(cmd, body, checksum) {
  var payload = this.framer.packet(cmd, body, checksum);
  this.write(payload);
};

/**
 * Emit an error and destroy the peer.
 * @private
 * @param {...String|Error} err
 */

Peer.prototype.error = function error(err) {
  var msg;

  if (this.destroyed)
    return;

  if (typeof err === 'string') {
    msg = util.fmt.apply(util, arguments);
    err = new Error(msg);
  }

  err.message += ' (' + this.hostname + ')';

  this.emit('error', err);
};

/**
 * Calculate peer block inv type (filtered,
 * compact, witness, or non-witness).
 * @returns {Number}
 */

Peer.prototype.blockType = function blockType() {
  if (this.options.spv)
    return invTypes.FILTERED_BLOCK;

  if (this.outbound) {
    if (this.options.compact && this.compactMode !== -1) {
      if (!this.options.witness || this.compactWitness)
        return invTypes.CMPCT_BLOCK;
    }
  }

  if (this.haveWitness)
    return invTypes.WITNESS_BLOCK;

  return invTypes.BLOCK;
};

/**
 * Calculate peer tx inv type (witness or non-witness).
 * @returns {Number}
 */

Peer.prototype.txType = function txType() {
  if (this.haveWitness)
    return invTypes.WITNESS_TX;

  return invTypes.TX;
};

/**
 * Send `getdata` to peer.
 * @param {InvItem[]} items
 */

Peer.prototype.getData = function getData(items) {
  this.send(new packets.GetDataPacket(items));
};

/**
 * Send batched `getdata` to peer.
 * @param {InvType} type
 * @param {Hash[]} hashes
 */

Peer.prototype.getItems = function getItems(type, hashes) {
  var items = [];
  var i, hash;

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];
    items.push(new InvItem(type, hash));
  }

  this.getData(items);
};

/**
 * Send batched `getdata` to peer (blocks).
 * @param {Hash[]} hashes
 */

Peer.prototype.getBlock = function getBlock(hashes) {
  this.getItems(this.blockType(), hashes);
};

/**
 * Send batched `getdata` to peer (txs).
 * @param {Hash[]} hashes
 */

Peer.prototype.getTX = function getTX(hashes) {
  this.getItems(this.txType(), hashes);
};

/**
 * Handle a packet payload.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.handlePacket = co(function* handlePacket(packet) {
  var unlock;

  // We stop reads and lock the peer for any
  // packet with significant IO/asynchronocity.
  switch (packet.type) {
    case packetTypes.GETDATA:
    case packetTypes.GETBLOCKS:
    case packetTypes.GETHEADERS:
    case packetTypes.GETUTXOS:
    case packetTypes.GETBLOCKTXN:
      unlock = yield this.locker.lock();
      try {
        this.socket.pause();
        return yield this.onPacket(packet);
      } finally {
        this.socket.resume();
        unlock();
      }
      break;
    default:
      return yield this.onPacket(packet);
  }
});

/**
 * Handle a packet payload without a lock.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.onPacket = co(function* onPacket(packet) {
  var entry;

  if (this.destroyed)
    throw new Error('Destroyed peer sent a packet.');

  if (this.bip151
      && !this.bip151.completed
      && packet.type !== packetTypes.ENCINIT
      && packet.type !== packetTypes.ENCACK) {
    this.bip151.complete(new Error('Message before handshake.'));
  }

  if (this.bip150
      && !this.bip150.completed
      && packet.type !== packetTypes.AUTHCHALLENGE
      && packet.type !== packetTypes.AUTHREPLY
      && packet.type !== packetTypes.AUTHPROPOSE) {
    this.bip150.complete(new Error('Message before auth.'));
  }

  if (this.lastMerkle) {
    if (packet.type !== packetTypes.TX)
      this.flushMerkle();
  }

  entry = this.fulfill(packet);

  switch (packet.type) {
    case packetTypes.VERSION:
      yield this.handleVersion(packet);
      break;
    case packetTypes.VERACK:
      yield this.handleVerack(packet);
      break;
    case packetTypes.PING:
      yield this.handlePing(packet);
      break;
    case packetTypes.PONG:
      yield this.handlePong(packet);
      break;
    case packetTypes.ALERT:
      yield this.handleAlert(packet);
      break;
    case packetTypes.GETADDR:
      yield this.handleGetAddr(packet);
      break;
    case packetTypes.ADDR:
      yield this.handleAddr(packet);
      break;
    case packetTypes.INV:
      yield this.handleInv(packet);
      break;
    case packetTypes.GETDATA:
      yield this.handleGetData(packet);
      break;
    case packetTypes.NOTFOUND:
      yield this.handleNotFound(packet);
      break;
    case packetTypes.GETBLOCKS:
      yield this.handleGetBlocks(packet);
      break;
    case packetTypes.GETHEADERS:
      yield this.handleGetHeaders(packet);
      break;
    case packetTypes.HEADERS:
      yield this.handleHeaders(packet);
      break;
    case packetTypes.SENDHEADERS:
      yield this.handleSendHeaders(packet);
      break;
    case packetTypes.BLOCK:
      yield this.handleBlock(packet);
      break;
    case packetTypes.TX:
      yield this.handleTX(packet);
      break;
    case packetTypes.REJECT:
      yield this.handleReject(packet);
      break;
    case packetTypes.MEMPOOL:
      yield this.handleMempool(packet);
      break;
    case packetTypes.FILTERLOAD:
      yield this.handleFilterLoad(packet);
      break;
    case packetTypes.FILTERADD:
      yield this.handleFilterAdd(packet);
      break;
    case packetTypes.FILTERCLEAR:
      yield this.handleFilterClear(packet);
      break;
    case packetTypes.MERKLEBLOCK:
      yield this.handleMerkleBlock(packet);
      break;
    case packetTypes.GETUTXOS:
      yield this.handleGetUTXOs(packet);
      break;
    case packetTypes.UTXOS:
      yield this.handleUTXOs(packet);
      break;
    case packetTypes.HAVEWITNESS:
      yield this.handleHaveWitness(packet);
      break;
    case packetTypes.FEEFILTER:
      yield this.handleFeeFilter(packet);
      break;
    case packetTypes.SENDCMPCT:
      yield this.handleSendCmpct(packet);
      break;
    case packetTypes.CMPCTBLOCK:
      yield this.handleCmpctBlock(packet);
      break;
    case packetTypes.GETBLOCKTXN:
      yield this.handleGetBlockTxn(packet);
      break;
    case packetTypes.BLOCKTXN:
      yield this.handleBlockTxn(packet);
      break;
    case packetTypes.ENCINIT:
      yield this.handleEncinit(packet);
      break;
    case packetTypes.ENCACK:
      yield this.handleEncack(packet);
      break;
    case packetTypes.AUTHCHALLENGE:
      yield this.handleAuthChallenge(packet);
      break;
    case packetTypes.AUTHREPLY:
      yield this.handleAuthReply(packet);
      break;
    case packetTypes.AUTHPROPOSE:
      yield this.handleAuthPropose(packet);
      break;
    case packetTypes.UNKNOWN:
      yield this.handleUnknown(packet);
      break;
    default:
      assert(false, 'Bad packet type.');
      break;
  }

  if (entry)
    entry.resolve(packet);
});

/**
 * Flush merkle block once all matched
 * txs have been received.
 * @private
 */

Peer.prototype.flushMerkle = function flushMerkle() {
  assert(this.lastMerkle);
  this.lastBlock = util.ms();
  this.emit('merkleblock', this.lastMerkle);
  this.lastMerkle = null;
  this.waitingTX = 0;
};

/**
 * Handle `filterload` packet.
 * @private
 * @param {FilterLoadPacket}
 */

Peer.prototype.handleFilterLoad = co(function* handleFilterLoad(packet) {
  if (!packet.isWithinConstraints()) {
    this.increaseBan(100);
    return;
  }

  this.spvFilter = packet.filter;
  this.noRelay = false;
});

/**
 * Handle `filteradd` packet.
 * @private
 * @param {FilterAddPacket}
 */

Peer.prototype.handleFilterAdd = co(function* handleFilterAdd(packet) {
  var data = packet.data;

  if (data.length > constants.script.MAX_PUSH) {
    this.increaseBan(100);
    return;
  }

  if (this.spvFilter)
    this.spvFilter.add(data);

  this.noRelay = false;
});

/**
 * Handle `filterclear` packet.
 * @private
 * @param {FilterClearPacket}
 */

Peer.prototype.handleFilterClear = co(function* handleFilterClear(packet) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.noRelay = false;
});

/**
 * Handle `merkleblock` packet.
 * @private
 * @param {MerkleBlockPacket}
 */

Peer.prototype.handleMerkleBlock = co(function* handleMerkleBlock(packet) {
  var block = packet.block;

  // Potential DoS.
  if (!this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited merkleblock (%s).',
      this.hostname);
    this.increaseBan(100);
    return;
  }

  block.verifyPartial();

  this.lastMerkle = block;
  this.waitingTX = block.matches.length;

  if (this.waitingTX === 0)
    this.flushMerkle();
});

/**
 * Handle `feefilter` packet.
 * @private
 * @param {FeeFilterPacket}
 */

Peer.prototype.handleFeeFilter = co(function* handleFeeFilter(packet) {
  var rate = packet.rate;

  if (!(rate >= 0 && rate <= constants.MAX_MONEY)) {
    this.increaseBan(100);
    return;
  }

  this.feeRate = rate;

  this.emit('feefilter', rate);
});

/**
 * Handle `utxos` packet.
 * @private
 * @param {UTXOsPacket}
 */

Peer.prototype.handleUTXOs = co(function* handleUTXOs(utxos) {
  this.logger.debug('Received %d utxos (%s).',
    utxos.coins.length, this.hostname);
  this.emit('utxos', utxos);
});

/**
 * Handle `getutxos` packet.
 * @private
 */

Peer.prototype.handleGetUTXOs = co(function* handleGetUTXOs(packet) {
  var i, utxos, prevout, hash, index, coin;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (packet.prevout.length > 15)
    return;

  utxos = new packets.UTXOsPacket();

  for (i = 0; i < packet.prevout.length; i++) {
    prevout = packet.prevout[i];
    hash = prevout.hash;
    index = prevout.index;

    if (this.mempool && packet.mempool) {
      coin = this.mempool.getCoin(hash, index);

      if (coin) {
        utxos.hits.push(1);
        utxos.coins.push(coin);
        continue;
      }

      if (this.mempool.isSpent(hash, index)) {
        utxos.hits.push(0);
        continue;
      }
    }

    coin = yield this.chain.db.getCoin(hash, index);

    if (!coin) {
      utxos.hits.push(0);
      continue;
    }

    utxos.hits.push(1);
    utxos.coins.push(coin);
  }

  utxos.height = this.chain.height;
  utxos.tip = this.chain.tip.hash;

  this.send(utxos);
});

/**
 * Handle `havewitness` packet.
 * @private
 * @param {HaveWitnessPacket}
 */

Peer.prototype.handleHaveWitness = co(function* handleHaveWitness(packet) {
  this.haveWitness = true;
  this.emit('havewitness');
});

/**
 * Handle `getheaders` packet.
 * @private
 * @param {GetHeadersPacket}
 */

Peer.prototype.handleGetHeaders = co(function* handleGetHeaders(packet) {
  var headers = [];
  var hash, entry;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
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

    if (headers.length === 2000)
      break;

    if (entry.hash === packet.stop)
      break;

    entry = yield entry.getNext();
  }

  this.sendHeaders(headers);
});

/**
 * Handle `getblocks` packet.
 * @private
 * @param {GetBlocksPacket}
 */

Peer.prototype.handleGetBlocks = co(function* handleGetBlocks(packet) {
  var blocks = [];
  var hash;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

  hash = yield this.chain.findLocator(packet.locator);

  if (hash)
    hash = yield this.chain.db.getNextHash(hash);

  while (hash) {
    blocks.push(new InvItem(invTypes.BLOCK, hash));

    if (hash === packet.stop)
      break;

    if (blocks.length === 500) {
      this.hashContinue = hash;
      break;
    }

    hash = yield this.chain.db.getNextHash(hash);
  }

  this.sendInv(blocks);
});

/**
 * Handle `version` packet.
 * @private
 * @param {VersionPacket} packet
 */

Peer.prototype.handleVersion = co(function* handleVersion(packet) {
  if (this.version)
    throw new Error('Peer sent a duplicate version.');

  this.version = packet;
  this.noRelay = packet.noRelay;

  if (!this.network.selfConnect) {
    if (util.equal(packet.nonce, this.pool.localNonce))
      throw new Error('We connected to ourself. Oops.');
  }

  if (packet.version < constants.MIN_VERSION)
    throw new Error('Peer does not support required protocol version.');

  if (this.options.witness) {
    this.haveWitness = packet.hasWitness();
    if (!this.haveWitness && this.network.oldWitness) {
      try {
        yield this.wait(packetTypes.HAVEWITNESS, 10000);
      } catch (err) {
        ;
      }
    }
  }

  if (this.outbound) {
    if (!packet.hasNetwork())
      throw new Error('Peer does not support network services.');

    if (this.options.headers) {
      if (!packet.hasHeaders())
        throw new Error('Peer does not support getheaders.');
    }

    if (this.options.spv) {
      if (!packet.hasBloom())
        throw new Error('Peer does not support BIP37.');
    }

    if (this.options.witness) {
      if (!this.haveWitness)
        throw new Error('Peer does not support segregated witness.');
    }
  }

  this.send(new packets.VerackPacket());

  this.emit('version', packet);
});

/**
 * Handle `verack` packet.
 * @private
 * @param {VerackPacket}
 */

Peer.prototype.handleVerack = co(function* handleVerack(packet) {
  this.ack = true;
  this.emit('verack');
});

/**
 * Handle `mempool` packet.
 * @private
 * @param {MempoolPacket}
 */

Peer.prototype.handleMempool = co(function* handleMempool(packet) {
  var items = [];
  var i, hashes;

  if (!this.mempool)
    return;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++)
    items.push(new InvItem(invTypes.TX, hashes[i]));

  this.logger.debug('Sending mempool snapshot (%s).', this.hostname);

  this.sendInv(items);
});

/**
 * Get a block/tx from the broadcast map.
 * @private
 * @param {InvItem} item
 * @returns {Promise}
 */

Peer.prototype.getBroadcasted = function getBroadcasted(item) {
  var type = item.isTX() ? invTypes.TX : invTypes.BLOCK;
  var entry = this.pool.invMap[item.hash];

  if (!entry)
    return;

  if (type !== entry.type) {
    this.logger.debug(
      'Peer requested item with the wrong type (%s).',
      this.hostname);
    return;
  }

  this.logger.debug(
    'Peer requested %s %s as a %s packet (%s).',
    item.isTX() ? 'tx' : 'block',
    item.rhash(),
    item.hasWitness() ? 'witness' : 'normal',
    this.hostname);

  entry.ack(this);

  return entry.msg;
};

/**
 * Get a block/tx either from the broadcast map, mempool, or blockchain.
 * @private
 * @param {InvItem} item
 * @returns {Promise}
 */

Peer.prototype.getItem = co(function* getItem(item) {
  var entry = this.getBroadcasted(item);

  if (entry)
    return entry;

  if (this.options.selfish)
    return;

  if (item.isTX()) {
    if (!this.mempool)
      return;
    return this.mempool.getTX(item.hash);
  }

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

  return yield this.chain.db.getBlock(item.hash);
});

/**
 * Send a block from the broadcast list or chain.
 * @private
 * @param {InvItem} item
 * @returns {Boolean}
 */

Peer.prototype.sendBlock = co(function* sendBlock(item, witness) {
  var block = this.getBroadcasted(item);

  // Check for a broadcasted item first.
  if (block) {
    this.send(new packets.BlockPacket(block, witness));
    return true;
  }

  if (this.options.selfish
      || this.chain.db.options.spv
      || this.chain.db.options.prune) {
    return false;
  }

  // If we have the same serialization, we
  // can write the raw binary to the socket.
  if (witness === this.chain.db.options.witness) {
    block = yield this.chain.db.getRawBlock(item.hash);

    if (!block)
      return false;

    this.sendRaw('block', block);

    return true;
  }

  block = yield this.chain.db.getBlock(item.hash);

  if (!block)
    return false;

  this.send(new packets.BlockPacket(block, witness));

  return true;
});

/**
 * Send a compact block.
 * @private
 * @param {Block} block
 * @param {Boolean} witness
 * @returns {Boolean}
 */

Peer.prototype.sendCompactBlock = function sendCompactBlock(block, witness) {
  // Try again with a new nonce
  // if we get a siphash collision.
  for (;;) {
    try {
      block = BIP152.CompactBlock.fromBlock(block, witness);
    } catch (e) {
      continue;
    }
    break;
  }

  this.send(new packets.CmpctBlockPacket(block, witness));
};

/**
 * Handle `getdata` packet.
 * @private
 * @param {GetDataPacket}
 */

Peer.prototype.handleGetData = co(function* handleGetData(packet) {
  var notFound = [];
  var txs = 0;
  var blocks = 0;
  var unknown = -1;
  var items = packet.items;
  var i, j, item, tx, block, result, height;

  if (items.length > 50000)
    throw new Error('getdata size too large (' + items.length + ').');

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (item.isTX()) {
      tx = yield this.getItem(item);

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

      this.send(new packets.TXPacket(tx, item.hasWitness()));

      txs++;

      continue;
    }

    switch (item.type) {
      case invTypes.BLOCK:
      case invTypes.WITNESS_BLOCK:
        result = yield this.sendBlock(item, item.hasWitness());
        if (!result) {
          notFound.push(item);
          continue;
        }
        blocks++;
        break;
      case invTypes.FILTERED_BLOCK:
      case invTypes.WITNESS_FILTERED_BLOCK:
        if (!this.spvFilter) {
          notFound.push(item);
          continue;
        }

        block = yield this.getItem(item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        block = block.toMerkle(this.spvFilter);

        this.send(new packets.MerkleBlockPacket(block));

        for (j = 0; j < block.txs.length; j++) {
          tx = block.txs[j];
          this.send(new packets.TXPacket(tx, item.hasWitness()));
          txs++;
        }

        blocks++;

        break;
      case invTypes.CMPCT_BLOCK:
        height = yield this.chain.db.getHeight(item.hash);

        // Fallback to full block.
        if (height < this.chain.tip.height - 10) {
          result = yield this.sendBlock(item, this.compactWitness);
          if (!result) {
            notFound.push(item);
            continue;
          }
          blocks++;
          break;
        }

        block = yield this.getItem(item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        this.sendCompactBlock(block, this.compactWitness);

        blocks++;

        break;
      default:
        unknown = item.type;
        notFound.push(item);
        continue;
    }

    if (item.hash === this.hashContinue) {
      this.sendInv([new InvItem(invTypes.BLOCK, this.chain.tip.hash)]);
      this.hashContinue = null;
    }
  }

  if (notFound.length > 0)
    this.send(new packets.NotFoundPacket(notFound));

  if (txs > 0) {
    this.logger.debug(
      'Served %d txs with getdata (notfound=%d) (%s).',
      txs, notFound.length, this.hostname);
  }

  if (blocks > 0) {
    this.logger.debug(
      'Served %d blocks with getdata (notfound=%d) (%s).',
      blocks, notFound.length, this.hostname);
  }

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown getdata type: %s (%d).',
      unknown, this.hostname);
  }
});

/**
 * Handle `notfound` packet.
 * @private
 * @param {NotFoundPacket}
 */

Peer.prototype.handleNotFound = co(function* handleNotFound(packet) {
  this.emit('notfound', packet.items);
});

/**
 * Handle `addr` packet.
 * @private
 * @param {AddrPacket}
 */

Peer.prototype.handleAddr = co(function* handleAddr(packet) {
  var now = this.network.now();
  var addrs = packet.items;
  var i, addr;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    if (addr.ts <= 100000000 || addr.ts > now + 10 * 60)
      addr.ts = now - 5 * 24 * 60 * 60;

    this.addrFilter.add(addr.hostname, 'ascii');
  }

  this.logger.info(
    'Received %d addrs (hosts=%d, peers=%d) (%s).',
    addrs.length,
    this.pool.hosts.size(),
    this.pool.peers.size(),
    this.hostname);

  this.emit('addr', addrs);
});

/**
 * Handle `ping` packet.
 * @private
 * @param {PingPacket}
 */

Peer.prototype.handlePing = co(function* handlePing(packet) {
  this.emit('ping', this.minPing);
  if (packet.nonce)
    this.send(new packets.PongPacket(packet.nonce));
});

/**
 * Handle `pong` packet.
 * @private
 * @param {PongPacket}
 */

Peer.prototype.handlePong = co(function* handlePong(packet) {
  var nonce = packet.nonce;
  var now = util.ms();

  if (!this.challenge) {
    this.logger.debug('Peer sent an unsolicited pong (%s).', this.hostname);
    return;
  }

  if (!util.equal(nonce, this.challenge)) {
    if (util.equal(nonce, constants.ZERO_U64)) {
      this.logger.debug('Peer sent a zero nonce (%s).', this.hostname);
      this.challenge = null;
      return;
    }
    this.logger.debug('Peer sent the wrong nonce (%s).', this.hostname);
    return;
  }

  if (now >= this.lastPing) {
    this.lastPong = now;
    if (this.minPing === -1)
      this.minPing = now - this.lastPing;
    this.minPing = Math.min(this.minPing, now - this.lastPing);
  } else {
    this.logger.debug('Timing mismatch (what?) (%s).', this.hostname);
  }

  this.challenge = null;

  this.emit('pong', this.minPing);
});

/**
 * Handle `getaddr` packet.
 * @private
 * @param {GetAddrPacket}
 */

Peer.prototype.handleGetAddr = co(function* handleGetAddr(packet) {
  var items = [];
  var i, addrs, addr;

  if (this.options.selfish)
    return;

  if (this.sentAddr) {
    this.logger.debug('Ignoring repeated getaddr (%s).', this.hostname);
    return;
  }

  this.sentAddr = true;

  addrs = this.pool.hosts.toArray();

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    if (!this.addrFilter.added(addr.hostname, 'ascii'))
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
    this.hostname);

  this.send(new packets.AddrPacket(items));
});

/**
 * Handle `inv` packet.
 * @private
 * @param {InvPacket}
 */

Peer.prototype.handleInv = co(function* handleInv(packet) {
  var items = packet.items;
  var blocks = [];
  var txs = [];
  var unknown = -1;
  var i, item;

  if (items.length > 50000) {
    this.increaseBan(100);
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
    this.invFilter.add(item.hash, 'hex');
  }

  this.emit('inv', items);

  if (blocks.length > 0)
    this.emit('blocks', blocks);

  if (txs.length > 0)
    this.emit('txs', txs);

  this.logger.debug(
    'Received inv packet with %d items: blocks=%d txs=%d (%s).',
    items.length, blocks.length, txs.length, this.hostname);

  if (unknown !== -1) {
    this.logger.warning(
      'Peer sent an unknown inv type: %d (%s).',
      unknown, this.hostname);
  }
});

/**
 * Handle `headers` packet.
 * @private
 * @param {HeadersPacket}
 */

Peer.prototype.handleHeaders = co(function* handleHeaders(packet) {
  var headers = packet.items;

  this.logger.debug(
    'Received headers packet with %d items (%s).',
    headers.length, this.hostname);

  if (headers.length > 2000) {
    this.increaseBan(100);
    return;
  }

  this.emit('headers', headers);
});

/**
 * Handle `sendheaders` packet.
 * @private
 * @param {SendHeadersPacket}
 */

Peer.prototype.handleSendHeaders = co(function* handleSendHeaders(packet) {
  this.preferHeaders = true;
  this.emit('sendheaders');
});

/**
 * Handle `block` packet.
 * @private
 * @param {BlockPacket}
 */

Peer.prototype.handleBlock = co(function* handleBlock(packet) {
  if (this.options.spv) {
    this.logger.warning(
      'Peer sent unsolicited block (%s).',
      this.hostname);
    return;
  }

  this.lastBlock = util.ms();

  this.emit('block', packet.block);
});

/**
 * Handle `tx` packet.
 * @private
 * @param {TXPacket}
 */

Peer.prototype.handleTX = co(function* handleTX(packet) {
  var tx = packet.tx;

  if (this.lastMerkle) {
    if (this.lastMerkle.hasTX(tx)) {
      this.lastMerkle.addTX(tx);
      if (--this.waitingTX === 0)
        this.flushMerkle();
      return;
    }
  }

  this.emit('tx', tx);
});

/**
 * Handle `reject` packet.
 * @private
 * @param {RejectPacket} reject
 */

Peer.prototype.handleReject = co(function* handleReject(reject) {
  var entry;

  this.emit('reject', reject);

  if (!reject.hash)
    return;

  entry = this.pool.invMap[reject.hash];

  if (!entry)
    return;

  entry.reject(this);
});

/**
 * Handle `alert` packet.
 * @private
 * @param {AlertPacket}
 */

Peer.prototype.handleAlert = co(function* handleAlert(alert) {
  this.invFilter.add(alert.hash());
  this.emit('alert', alert);
});

/**
 * Handle `encinit` packet.
 * @private
 * @param {EncinitPacket}
 */

Peer.prototype.handleEncinit = co(function* handleEncinit(packet) {
  if (!this.bip151)
    return;

  this.bip151.encinit(packet.publicKey, packet.cipher);

  this.emit('encinit', packet);

  this.send(this.bip151.toEncack());
});

/**
 * Handle `encack` packet.
 * @private
 * @param {EncackPacket}
 */

Peer.prototype.handleEncack = co(function* handleEncack(packet) {
  if (!this.bip151)
    return;

  this.bip151.encack(packet.publicKey);

  this.emit('encack', packet);
});

/**
 * Handle `authchallenge` packet.
 * @private
 * @param {AuthChallengePacket}
 */

Peer.prototype.handleAuthChallenge = co(function* handleAuthChallenge(packet) {
  var sig;

  if (!this.bip150)
    return;

  sig = this.bip150.challenge(packet.hash);

  this.emit('authchallenge', packet.hash);

  this.send(new packets.AuthReplyPacket(sig));
});

/**
 * Handle `authreply` packet.
 * @private
 * @param {AuthReplyPacket}
 */

Peer.prototype.handleAuthReply = co(function* handleAuthReply(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.reply(packet.signature);

  if (hash)
    this.send(new packets.AuthProposePacket(hash));

  this.emit('authreply', packet.signature);
});

/**
 * Handle `authpropose` packet.
 * @private
 * @param {AuthProposePacket}
 */

Peer.prototype.handleAuthPropose = co(function* handleAuthPropose(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.propose(packet.hash);

  this.send(new packets.AuthChallengePacket(hash));

  this.emit('authpropose', packet.hash);
});

/**
 * Handle an unknown packet.
 * @private
 * @param {UnknownPacket}
 */

Peer.prototype.handleUnknown = co(function* handleUnknown(packet) {
  this.logger.warning('Unknown packet: %s.', packet.cmd);
  this.emit('unknown', packet);
});

/**
 * Handle `sendcmpct` packet.
 * @private
 * @param {SendCmpctPacket}
 */

Peer.prototype.handleSendCmpct = co(function* handleSendCmpct(packet) {
  var max = this.options.witness ? 2 : 1;

  if (packet.version > max) {
    // Ignore
    this.logger.info('Peer request compact blocks version %d (%s).',
      packet.version, this.hostname);
    return;
  }

  if (packet.mode > 1) {
    this.logger.info('Peer request compact blocks mode %d (%s).',
      packet.mode, this.hostname);
    return;
  }

  // Core witness nodes send this twice
  // with both version 1 and 2 (why
  // would you even _want_ non-witness
  // blocks if you use segwit??).
  if (this.compactMode !== -1)
    return;

  this.logger.info('Peer initialized compact blocks (%s).', this.hostname);

  this.compactMode = packet.mode;
  this.compactWitness = packet.version === 2;
  this.emit('sendcmpct', packet);
});

/**
 * Handle `cmpctblock` packet.
 * @private
 * @param {CmpctBlockPacket}
 */

Peer.prototype.handleCmpctBlock = co(function* handleCmpctBlock(packet) {
  var block = packet.block;
  var hash = block.hash('hex');
  var ret = new VerifyResult();
  var result;

  if (!this.options.compact) {
    this.logger.info('Peer sent unsolicited cmpctblock (%s).', this.hostname);
    return;
  }

  if (!this.mempool) {
    this.logger.warning('Requesting compact blocks without a mempool!');
    return;
  }

  if (this.compactBlocks[hash]) {
    this.logger.debug(
      'Peer sent us a duplicate compact block (%s).',
      this.hostname);
    return;
  }

  if (!block.verify(ret)) {
    this.logger.debug(
      'Peer sent an invalid compact block (%s).',
      this.hostname);
    this.reject(block, 'invalid', ret.reason, ret.score);
    return;
  }

  result = block.fillMempool(this.options.witness, this.mempool);

  if (result) {
    this.lastBlock = util.ms();
    this.emit('block', block.toBlock());
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash(), this.hostname);
    return;
  }

  if (this.compactAmount >= 10) {
    this.logger.warning('Compact block DoS attempt (%s).', this.hostname);
    this.destroy();
    return;
  }

  this.compactBlocks[hash] = block;
  this.compactAmount++;

  this.send(new packets.GetBlockTxnPacket(block.toRequest()));

  this.logger.debug(
    'Received semi-full compact block %s (%s).',
    block.rhash(), this.hostname);
});

/**
 * Handle `getblocktxn` packet.
 * @private
 * @param {GetBlockTxnPacket}
 */

Peer.prototype.handleGetBlockTxn = co(function* handleGetBlockTxn(packet) {
  var req = packet.request;
  var res, item, block, height;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

  if (this.options.selfish)
    return;

  item = new InvItem(invTypes.BLOCK, req.hash);

  block = yield this.getItem(item);

  if (!block) {
    this.logger.debug(
      'Peer sent getblocktxn for non-existent block (%s).',
      this.hostname);
    this.increaseBan(100);
    return;
  }

  height = yield this.chain.db.getHeight(req.hash);

  if (height < this.chain.tip.height - 15) {
    this.logger.debug(
      'Peer sent a getblocktxn for a block > 15 deep (%s)',
      this.hostname);
    return;
  }

  res = BIP152.TXResponse.fromBlock(block, req);

  this.send(new packets.BlockTxnPacket(res, this.compactWitness));

  this.emit('blocktxn', req);
});

/**
 * Handle `blocktxn` packet.
 * @private
 * @param {BlockTxnPacket}
 */

Peer.prototype.handleBlockTxn = co(function* handleBlockTxn(packet) {
  var res = packet.response;
  var block = this.compactBlocks[res.hash];

  if (!block) {
    this.logger.debug('Peer sent unsolicited blocktxn (%s).', this.hostname);
    this.compactBlocks = {};
    this.compactAmount = 0;
    return;
  }

  delete this.compactBlocks[res.hash];
  this.compactAmount--;

  if (!block.fillMissing(res)) {
    this.increaseBan(100);
    this.logger.warning('Peer sent non-full blocktxn (%s).', this.hostname);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash(), this.hostname);

  this.lastBlock = util.ms();

  this.emit('block', block.toBlock());
  this.emit('getblocktxn', res);
});

/**
 * Send an `alert` to peer.
 * @param {AlertPacket} alert
 */

Peer.prototype.sendAlert = function sendAlert(alert) {
  if (!this.ack)
    return;

  if (!this.invFilter.added(alert.hash()))
    return;

  this.send(alert);
};

/**
 * Send `getheaders` to peer. Note that unlike
 * `getblocks`, `getheaders` can have a null locator.
 * @param {Hash[]?} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.sendGetHeaders = function sendGetHeaders(locator, stop) {
  var packet = new packets.GetHeadersPacket(locator, stop);
  var height = -1;
  var hash = null;

  this.logger.debug(
    'Requesting headers packet from peer with getheaders (%s).',
    this.hostname);

  if (packet.locator.length > 0) {
    height = this.chain.checkHeight(packet.locator[0]);
    hash = util.revHex(packet.locator[0]);
  }

  if (stop)
    stop = util.revHex(stop);

  this.logger.debug(
    'Height: %d, Hash: %s, Stop: %s',
    height, hash, stop || null);

  this.send(packet);
};

/**
 * Send `getblocks` to peer.
 * @param {Hash[]} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.sendGetBlocks = function getBlocks(locator, stop) {
  var packet = new packets.GetBlocksPacket(locator, stop);
  var height = -1;
  var hash = null;

  this.logger.debug(
    'Requesting inv packet from peer with getblocks (%s).',
    this.hostname);

  if (packet.locator.length > 0) {
    height = this.chain.checkHeight(packet.locator[0]);
    hash = util.revHex(packet.locator[0]);
  }

  if (stop)
    stop = util.revHex(stop);

  this.logger.debug(
    'Height: %d, Hash: %s, Stop: %s',
    height, hash, stop || null);

  this.send(packet);
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.sendMempool = function sendMempool() {
  if (!this.ack)
    return;

  if (!this.version)
    return;

  if (!this.version.hasBloom()) {
    this.logger.debug(
      'Cannot request mempool for non-bloom peer (%s).',
      this.hostname);
    return;
  }

  this.logger.debug(
    'Requesting inv packet from peer with mempool (%s).',
    this.hostname);

  this.send(new packets.MempoolPacket());
};

/**
 * Send `reject` to peer.
 * @param {Number} code
 * @param {String} reason
 * @param {TX|Block} obj
 */

Peer.prototype.sendReject = function sendReject(code, reason, obj) {
  var reject = packets.RejectPacket.fromReason(code, reason, obj);

  if (obj) {
    this.logger.debug('Rejecting %s %s (%s): ccode=%s reason=%s.',
      reject.message, obj.rhash(), this.hostname, code, reason);
  } else {
    this.logger.debug('Rejecting packet from %s: ccode=%s reason=%s.',
      this.hostname, code, reason);
  }

  this.logger.debug(
    'Sending reject packet to peer (%s).',
    this.hostname);

  this.send(reject);
};

/**
 * Send a `sendcmpct` packet.
 */

Peer.prototype.sendCompact = function sendCompact() {
  var version = this.options.witness ? 2 : 1;
  this.logger.info('Initializing compact blocks (%s).', this.hostname);
  this.send(new packets.SendCmpctPacket(0, version));
};

/**
 * Increase banscore on peer.
 * @param {Number} score
 */

Peer.prototype.increaseBan = function increaseBan(score) {
  this.banScore += score;

  if (this.banScore >= this.pool.banScore) {
    this.logger.debug('Ban threshold exceeded (%s).', this.hostname);
    this.ban();
    return true;
  }

  return false;
};

/**
 * Ban peer.
 */

Peer.prototype.ban = function ban() {
  this.pool.ban(this.address);
};

/**
 * Send a `reject` packet to peer.
 * @see Framer.reject
 * @param {(TX|Block)?} obj
 * @param {String} code - cccode.
 * @param {String} reason
 * @param {Number} score
 */

Peer.prototype.reject = function reject(obj, code, reason, score) {
  this.sendReject(code, reason, obj);
  this.increaseBan(score);
};

/**
 * Send `getblocks` to peer after building
 * locator and resolving orphan root.
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash} orphan - Orphan hash to resolve.
 * @returns {Promise}
 */

Peer.prototype.resolveOrphan = co(function* resolveOrphan(tip, orphan) {
  var root, locator;

  assert(orphan);

  locator = yield this.chain.getLocator(tip);
  root = this.chain.getOrphanRoot(orphan);

  // Was probably resolved.
  if (!root) {
    this.logger.debug('Orphan root was already resolved.');
    return;
  }

  this.sendGetBlocks(locator, root);
});

/**
 * Send `getheaders` to peer after building locator.
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Peer.prototype.getHeaders = co(function* getHeaders(tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  this.sendGetHeaders(locator, stop);
});

/**
 * Send `getblocks` to peer after building locator.
 * @param {Hash} tip - Tip hash to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Peer.prototype.getBlocks = co(function* getBlocks(tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  this.sendGetBlocks(locator, stop);
});

/**
 * Start syncing from peer.
 * @returns {Promise}
 */

Peer.prototype.sync = co(function* sync() {
  var tip;

  if (!this.pool.syncing)
    return;

  if (!this.ack)
    return;

  if (this.syncSent)
    return;

  if (!this.version.hasNetwork())
    return;

  if (this.options.witness && !this.haveWitness)
    return;

  if (!this.isLoader()) {
    if (!this.chain.synced)
      return;
  }

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (this.isLoader() && this.chain.synced)
      this.sendMempool();
  }

  this.syncSent = true;

  this.lastBlock = util.ms();

  if (this.options.headers) {
    if (!this.chain.tip.isGenesis())
      tip = this.chain.tip.prevBlock;

    return yield this.getHeaders(tip);
  }

  return yield this.getBlocks();
});

/**
 * Inspect the peer.
 * @returns {String}
 */

Peer.prototype.inspect = function inspect() {
  return '<Peer:'
    + ' ack=' + this.ack
    + ' host=' + this.hostname
    + ' outbound=' + this.outbound
    + ' ping=' + this.minPing
    + '>';
};

/**
 * RequestEntry
 * @constructor
 */

function RequestEntry() {
  this.timeout = 0;
  this.jobs = [];
}

RequestEntry.prototype.addJob = function addJob(resolve, reject) {
  this.jobs.push(co.job(resolve, reject));
};

RequestEntry.prototype.setTimeout = function setTimeout(timeout) {
  this.timeout = util.ms() + timeout;
};

RequestEntry.prototype.reject = function reject(err) {
  var i, job;

  for (i = 0; i < this.jobs.length; i++) {
    job = this.jobs[i];
    job.reject(err);
  }

  this.jobs.length = 0;
};

RequestEntry.prototype.resolve = function resolve(result) {
  var i, job;

  for (i = 0; i < this.jobs.length; i++) {
    job = this.jobs[i];
    job.resolve(result);
  }

  this.jobs.length = 0;
};

/*
 * Expose
 */

module.exports = Peer;
