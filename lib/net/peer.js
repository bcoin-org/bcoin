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
var Map = require('../utils/map');
var Parser = require('./parser');
var Framer = require('./framer');
var packets = require('./packets');
var consensus = require('../protocol/consensus');
var common = require('./common');
var InvItem = require('../primitives/invitem');
var Lock = require('../utils/lock');
var Bloom = require('../utils/bloom');
var BIP151 = require('./bip151');
var BIP150 = require('./bip150');
var BIP152 = require('./bip152');
var Block = require('../primitives/block');
var TX = require('../primitives/tx');
var encoding = require('../utils/encoding');
var NetAddress = require('../primitives/netaddress');
var services = common.services;
var invTypes = InvItem.types;
var packetTypes = packets.types;

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
 * @property {Number} version
 * @property {Boolean} destroyed
 * @property {Boolean} ack - Whether verack has been received.
 * @property {Boolean} connected
 * @property {Number} ts
 * @property {Boolean} preferHeaders - Whether the peer has
 * requested getheaders.
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
  this.options = this.pool.options;
  this.network = this.pool.network;
  this.logger = this.pool.logger;
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.locker = new Lock();
  this.next = null;
  this.prev = null;

  this.socket = null;
  this.outbound = false;
  this.address = new NetAddress();
  this.connected = false;
  this.destroyed = false;
  this.ack = false;
  this.handshake = false;
  this.ts = 0;
  this.lastSend = 0;
  this.lastRecv = 0;
  this.drainStart = 0;
  this.drainSize = 0;
  this.drainQueue = [];
  this.banScore = 0;
  this.invQueue = [];

  this.version = -1;
  this.services = 0;
  this.height = -1;
  this.agent = null;
  this.noRelay = false;
  this.preferHeaders = false;
  this.hashContinue = null;
  this.spvFilter = null;
  this.feeRate = -1;
  this.bip151 = null;
  this.bip150 = null;
  this.compactMode = -1;
  this.compactWitness = false;
  this.merkleBlock = null;
  this.merkleTime = -1;
  this.merkleMatches = 0;
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

  this.requestMap = new Map();
  this.responseMap = new Map();
  this.compactBlocks = new Map();

  if (this.options.bip151) {
    this.bip151 = new BIP151();
    if (this.options.bip150) {
      this.bip150 = new BIP150(
        this.bip151,
        this.hostname,
        this.outbound,
        this.pool.authdb,
        this.options.identityKey);
      this.bip151.bip150 = this.bip150;
    }
  }

  this.parser = new Parser(this);
  this.framer = new Framer(this);

  this._init();
}

util.inherits(Peer, EventEmitter);

/**
 * Max output bytes buffered before
 * invoking stall behavior for peer.
 * @const {Number}
 * @default
 */

Peer.DRAIN_MAX = 5 << 20;

/**
 * Timeout for peer to read from
 * their end of the socket.
 * @const {Number}
 * @default
 */

Peer.DRAIN_TIMEOUT = 10000;

/**
 * Interval to check for drainage
 * and required responses from peer.
 * @const {Number}
 * @default
 */

Peer.STALL_INTERVAL = 5000;

/**
 * Interval for pinging peers.
 * @const {Number}
 * @default
 */

Peer.PING_INTERVAL = 30000;

/**
 * Interval to flush invs.
 * Higher means more invs (usually
 * txs) will be accumulated before
 * flushing.
 * @const {Number}
 * @default
 */

Peer.INV_INTERVAL = 5000;

/**
 * Required time for peers to
 * respond to messages (i.e.
 * getblocks/getdata).
 * @const {Number}
 * @default
 */

Peer.RESPONSE_TIMEOUT = 30000;

/**
 * Getter to retrieve host.
 * @function
 * @name host(get)
 * @memberof Peer#
 * @returns {String}
 */

Peer.prototype.__defineGetter__('host', function() {
  return this.address.host;
});

/**
 * Getter to retrieve port.
 * @function
 * @name port(get)
 * @memberof Peer#
 * @returns {Number}
 */

Peer.prototype.__defineGetter__('port', function() {
  return this.address.port;
});

/**
 * Getter to retrieve hostname.
 * @function
 * @name hostname(get)
 * @memberof Peer#
 * @returns {Number}
 */

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
      yield self.readPacket(packet);
    } catch (e) {
      self.error(e);
      self.destroy();
    }
  }));

  this.parser.on('error', function(err) {
    self.error(err);
    self.sendReject('malformed', 'error parsing message');
    self.increaseBan(10);
  });

  if (this.bip151) {
    this.bip151.on('error', function(err) {
      self.error(err);
      self.destroy();
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
  var proxy = this.options.proxyServer;
  var socket;

  assert(!this.socket);

  socket = this.options.createSocket(addr.port, addr.host, proxy);

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
  assert(!this.destroyed);

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
  assert(!this.destroyed);

  if (!this.bip150)
    return;

  assert(this.bip151);
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

  if (!this.ack) {
    yield this.wait(packetTypes.VERACK, 10000);
    assert(this.ack);
  }

  // Wait for _their_ version.
  if (this.version === -1) {
    this.logger.debug(
      'Peer sent a verack without a version (%s).',
      this.hostname);

    yield this.wait(packetTypes.VERSION, 10000);

    assert(this.version !== -1);
  }

  this.handshake = true;

  this.logger.debug('Version handshake complete (%s).', this.hostname);
});

/**
 * Finalize peer after handshake.
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

  if (!this.handshake)
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
      this.sendCompactBlock(block);
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

  if (!this.handshake)
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
 * Send inv to a peer.
 * @param {InvItem[]} items
 */

Peer.prototype.sendInv = function sendInv(items) {
  var hasBlock = false;
  var i, item;

  if (!this.handshake)
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

  if (!this.handshake)
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
 * Send a compact block.
 * @private
 * @param {Block} block
 * @returns {Boolean}
 */

Peer.prototype.sendCompactBlock = function sendCompactBlock(block) {
  var witness = this.compactWitness;

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
 * Send a `version` packet.
 */

Peer.prototype.sendVersion = function sendVersion() {
  var packet = new packets.VersionPacket();
  packet.version = this.options.version;
  packet.services = this.options.services;
  packet.ts = this.network.now();
  packet.recv = this.address;
  packet.from = this.pool.address;
  packet.nonce = this.pool.nonce;
  packet.agent = this.options.agent;
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
  if (!this.handshake)
    return;

  if (this.version <= 60000) {
    this.send(new packets.PingPacket());
    return;
  }

  if (this.challenge) {
    this.logger.debug('Peer has not responded to ping (%s).', this.hostname);
    return;
  }

  this.lastPing = util.ms();
  this.challenge = util.nonce();

  this.send(new packets.PingPacket(this.challenge));
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.sendFilterLoad = function sendFilterLoad(filter) {
  if (!this.handshake)
    return;

  if (!this.options.spv)
    return;

  if (!(this.services & services.BLOOM))
    return;

  this.send(new packets.FilterLoadPacket(filter));
};

/**
 * Set a fee rate filter for the peer.
 * @param {Rate} rate
 */

Peer.prototype.sendFeeRate = function sendFeeRate(rate) {
  if (!this.handshake)
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

  keys = this.responseMap.keys();

  for (i = 0; i < keys.length; i++) {
    cmd = keys[i];
    entry = this.responseMap.get(cmd);
    this.responseMap.remove(cmd);
    entry.reject(new Error('Peer was destroyed.'));
  }

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

  if (!this.outbound)
    return;

  switch (packet.type) {
    case packetTypes.MEMPOOL:
      this.request(packetTypes.INV, timeout);
      break;
    case packetTypes.GETBLOCKS:
      if (!this.chain.synced)
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
  var keys = this.responseMap.keys();
  var now = util.ms();
  var i, key, entry, name;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.responseMap.get(key);
    if (now > entry.timeout) {
      name = packets.typesByVal[key];
      this.error('Peer is stalling (%s).', name.toLowerCase());
      this.destroy();
      return;
    }
  }

  if (this.merkleBlock) {
    assert(this.merkleTime !== -1);
    if (now > this.merkleTime + 60000) {
      this.error('Peer is stalling (merkleblock).');
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
  var entry = this.responseMap.get(type);

  if (this.destroyed)
    return;

  if (!entry) {
    entry = new RequestEntry();
    this.responseMap.set(type, entry);
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
  var entry = this.responseMap.get(type);

  if (!entry)
    return;

  this.responseMap.remove(type);

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

  if (typeof err.code === 'string' && err.code[0] === 'E') {
    msg = err.code;
    err = new Error(msg);
    err.code = msg;
    err.message = 'Socket Error: ' + msg;
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

  if (this.outbound && this.chain.synced) {
    if (this.options.compact && this.compactMode !== -1) {
      if (!this.options.witness || this.compactWitness)
        return invTypes.CMPCT_BLOCK;
    }
  }

  if (this.hasWitness())
    return invTypes.WITNESS_BLOCK;

  return invTypes.BLOCK;
};

/**
 * Calculate peer tx inv type (witness or non-witness).
 * @returns {Number}
 */

Peer.prototype.txType = function txType() {
  if (this.hasWitness())
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

  if (items.length === 0)
    return;

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

Peer.prototype.readPacket = co(function* readPacket(packet) {
  var unlock = yield this.locker.lock();
  try {
    this.socket.pause();
    return yield this.handlePacket(packet);
  } finally {
    this.socket.resume();
    unlock();
  }
});

/**
 * Handle a packet payload without a lock.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.handlePacket = co(function* handlePacket(packet) {
  var entry;

  if (this.destroyed)
    throw new Error('Destroyed peer sent a packet.');

  if (this.bip151
      && this.bip151.job
      && !this.bip151.completed
      && packet.type !== packetTypes.ENCINIT
      && packet.type !== packetTypes.ENCACK) {
    this.bip151.reject(new Error('Message before handshake.'));
  }

  if (this.bip150
      && this.bip150.job
      && !this.bip150.completed
      && packet.type !== packetTypes.AUTHCHALLENGE
      && packet.type !== packetTypes.AUTHREPLY
      && packet.type !== packetTypes.AUTHPROPOSE) {
    this.bip150.reject(new Error('Message before auth.'));
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

  if (packet.type === packetTypes.UNKNOWN) {
    this.emit('unknown', packet);
    return;
  }

  this.emit(packet.cmd, packet);
});

/**
 * Handle `filterload` packet.
 * @private
 * @param {FilterLoadPacket} packet
 */

Peer.prototype.handleFilterLoad = co(function* handleFilterLoad(packet) {
  if (!packet.isWithinConstraints()) {
    this.increaseBan(100);
    return;
  }

  this.spvFilter = packet.filter;
  this.noRelay = false;

  yield this.pool.handleFilterLoad(this, packet);
});

/**
 * Handle `filteradd` packet.
 * @private
 * @param {FilterAddPacket} packet
 */

Peer.prototype.handleFilterAdd = co(function* handleFilterAdd(packet) {
  var data = packet.data;

  if (data.length > consensus.MAX_SCRIPT_PUSH) {
    this.increaseBan(100);
    return;
  }

  if (this.spvFilter)
    this.spvFilter.add(data);

  this.noRelay = false;

  yield this.pool.handleFilterAdd(this, packet);
});

/**
 * Handle `filterclear` packet.
 * @private
 * @param {FilterClearPacket} packet
 */

Peer.prototype.handleFilterClear = co(function* handleFilterClear(packet) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.noRelay = false;

  yield this.pool.handleFilterClear(this, packet);
});

/**
 * Handle `merkleblock` packet.
 * @private
 * @param {MerkleBlockPacket} packet
 */

Peer.prototype.handleMerkleBlock = co(function* handleMerkleBlock(packet) {
  yield this.pool.handleMerkleBlock(this, packet);
});

/**
 * Handle `feefilter` packet.
 * @private
 * @param {FeeFilterPacket} packet
 */

Peer.prototype.handleFeeFilter = co(function* handleFeeFilter(packet) {
  var rate = packet.rate;

  if (!(rate >= 0 && rate <= consensus.MAX_MONEY)) {
    this.increaseBan(100);
    return;
  }

  this.feeRate = rate;

  yield this.pool.handleFeeFilter(this, packet);
});

/**
 * Handle `getheaders` packet.
 * @private
 * @param {GetHeadersPacket} packet
 */

Peer.prototype.handleGetHeaders = co(function* handleGetHeaders(packet) {
  yield this.pool.handleGetHeaders(this, packet);
});

/**
 * Handle `getblocks` packet.
 * @private
 * @param {GetBlocksPacket} packet
 */

Peer.prototype.handleGetBlocks = co(function* handleGetBlocks(packet) {
  yield this.pool.handleGetBlocks(this, packet);
});

/**
 * Handle `version` packet.
 * @private
 * @param {VersionPacket} packet
 */

Peer.prototype.handleVersion = co(function* handleVersion(packet) {
  if (this.version !== -1)
    throw new Error('Peer sent a duplicate version.');

  this.version = packet.version;
  this.services = packet.services;
  this.height = packet.height;
  this.agent = packet.agent;
  this.noRelay = packet.noRelay;

  if (!this.network.selfConnect) {
    if (util.equal(packet.nonce, this.pool.nonce))
      throw new Error('We connected to ourself. Oops.');
  }

  if (this.version < common.MIN_VERSION)
    throw new Error('Peer does not support required protocol version.');

  if (this.outbound) {
    if (!(this.services & services.NETWORK))
      throw new Error('Peer does not support network services.');

    if (this.options.headers) {
      if (this.version < common.HEADERS_VERSION)
        throw new Error('Peer does not support getheaders.');
    }

    if (this.options.spv) {
      if (!(this.services & services.BLOOM))
        throw new Error('Peer does not support BIP37.');

      if (this.version < common.BLOOM_VERSION)
        throw new Error('Peer does not support BIP37.');
    }

    if (this.options.witness) {
      if (!(this.services & services.WITNESS))
        throw new Error('Peer does not support segregated witness.');
    }
  }

  this.send(new packets.VerackPacket());

  yield this.pool.handleVersion(this, packet);
});

/**
 * Handle `verack` packet.
 * @private
 * @param {VerackPacket} packet
 */

Peer.prototype.handleVerack = co(function* handleVerack(packet) {
  if (this.ack) {
    this.logger.debug('Peer sent duplicate ack (%s).', this.hostname);
    return;
  }

  this.ack = true;
  this.logger.debug('Received verack (%s).', this.hostname);

  yield this.pool.handleVerack(this, packet);
});

/**
 * Handle `mempool` packet.
 * @private
 * @param {MempoolPacket} packet
 */

Peer.prototype.handleMempool = co(function* handleMempool(packet) {
  yield this.pool.handleMempool(this, packet);
});

/**
 * Handle `getdata` packet.
 * @private
 * @param {GetDataPacket} packet
 */

Peer.prototype.handleGetData = co(function* handleGetData(packet) {
  yield this.pool.handleGetData(this, packet);
});

/**
 * Handle `notfound` packet.
 * @private
 * @param {NotFoundPacket} packet
 */

Peer.prototype.handleNotFound = co(function* handleNotFound(packet) {
  yield this.pool.handleNotFound(this, packet);
});

/**
 * Handle `addr` packet.
 * @private
 * @param {AddrPacket} packet
 */

Peer.prototype.handleAddr = co(function* handleAddr(packet) {
  yield this.pool.handleAddr(this, packet);
});

/**
 * Handle `ping` packet.
 * @private
 * @param {PingPacket} packet
 */

Peer.prototype.handlePing = co(function* handlePing(packet) {
  if (packet.nonce)
    this.send(new packets.PongPacket(packet.nonce));
  yield this.pool.handlePing(this, packet);
});

/**
 * Handle `pong` packet.
 * @private
 * @param {PongPacket} packet
 */

Peer.prototype.handlePong = co(function* handlePong(packet) {
  var nonce = packet.nonce;
  var now = util.ms();

  if (!this.challenge) {
    this.logger.debug('Peer sent an unsolicited pong (%s).', this.hostname);
    return;
  }

  if (!util.equal(nonce, this.challenge)) {
    if (util.equal(nonce, encoding.ZERO_U64)) {
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

  yield this.pool.handlePong(this, packet);
});

/**
 * Handle `getaddr` packet.
 * @private
 * @param {GetAddrPacket} packet
 */

Peer.prototype.handleGetAddr = co(function* handleGetAddr(packet) {
  yield this.pool.handleGetAddr(this, packet);
});

/**
 * Handle `inv` packet.
 * @private
 * @param {InvPacket} packet
 */

Peer.prototype.handleInv = co(function* handleInv(packet) {
  yield this.pool.handleInv(this, packet);
});

/**
 * Handle `headers` packet.
 * @private
 * @param {HeadersPacket} packet
 */

Peer.prototype.handleHeaders = co(function* handleHeaders(packet) {
  yield this.pool.handleHeaders(this, packet);
});

/**
 * Handle `sendheaders` packet.
 * @private
 * @param {SendHeadersPacket} packet
 */

Peer.prototype.handleSendHeaders = co(function* handleSendHeaders(packet) {
  this.preferHeaders = true;
  yield this.pool.handleSendHeaders(this, packet);
});

/**
 * Handle `block` packet.
 * @private
 * @param {BlockPacket} packet
 */

Peer.prototype.handleBlock = co(function* handleBlock(packet) {
  yield this.pool.handleBlock(this, packet);
});

/**
 * Handle `tx` packet.
 * @private
 * @param {TXPacket} packet
 */

Peer.prototype.handleTX = co(function* handleTX(packet) {
  yield this.pool.handleTX(this, packet);
});

/**
 * Handle `reject` packet.
 * @private
 * @param {RejectPacket} packet
 */

Peer.prototype.handleReject = co(function* handleReject(packet) {
  yield this.pool.handleReject(this, packet);
});

/**
 * Handle `encinit` packet.
 * @private
 * @param {EncinitPacket} packet
 */

Peer.prototype.handleEncinit = co(function* handleEncinit(packet) {
  if (!this.bip151)
    return;

  this.bip151.encinit(packet.publicKey, packet.cipher);

  this.send(this.bip151.toEncack());

  yield this.pool.handleEncinit(this, packet);
});

/**
 * Handle `encack` packet.
 * @private
 * @param {EncackPacket} packet
 */

Peer.prototype.handleEncack = co(function* handleEncack(packet) {
  if (!this.bip151)
    return;

  this.bip151.encack(packet.publicKey);

  yield this.pool.handleEncack(this, packet);
});

/**
 * Handle `authchallenge` packet.
 * @private
 * @param {AuthChallengePacket} packet
 */

Peer.prototype.handleAuthChallenge = co(function* handleAuthChallenge(packet) {
  var sig;

  if (!this.bip150)
    return;

  sig = this.bip150.challenge(packet.hash);

  this.send(new packets.AuthReplyPacket(sig));

  yield this.pool.handleAuthChallenge(this, packet);
});

/**
 * Handle `authreply` packet.
 * @private
 * @param {AuthReplyPacket} packet
 */

Peer.prototype.handleAuthReply = co(function* handleAuthReply(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.reply(packet.signature);

  if (hash)
    this.send(new packets.AuthProposePacket(hash));

  yield this.pool.handleAuthReply(this, packet);
});

/**
 * Handle `authpropose` packet.
 * @private
 * @param {AuthProposePacket} packet
 */

Peer.prototype.handleAuthPropose = co(function* handleAuthPropose(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.propose(packet.hash);

  this.send(new packets.AuthChallengePacket(hash));

  yield this.pool.handleAuthPropose(this, packet);
});

/**
 * Handle an unknown packet.
 * @private
 * @param {UnknownPacket} packet
 */

Peer.prototype.handleUnknown = co(function* handleUnknown(packet) {
  yield this.pool.handleUnknown(this, packet);
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

  yield this.pool.handleSendCmpct(this, packet);
});

/**
 * Handle `cmpctblock` packet.
 * @private
 * @param {CmpctBlockPacket}
 */

Peer.prototype.handleCmpctBlock = co(function* handleCmpctBlock(packet) {
  yield this.pool.handleCmpctBlock(this, packet);
});

/**
 * Handle `getblocktxn` packet.
 * @private
 * @param {GetBlockTxnPacket}
 */

Peer.prototype.handleGetBlockTxn = co(function* handleGetBlockTxn(packet) {
  yield this.pool.handleGetBlockTxn(this, packet);
});

/**
 * Handle `blocktxn` packet.
 * @private
 * @param {BlockTxnPacket}
 */

Peer.prototype.handleBlockTxn = co(function* handleBlockTxn(packet) {
  yield this.pool.handleBlockTxn(this, packet);
});

/**
 * Send `getheaders` to peer. Note that unlike
 * `getblocks`, `getheaders` can have a null locator.
 * @param {Hash[]?} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.sendGetHeaders = function sendGetHeaders(locator, stop) {
  var packet = new packets.GetHeadersPacket(locator, stop);
  var hash = null;
  var end = null;

  if (packet.locator.length > 0)
    hash = util.revHex(packet.locator[0]);

  if (stop)
    end = util.revHex(stop);

  this.logger.debug(
    'Requesting headers packet from peer with getheaders (%s).',
    this.hostname);

  this.logger.debug(
    'Sending getheaders (hash=%s, stop=%s).',
    hash, end);

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
  var end = null;

  if (packet.locator.length > 0) {
    height = this.chain.checkHeight(packet.locator[0]);
    hash = util.revHex(packet.locator[0]);
  }

  if (stop)
    end = util.revHex(stop);

  this.logger.debug(
    'Requesting inv packet from peer with getblocks (%s).',
    this.hostname);

  this.logger.debug(
    'Sending getblocks (height=%d, hash=%s, stop=%s).',
    height, hash, end);

  this.send(packet);
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.sendMempool = function sendMempool() {
  if (!this.handshake)
    return;

  if (!(this.services & services.BLOOM)) {
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
 * @param {TX|Block} msg
 */

Peer.prototype.sendReject = function sendReject(code, reason, msg) {
  var reject = packets.RejectPacket.fromReason(code, reason, msg);

  if (msg) {
    this.logger.debug('Rejecting %s %s (%s): ccode=%s reason=%s.',
      reject.message, msg.rhash(), this.hostname, code, reason);
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
 * @param {Number} mode
 */

Peer.prototype.sendCompact = function sendCompact(mode) {
  var version = this.options.witness ? 2 : 1;
  this.logger.info('Initializing compact blocks (%s).', this.hostname);
  this.send(new packets.SendCmpctPacket(mode, version));
};

/**
 * Increase banscore on peer.
 * @param {Number} score
 */

Peer.prototype.increaseBan = function increaseBan(score) {
  this.banScore += score;

  if (this.banScore >= this.options.banScore) {
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
 * @param {(TX|Block)?} msg
 * @param {String} code
 * @param {String} reason
 * @param {Number} score
 */

Peer.prototype.reject = function reject(msg, code, reason, score) {
  this.sendReject(code, reason, msg);
  this.increaseBan(score);
};

/**
 * Start syncing from peer.
 * @returns {Promise}
 */

Peer.prototype.sync = co(function* sync() {
  var locator, tip, checkpoint;

  if (!this.pool.syncing)
    return false;

  if (!this.handshake)
    return false;

  if (this.syncSent)
    return false;

  if (!(this.services & services.NETWORK))
    return false;

  if (this.options.witness && !this.hasWitness())
    return false;

  if (!this.isLoader()) {
    if (!this.chain.synced)
      return false;
  }

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (this.isLoader() && this.chain.synced)
      this.sendMempool();
  }

  this.syncSent = true;

  this.lastBlock = util.ms();

  if (this.pool.headersFirst) {
    tip = this.chain.tip;
    checkpoint = this.pool.nextCheckpoint;
    this.sendGetHeaders([tip.hash], checkpoint.hash);
    return true;
  }

  locator = yield this.chain.getLocator();

  this.sendGetBlocks(locator);

  return true;
});

/**
 * Test whether required services are available.
 * @param {Number} services
 * @returns {Boolean}
 */

Peer.prototype.hasServices = function hasServices(services) {
  return (this.services & services) === services;
};

/**
 * Test whether the WITNESS service bit is set.
 * @returns {Boolean}
 */

Peer.prototype.hasWitness = function hasWitness() {
  return (this.services & services.WITNESS) !== 0;
};

/**
 * Inspect the peer.
 * @returns {String}
 */

Peer.prototype.inspect = function inspect() {
  return '<Peer:'
    + ' handshake=' + this.handshake
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
