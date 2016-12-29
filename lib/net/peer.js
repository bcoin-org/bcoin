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
var List = require('../utils/list');
var NetAddress = require('../primitives/netaddress');
var invTypes = constants.inv;
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
 * @property {Boolean} relay - Whether to relay transactions
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
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = 0;
  this.lastSend = 0;
  this.lastRecv = 0;
  this.drainStart = 0;
  this.drainSize = 0;
  this.drainQueue = [];
  this.banScore = 0;

  this.version = null;
  this.preferHeaders = false;
  this.haveWitness = false;
  this.hashContinue = null;
  this.spvFilter = null;
  this.relay = true;
  this.feeRate = -1;
  this.bip151 = null;
  this.bip150 = null;
  this.compactMode = null;
  this.compactWitness = false;
  this.compactBlocks = {};
  this.lastMerkle = null;
  this.waitingTX = 0;
  this.syncSent = false;
  this.sentAddr = false;
  this.sentGetAddr = false;
  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;

  this.connectTimeout = null;
  this.pingTimer = null;
  this.pingInterval = 30000;
  this.stallTimer = null;
  this.stallInterval = 5000;

  this.addrFilter = new Bloom.Rolling(5000, 0.001);
  this.invFilter = new Bloom.Rolling(50000, 0.000001);

  this.requestTimeout = 10000;
  this.requestMap = {};

  this.queueBlock = new List();
  this.queueTX = new List();

  if (this.options.bip151) {
    this.bip151 = new BIP151();
    if (this.options.bip150) {
      this.bip150 = new BIP150(
        this.bip151,
        this.hostname,
        this.outbound,
        this.pool.auth,
        this.pool.identityKey);
      this.bip151.bip150 = this.bip150;
    }
  }

  this.parser = new Parser(this);
  this.framer = new Framer(this);

  this._init();
}

util.inherits(Peer, EventEmitter);

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
  // Mark address attempt.
  this.markAttempt();

  // Connect to peer.
  yield this.initConnect();
  yield this.initStall();

  // Mark address success.
  this.markSuccess();

  // Handshake.
  yield this.initBIP151();
  yield this.initBIP150();
  yield this.initVersion();
  yield this.finalize();

  assert(!this.destroyed);

  // Mark address ack.
  this.markAck();

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
  this.stallTimer = setInterval(function() {
    self.maybeStall();
  }, this.stallInterval);
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

  if (this.destroyed)
    throw new Error('Peer was destroyed during BIP150 handshake.');

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
  // Say hello.
  this.sendVersion();

  // Advertise our address.
  if (!this.pool.address.isNull()
      && !this.options.selfish
      && this.pool.server) {
    this.send(new packets.AddrPacket([this.pool.address]));
  }

  yield this.request('verack');

  if (this.destroyed)
    throw new Error('Peer was destroyed during version handshake.');

  // Wait for _their_ version.
  if (!this.version) {
    this.logger.debug(
      'Peer sent a verack without a version (%s).',
      this.hostname);

    yield this.request('version');

    if (this.destroyed)
      throw new Error('Peer was destroyed during version handshake.');

    assert(this.version);
  }

  if (!this.network.selfConnect) {
    if (util.equal(this.version.nonce, this.pool.localNonce))
      throw new Error('We connected to ourself. Oops.');
  }

  if (this.version.version < constants.MIN_VERSION)
    throw new Error('Peer does not support required protocol version.');

  if (this.options.witness) {
    this.haveWitness = this.version.hasWitness();
    if (!this.haveWitness && this.network.oldWitness) {
      try {
        yield this.request('havewitness');
        this.haveWitness = true;
      } catch (err) {
        ;
      }
    }
  }

  if (this.outbound) {
    if (!this.version.hasNetwork())
      throw new Error('Peer does not support network services.');

    if (this.options.headers) {
      if (!this.version.hasHeaders())
        throw new Error('Peer does not support getheaders.');
    }

    if (this.options.spv) {
      if (!this.version.hasBloom())
        throw new Error('Peer does not support BIP37.');
    }

    if (this.options.witness) {
      if (!this.haveWitness)
        throw new Error('Peer does not support segregated witness.');
    }
  }

  this.ack = true;

  this.logger.debug('Received verack (%s).', this.hostname);
});

/**
 * Handle `ack` event (called on verack).
 * @private
 */

Peer.prototype.finalize = co(function* finalize() {
  var self = this;

  // Setup the ping interval.
  this.pingTimer = setInterval(function() {
    self.sendPing();
  }, this.pingInterval);

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
    if (this.compactMode && this.compactMode.mode === 1) {
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
  if (!this.relay)
    return;

  if (!Array.isArray(txs))
    txs = [txs];

  for (i = 0; i < txs.length; i++) {
    tx = txs[i];

    assert(tx instanceof TX);

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

    // Don't send if they already have it.
    if (this.invFilter.test(tx.hash()))
      continue;

    inv.push(tx.toInv());
  }

  this.sendInv(inv);
};

/**
 * Announce broadcast list to peer.
 */

Peer.prototype.announceList = function announceList() {
  var txs = [];
  var blocks = [];
  var item;

  for (item = this.pool.invItems.head; item; item = item.next) {
    switch (item.type) {
      case invTypes.TX:
        txs.push(item.msg);
        break;
      case invTypes.BLOCK:
        blocks.push(item.msg);
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
  var i, item, chunk;

  if (!this.ack)
    return;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];
    this.invFilter.add(item.hash, 'hex');
  }

  if (items.length === 0)
    return;

  this.logger.spam('Serving %d inv items to %s.',
    items.length, this.hostname);

  for (i = 0; i < items.length; i += 50000) {
    chunk = items.slice(i, i + 50000);
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
  packet.relay = this.options.relay;
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
  var i, keys, cmd, queue, entry, hash;

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

  if (this.stallTimer != null) {
    clearInterval(this.stallTimer);
    this.stallTimer = null;
  }

  if (this.connectTimeout != null) {
    clearTimeout(this.connectTimeout);
    this.connectTimeout = null;
  }

  keys = Object.keys(this.requestMap);

  for (i = 0; i < keys.length; i++) {
    cmd = keys[i];
    queue = this.requestMap[cmd];
    for (entry = queue.head; entry; entry = entry.next)
      entry.stop();
    delete this.requestMap[cmd];
  }

  keys = Object.keys(this.compactBlocks);

  for (i = 0; i < keys.length; i++) {
    hash = keys[i];
    entry = this.compactBlocks[hash];
    entry.destroy();
  }

  this.locker.destroy();

  this.emit('close');
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
 * @param {Function} resolve
 * @param {Function} reject
 */

Peer.prototype.needsDrain = function needsDrain(size) {
  if (this.maybeStall()) {
    this.error('Peer stalled (drain).');
    this.destroy();
    return;
  }

  this.drainStart = util.now();
  this.drainSize += size;

  if (this.drainSize >= (5 << 20)) {
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

  if (util.now() < this.drainStart + 10)
    return false;

  this.drainSize = 0;
  this.error('Peer stalled.');
  this.destroy();

  return true;
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
 * Wait for a packet to be received from peer.
 * @private
 * @param {String} cmd - Packet name.
 * @returns {Promise} - Returns Object(payload).
 * Executed on timeout or once packet is received.
 */

Peer.prototype.request = function request(cmd) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var entry;

    if (self.destroyed)
      return reject(new Error('Request destroyed.'));

    entry = new RequestEntry(self, cmd, resolve, reject);

    if (!self.requestMap[cmd])
      self.requestMap[cmd] = new List();

    self.requestMap[cmd].push(entry);
  });
};

/**
 * Fulfill awaiting requests created with {@link Peer#request}.
 * @private
 * @param {String} cmd - Packet name.
 * @param {Object} payload
 */

Peer.prototype.response = function response(cmd, payload) {
  var queue = this.requestMap[cmd];
  var entry;

  if (!queue)
    return false;

  entry = queue.shift();
  assert(entry);

  if (queue.size === 0)
    delete this.requestMap[cmd];

  entry.stop();
  entry.resolve(payload);

  return true;
};

/**
 * Calculate peer block inv type (filtered,
 * compact, witness, or non-witness).
 * @returns {Number}
 */

Peer.prototype.blockType = function blockType() {
  if (this.options.spv)
    return invTypes.FILTERED_BLOCK;

  if (this.options.compact && this.compactMode) {
    if (!this.options.witness || this.compactWitness)
      return invTypes.CMPCT_BLOCK;
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
 * @param {LoadRequest[]} items
 */

Peer.prototype.getData = function getData(items) {
  var inv = [];
  var i, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];
    inv.push(item.toInv());
  }

  this.send(new packets.GetDataPacket(inv));
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

  this.lastRecv = util.ms();

  switch (packet.type) {
    case packetTypes.VERSION:
      return yield this.handleVersion(packet);
    case packetTypes.VERACK:
      return yield this.handleVerack(packet);
    case packetTypes.PING:
      return yield this.handlePing(packet);
    case packetTypes.PONG:
      return yield this.handlePong(packet);
    case packetTypes.ALERT:
      return yield this.handleAlert(packet);
    case packetTypes.GETADDR:
      return yield this.handleGetAddr(packet);
    case packetTypes.ADDR:
      return yield this.handleAddr(packet);
    case packetTypes.INV:
      return yield this.handleInv(packet);
    case packetTypes.GETDATA:
      return yield this.handleGetData(packet);
    case packetTypes.NOTFOUND:
      return yield this.handleNotFound(packet);
    case packetTypes.GETBLOCKS:
      return yield this.handleGetBlocks(packet);
    case packetTypes.GETHEADERS:
      return yield this.handleGetHeaders(packet);
    case packetTypes.HEADERS:
      return yield this.handleHeaders(packet);
    case packetTypes.SENDHEADERS:
      return yield this.handleSendHeaders(packet);
    case packetTypes.BLOCK:
      return yield this.handleBlock(packet);
    case packetTypes.TX:
      return yield this.handleTX(packet);
    case packetTypes.REJECT:
      return yield this.handleReject(packet);
    case packetTypes.MEMPOOL:
      return yield this.handleMempool(packet);
    case packetTypes.FILTERLOAD:
      return yield this.handleFilterLoad(packet);
    case packetTypes.FILTERADD:
      return yield this.handleFilterAdd(packet);
    case packetTypes.FILTERCLEAR:
      return yield this.handleFilterClear(packet);
    case packetTypes.MERKLEBLOCK:
      return yield this.handleMerkleBlock(packet);
    case packetTypes.GETUTXOS:
      return yield this.handleGetUTXOs(packet);
    case packetTypes.UTXOS:
      return yield this.handleUTXOs(packet);
    case packetTypes.HAVEWITNESS:
      return yield this.handleHaveWitness(packet);
    case packetTypes.FEEFILTER:
      return yield this.handleFeeFilter(packet);
    case packetTypes.SENDCMPCT:
      return yield this.handleSendCmpct(packet);
    case packetTypes.CMPCTBLOCK:
      return yield this.handleCmpctBlock(packet);
    case packetTypes.GETBLOCKTXN:
      return yield this.handleGetBlockTxn(packet);
    case packetTypes.BLOCKTXN:
      return yield this.handleBlockTxn(packet);
    case packetTypes.ENCINIT:
      return yield this.handleEncinit(packet);
    case packetTypes.ENCACK:
      return yield this.handleEncack(packet);
    case packetTypes.AUTHCHALLENGE:
      return yield this.handleAuthChallenge(packet);
    case packetTypes.AUTHREPLY:
      return yield this.handleAuthReply(packet);
    case packetTypes.AUTHPROPOSE:
      return yield this.handleAuthPropose(packet);
    case packetTypes.UNKNOWN:
      return yield this.handleUnknown(packet);
    default:
      assert(false, 'Bad packet type.');
      break;
  }
});

/**
 * Flush merkle block once all matched
 * txs have been received.
 * @private
 */

Peer.prototype.flushMerkle = function flushMerkle() {
  assert(this.lastMerkle);
  this.fire('merkleblock', this.lastMerkle);
  this.lastMerkle = null;
  this.waitingTX = 0;
};

/**
 * Emit an event and fulfill a response.
 * @param {String} cmd
 * @param {Object} payload
 */

Peer.prototype.fire = function fire(cmd, payload) {
  this.response(cmd, payload);
  this.emit(cmd, payload);
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
  this.relay = true;
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

  this.relay = true;
});

/**
 * Handle `filterclear` packet.
 * @private
 * @param {FilterClearPacket}
 */

Peer.prototype.handleFilterClear = co(function* handleFilterClear(packet) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.relay = true;
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

  this.fire('feefilter', rate);
});

/**
 * Handle `utxos` packet.
 * @private
 * @param {UTXOsPacket}
 */

Peer.prototype.handleUTXOs = co(function* handleUTXOs(utxos) {
  this.logger.debug('Received %d utxos (%s).',
    utxos.coins.length, this.hostname);
  this.fire('utxos', utxos);
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
  this.fire('havewitness');
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
 * @param {VersionPacket}
 */

Peer.prototype.handleVersion = co(function* handleVersion(version) {
  if (this.version)
    throw new Error('Peer sent a duplicate version.');

  this.relay = version.relay;
  this.version = version;

  this.send(new packets.VerackPacket());

  this.fire('version', version);
});

/**
 * Handle `verack` packet.
 * @private
 * @param {VerackPacket}
 */

Peer.prototype.handleVerack = co(function* handleVerack(packet) {
  this.fire('verack');
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
  var entry = this.pool.invMap[item.hash];

  if (!entry)
    return;

  this.logger.debug(
    'Peer requested %s %s as a %s packet (%s).',
    entry.type === invTypes.TX ? 'tx' : 'block',
    util.revHex(entry.hash),
    item.hasWitness() ? 'witness' : 'normal',
    this.hostname);

  entry.ack(this);

  if (item.isTX()) {
    if (entry.type !== invTypes.TX)
      return;
  } else {
    if (entry.type !== invTypes.BLOCK)
      return;
  }

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
        // Fallback to full block.
        height = yield this.chain.db.getHeight(item.hash);
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

        yield this.sendCompactBlock(block, this.compactWitness);

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
  this.fire('notfound', packet.items);
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

  this.fire('addr', addrs);
});

/**
 * Handle `ping` packet.
 * @private
 * @param {PingPacket}
 */

Peer.prototype.handlePing = co(function* handlePing(packet) {
  this.fire('ping', this.minPing);
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

  this.fire('pong', this.minPing);
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
      case invTypes.TX:
        txs.push(item.hash);
        break;
      case invTypes.BLOCK:
        blocks.push(item.hash);
        break;
      default:
        unknown = item.type;
        continue;
    }
    this.invFilter.add(item.hash, 'hex');
  }

  this.fire('inv', items);

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

  this.fire('headers', headers);
});

/**
 * Handle `sendheaders` packet.
 * @private
 * @param {SendHeadersPacket}
 */

Peer.prototype.handleSendHeaders = co(function* handleSendHeaders(packet) {
  this.preferHeaders = true;
  this.fire('sendheaders');
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

  this.fire('block', packet.block);
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

  this.fire('tx', tx);
});

/**
 * Handle `reject` packet.
 * @private
 * @param {RejectPacket} reject
 */

Peer.prototype.handleReject = co(function* handleReject(reject) {
  var entry;

  this.fire('reject', reject);

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
  this.fire('alert', alert);
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

  this.fire('encinit', packet);

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

  this.fire('encack', packet);
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

  this.fire('authchallenge', packet.hash);

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

  this.fire('authreply', packet.signature);
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

  this.fire('authpropose', packet.hash);
});

/**
 * Handle an unknown packet.
 * @private
 * @param {UnknownPacket}
 */

Peer.prototype.handleUnknown = co(function* handleUnknown(packet) {
  this.logger.warning('Unknown packet: %s.', packet.cmd);
  this.fire('unknown', packet);
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
  if (this.compactMode)
    return;

  this.logger.info('Peer initialized compact blocks (%s).', this.hostname);

  this.compactMode = packet;
  this.compactWitness = packet.version === 2;
  this.fire('sendcmpct', packet);
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
    this.fire('block', block.toBlock());
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash(), this.hostname);
    return;
  }

  this.compactBlocks[hash] = block;

  this.send(new packets.GetBlockTxnPacket(block.toRequest()));

  this.logger.debug(
    'Received semi-full compact block %s (%s).',
    block.rhash(), this.hostname);

  try {
    yield block.wait(10000);
  } catch (e) {
    this.logger.debug(
      'Compact block timed out: %s (%s).',
      block.rhash(), this.hostname);

    delete this.compactBlocks[hash];
  }
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

  this.fire('blocktxn', req);
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
    return;
  }

  block.complete();

  delete this.compactBlocks[res.hash];

  if (!block.fillMissing(res)) {
    this.increaseBan(100);
    this.logger.warning('Peer sent non-full blocktxn (%s).', this.hostname);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash(), this.hostname);

  this.fire('block', block.toBlock());
  this.fire('getblocktxn', res);
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
 * Mark connection attempt.
 */

Peer.prototype.markAttempt = function markAttempt() {
  this.pool.hosts.markAttempt(this.hostname);
};

/**
 * Mark connection success.
 */

Peer.prototype.markSuccess = function markSuccess() {
  this.pool.hosts.markSuccess(this.hostname);
};

/**
 * Mark ack success.
 */

Peer.prototype.markAck = function markAck() {
  assert(this.version);
  this.pool.hosts.markAck(this.hostname, this.version.services);
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
    + ' id=' + this.id
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

function RequestEntry(peer, cmd, resolve, reject) {
  this.peer = peer;
  this.cmd = cmd;
  this.resolve = resolve;
  this.reject = reject;
  this.onTimeout = this._onTimeout.bind(this);
  this.timeout = setTimeout(this.onTimeout, this.peer.requestTimeout);
  this.prev = null;
  this.next = null;
}

RequestEntry.prototype._onTimeout = function _onTimeout() {
  var queue = this.peer.requestMap[this.cmd];

  if (!queue)
    return;

  if (queue.remove(this)) {
    if (queue.size === 0)
      delete this.peer.requestMap[this.cmd];
    this.reject(new Error('Timed out: ' + this.cmd));
  }
};

RequestEntry.prototype.stop = function stop() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
};

/*
 * Expose
 */

module.exports = Peer;
