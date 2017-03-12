/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
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
var Network = require('../protocol/network');
var Logger = require('../node/logger');
var tcp = require('./tcp');
var services = common.services;
var invTypes = InvItem.types;
var packetTypes = packets.types;

/**
 * Represents a remote peer.
 * @alias module:net.Peer
 * @constructor
 * @param {PeerOptions} options
 * @property {net.Socket} socket
 * @property {NetAddress} address
 * @property {Parser} parser
 * @property {Framer} framer
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

function Peer(options) {
  if (!(this instanceof Peer))
    return new Peer(options);

  EventEmitter.call(this);

  this.options = options;
  this.network = this.options.network;
  this.logger = this.options.logger.context('peer');
  this.locker = new Lock();

  this.parser = new Parser(this.network);
  this.framer = new Framer(this.network);

  this.socket = null;
  this.opened = false;
  this.outbound = false;
  this.loader = false;
  this.address = new NetAddress();
  this.local = new NetAddress();
  this.connected = false;
  this.destroyed = false;
  this.ack = false;
  this.handshake = false;
  this.ts = 0;
  this.lastSend = 0;
  this.lastRecv = 0;
  this.drainSize = 0;
  this.drainQueue = [];
  this.banScore = 0;
  this.invQueue = [];
  this.onPacket = null;

  this.next = null;
  this.prev = null;

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
  this.merkleMap = null;
  this.syncing = false;
  this.sentAddr = false;
  this.sentGetAddr = false;
  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;
  this.blockTime = -1;

  this.bestHash = null;
  this.bestHeight = -1;

  this.connectTimeout = null;
  this.pingTimer = null;
  this.invTimer = null;
  this.stallTimer = null;

  this.addrFilter = new Bloom.Rolling(5000, 0.001);
  this.invFilter = new Bloom.Rolling(50000, 0.000001);

  this.blockMap = new Map();
  this.txMap = new Map();
  this.responseMap = new Map();
  this.compactBlocks = new Map();

  this._init();
}

util.inherits(Peer, EventEmitter);

/**
 * Max output bytes buffered before
 * invoking stall behavior for peer.
 * @const {Number}
 * @default
 */

Peer.DRAIN_MAX = 10 << 20;

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
 * Required time for loader to
 * respond with block/merkleblock.
 * @const {Number}
 * @default
 */

Peer.BLOCK_TIMEOUT = 120000;

/**
 * Required time for loader to
 * respond with a tx.
 * @const {Number}
 * @default
 */

Peer.TX_TIMEOUT = 120000;

/**
 * Generic timeout interval.
 * @const {Number}
 * @default
 */

Peer.TIMEOUT_INTERVAL = 20 * 60000;

/**
 * Create inbound peer from socket.
 * @param {PeerOptions} options
 * @param {net.Socket} socket
 * @returns {Peer}
 */

Peer.fromInbound = function fromInbound(options, socket) {
  var peer = new Peer(options);
  peer.accept(socket);
  return peer;
};

/**
 * Create outbound peer from net address.
 * @param {PeerOptions} options
 * @param {NetAddress} addr
 * @returns {Peer}
 */

Peer.fromOutbound = function fromOutbound(options, addr) {
  var peer = new Peer(options);
  peer.connect(addr);
  return peer;
};

/**
 * Create a peer from options.
 * @param {Object} options
 * @returns {Peer}
 */

Peer.fromOptions = function fromOptions(options) {
  return new Peer(new PeerOptions(options));
};

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
    if (self.destroyed)
      return;

    self.error(err);
    self.sendReject('malformed', 'error parsing message');
    self.increaseBan(10);
  });
};

/**
 * Getter to retrieve hostname.
 * @returns {String}
 */

Peer.prototype.hostname = function hostname() {
  return this.address.hostname;
};

/**
 * Frame a payload with a header.
 * @param {String} cmd - Packet type.
 * @param {Buffer} payload
 * @returns {Buffer} Payload with header prepended.
 */

Peer.prototype.framePacket = function framePacket(cmd, payload, checksum) {
  if (this.bip151 && this.bip151.handshake)
    return this.bip151.packet(cmd, payload);
  return this.framer.packet(cmd, payload, checksum);
};

/**
 * Feed data to the parser.
 * @param {Buffer} data
 */

Peer.prototype.feedParser = function feedParser(data) {
  if (this.bip151 && this.bip151.handshake)
    return this.bip151.feed(data);
  return this.parser.feed(data);
};

/**
 * Set BIP151 cipher type.
 * @param {Number} cipher
 */

Peer.prototype.setCipher = function setCipher(cipher) {
  var self = this;

  assert(!this.bip151, 'BIP151 already set.');
  assert(this.socket, 'Peer must be initialized with a socket.');
  assert(!this.opened, 'Cannot set cipher after open.');

  this.bip151 = new BIP151(cipher);

  this.bip151.on('error', function(err) {
    self.error(err);
    self.destroy();
  });

  this.bip151.on('rekey', function() {
    if (self.destroyed)
      return;

    self.logger.debug('Rekeying with peer (%s).', self.hostname());
    self.send(self.bip151.toRekey());
  });

  this.bip151.on('packet', function(cmd, body) {
    var payload;
    try {
      payload = self.parser.parsePayload(cmd, body);
    } catch (e) {
      self.parser.error(e);
      return;
    }
    self.parser.emit('packet', payload);
  });
};

/**
 * Set BIP150 auth.
 * @param {AuthDB} db
 * @param {Buffer} key
 */

Peer.prototype.setAuth = function setAuth(db, key) {
  var bip151 = this.bip151;
  var hostname = this.hostname();
  var outbound = this.outbound;

  assert(this.bip151, 'BIP151 not set.');
  assert(!this.bip150, 'BIP150 already set.');
  assert(this.socket, 'Peer must be initialized with a socket.');
  assert(!this.opened, 'Cannot set auth after open.');

  this.bip150 = new BIP150(bip151, hostname, outbound, db, key);
  this.bip151.bip150 = this.bip150;
};

/**
 * Bind to socket.
 * @param {net.Socket} socket
 */

Peer.prototype.bind = function bind(socket) {
  var self = this;

  assert(!this.socket);

  this.socket = socket;

  this.socket.once('error', function(err) {
    if (!self.connected)
      return;

    self.error(err);
    self.destroy();
  });

  this.socket.once('close', function() {
    self.error('Socket hangup.');
    self.destroy();
  });

  this.socket.on('drain', function() {
    self.handleDrain();
  });

  this.socket.on('data', function(chunk) {
    self.lastRecv = util.ms();
    self.feedParser(chunk);
  });

  this.socket.setNoDelay(true);
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
  this.ts = util.ms();
  this.outbound = false;
  this.connected = true;

  this.bind(socket);

  return socket;
};

/**
 * Create the socket and begin connecting. This method
 * will use `options.createSocket` if provided.
 * @param {NetAddress} addr
 * @returns {net.Socket}
 */

Peer.prototype.connect = function connect(addr) {
  var socket;

  assert(!this.socket);

  socket = this.options.createSocket(addr.port, addr.host);

  this.address = addr;
  this.outbound = true;
  this.connected = false;

  this.bind(socket);

  return socket;
};

/**
 * Open and perform initial handshake (without rejection).
 * @method
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
 * @method
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
 * @method
 * @returns {Promise}
 */

Peer.prototype._open = co(function* open() {
  this.opened = true;

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
 * @returns {Promise}
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
      self.ts = util.ms();
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
 * @returns {Promise}
 */

Peer.prototype.initStall = function initStall() {
  var self = this;
  assert(!this.stallTimer);
  assert(!this.destroyed);
  this.stallTimer = setInterval(function() {
    self.maybeTimeout();
  }, Peer.STALL_INTERVAL);
  return Promise.resolve();
};

/**
 * Handle `connect` event (called immediately
 * if a socket was passed into peer).
 * @method
 * @private
 * @returns {Promise}
 */

Peer.prototype.initBIP151 = co(function* initBIP151() {
  assert(!this.destroyed);

  // Send encinit. Wait for handshake to complete.
  if (!this.bip151)
    return;

  assert(!this.bip151.completed);

  this.logger.info('Attempting BIP151 handshake (%s).', this.hostname());

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
    this.logger.info('BIP151 handshake complete (%s).', this.hostname());
    this.logger.info('Connection is encrypted (%s).', this.hostname());
  }
});

/**
 * Handle post bip151-handshake.
 * @method
 * @private
 * @returns {Promise}
 */

Peer.prototype.initBIP150 = co(function* initBIP150() {
  assert(!this.destroyed);

  if (!this.bip150)
    return;

  assert(this.bip151);
  assert(!this.bip150.completed);

  if (!this.bip151.handshake)
    throw new Error('BIP151 handshake was not completed for BIP150.');

  this.logger.info('Attempting BIP150 handshake (%s).', this.hostname());

  if (this.bip150.outbound) {
    if (!this.bip150.peerIdentity)
      throw new Error('No known identity for peer.');
    this.send(this.bip150.toChallenge());
  }

  yield this.bip150.wait(3000);

  assert(!this.destroyed);
  assert(this.bip150.completed);

  if (this.bip150.auth) {
    this.logger.info('BIP150 handshake complete (%s).', this.hostname());
    this.logger.info('Peer is authed (%s): %s.',
      this.hostname(), this.bip150.getAddress());
  }
});

/**
 * Handle post handshake.
 * @method
 * @private
 * @returns {Promise}
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
      this.hostname());

    yield this.wait(packetTypes.VERSION, 10000);

    assert(this.version !== -1);
  }

  if (this.destroyed)
    throw new Error('Peer was destroyed during handshake.');

  this.handshake = true;

  this.logger.debug('Version handshake complete (%s).', this.hostname());
});

/**
 * Finalize peer after handshake.
 * @method
 * @private
 * @returns {Promise}
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

  this.queueInv(inv);
};

/**
 * Broadcast transactions to peer.
 * @param {TX[]} txs
 */

Peer.prototype.announceTX = function announceTX(txs) {
  var inv = [];
  var i, tx, hash, rate;

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
    if (this.feeRate !== -1) {
      hash = tx.hash('hex');
      rate = this.options.getRate(hash);
      if (rate !== -1 && rate < this.feeRate)
        continue;
    }

    inv.push(tx.toInv());
  }

  this.queueInv(inv);
};

/**
 * Send inv to a peer.
 * @param {InvItem[]} items
 */

Peer.prototype.queueInv = function queueInv(items) {
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

  if (this.destroyed)
    return;

  if (queue.length === 0)
    return;

  this.invQueue.length = 0;

  this.logger.spam('Serving %d inv items to %s.',
    queue.length, this.hostname());

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
 * Force send an inv (no filter check).
 * @param {InvItem[]} items
 */

Peer.prototype.sendInv = function sendInv(items) {
  var i, item, chunk;

  if (!this.handshake)
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
    items.length, this.hostname());

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
    items.length, this.hostname());

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
  var compact = BIP152.CompactBlock.fromBlock(block, witness);
  this.send(new packets.CmpctBlockPacket(compact, witness));
};

/**
 * Send a `version` packet.
 */

Peer.prototype.sendVersion = function sendVersion() {
  var packet = new packets.VersionPacket();
  packet.version = this.options.version;
  packet.services = this.options.services;
  packet.ts = this.network.now();
  packet.remote = this.address;
  packet.local.setNull();
  packet.local.services = this.options.services;
  packet.nonce = this.options.createNonce(this.hostname());
  packet.agent = this.options.agent;
  packet.height = this.options.getHeight();
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

  if (this.version <= common.PONG_VERSION) {
    this.send(new packets.PingPacket());
    return;
  }

  if (this.challenge) {
    this.logger.debug('Peer has not responded to ping (%s).', this.hostname());
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
  var i, keys, cmd, entry, jobs, job;

  if (this.destroyed)
    return;

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

  jobs = this.drainQueue;

  this.drainSize = 0;
  this.drainQueue = [];

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.reject(new Error('Peer was destroyed.'));
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
 */

Peer.prototype.write = function write(data) {
  if (this.destroyed)
    throw new Error('Peer is destroyed (write).');

  this.lastSend = util.ms();

  if (this.socket.write(data) === false)
    this.needsDrain(data.length);
};

/**
 * Send a packet.
 * @param {Packet} packet
 */

Peer.prototype.send = function send(packet) {
  var tx, checksum;

  if (this.destroyed)
    throw new Error('Peer is destroyed (send).');

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

  this.addTimeout(packet);
};

/**
 * Send a packet.
 * @param {Packet} packet
 */

Peer.prototype.sendRaw = function sendRaw(cmd, body, checksum) {
  var payload = this.framePacket(cmd, body, checksum);
  this.write(payload);
};

/**
 * Wait for a drain event.
 * @returns {Promise}
 */

Peer.prototype.drain = function drain() {
  var self = this;

  if (this.destroyed)
    return Promise.reject(new Error('Peer is destroyed.'));

  if (this.drainSize === 0)
    return Promise.resolve();

  return new Promise(function(resolve, reject) {
    self.drainQueue.push(co.job(resolve, reject));
  });
};

/**
 * Handle drain event.
 * @private
 */

Peer.prototype.handleDrain = function handleDrain() {
  var jobs = this.drainQueue;
  var i, job;

  this.drainSize = 0;

  if (jobs.length === 0)
    return;

  this.drainQueue = [];

  for (i = 0; i < jobs.length; i++) {
    job = jobs[i];
    job.resolve();
  }
};

/**
 * Add to drain counter.
 * @private
 * @param {Number} size
 */

Peer.prototype.needsDrain = function needsDrain(size) {
  this.drainSize += size;

  if (this.drainSize >= Peer.DRAIN_MAX) {
    this.logger.warning(
      'Peer is not reading: %dmb buffered (%s).',
      util.mb(this.drainSize),
      this.hostname());
    this.error('Peer stalled (drain).');
    this.destroy();
  }
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
      if (!this.options.isFull())
        this.request(packetTypes.INV, timeout);
      break;
    case packetTypes.GETHEADERS:
      this.request(packetTypes.HEADERS, timeout * 2);
      break;
    case packetTypes.GETDATA:
      this.request(packetTypes.DATA, timeout * 2);
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
  var i, key, entry, name, ts, block, mult;

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
    if (now > this.merkleTime + Peer.BLOCK_TIMEOUT) {
      this.error('Peer is stalling (merkleblock).');
      this.destroy();
      return;
    }
  }

  if (this.syncing && this.loader && !this.options.isFull()) {
    if (now > this.blockTime + Peer.BLOCK_TIMEOUT) {
      this.error('Peer is stalling (block).');
      this.destroy();
      return;
    }
  }

  if (this.options.isFull() || !this.syncing) {
    keys = this.blockMap.keys();

    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      ts = this.blockMap.get(key);
      if (now > ts + Peer.BLOCK_TIMEOUT) {
        this.error('Peer is stalling (block).');
        this.destroy();
        return;
      }
    }

    keys = this.txMap.keys();

    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      ts = this.txMap.get(key);
      if (now > ts + Peer.TX_TIMEOUT) {
        this.error('Peer is stalling (tx).');
        this.destroy();
        return;
      }
    }

    keys = this.compactBlocks.keys();

    for (i = 0; i < keys.length; i++) {
      key = keys[i];
      block = this.compactBlocks.get(key);
      if (now > block.now + Peer.RESPONSE_TIMEOUT) {
        this.error('Peer is stalling (blocktxn).');
        this.destroy();
        return;
      }
    }
  }

  if (now > this.ts + 60000) {
    assert(this.ts !== 0);

    if (this.lastRecv === 0 || this.lastSend === 0) {
      this.error('Peer is stalling (no message).');
      this.destroy();
      return;
    }

    if (now > this.lastSend + Peer.TIMEOUT_INTERVAL) {
      this.error('Peer is stalling (send).');
      this.destroy();
      return;
    }

    mult = this.version <= common.PONG_VERSION ? 4 : 1;

    if (now > this.lastRecv + Peer.TIMEOUT_INTERVAL * mult) {
      this.error('Peer is stalling (recv).');
      this.destroy();
      return;
    }

    if (this.challenge && now > this.lastPing + Peer.TIMEOUT_INTERVAL) {
      this.error('Peer is stalling (ping).');
      this.destroy();
      return;
    }
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

    if (self.destroyed) {
      reject(new Error('Peer is destroyed (request).'));
      return;
    }

    entry = self.request(type);

    entry.setTimeout(timeout);
    entry.addJob(resolve, reject);
  });
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

  err.message += ' (' + this.hostname() + ')';

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

  if (this.options.compact
      && this.hasCompactSupport()
      && this.hasCompact()) {
    return invTypes.CMPCT_BLOCK;
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
 * Send `getdata` to peer for a single block.
 * @param {Hash} hash
 */

Peer.prototype.getFullBlock = function getFullBlock(hash) {
  var type = invTypes.BLOCK;

  assert(!this.options.spv);

  if (this.hasWitness())
    type |= InvItem.WITNESS_FLAG;

  this.getItems(type, [hash]);
};

/**
 * Handle a packet payload.
 * @method
 * @private
 * @param {Packet} packet
 */

Peer.prototype.readPacket = co(function* readPacket(packet) {
  var unlock;

  if (this.destroyed)
    return;

  // The "pre-handshake" packets get
  // to bypass the lock, since they
  // are meant to change the way input
  // is handled at a low level. They
  // must be handled immediately.
  switch (packet.type) {
    case packetTypes.ENCINIT:
    case packetTypes.ENCACK:
    case packetTypes.AUTHCHALLENGE:
    case packetTypes.AUTHREPLY:
    case packetTypes.AUTHPROPOSE:
      try {
        this.socket.pause();
        yield this.handlePacket(packet);
      } finally {
        if (!this.destroyed)
          this.socket.resume();
      }
      break;
    default:
      unlock = yield this.locker.lock();
      try {
        this.socket.pause();
        yield this.handlePacket(packet);
      } finally {
        if (!this.destroyed)
          this.socket.resume();
        unlock();
      }
      break;
  }
});

/**
 * Handle a packet payload without a lock.
 * @method
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
    this.bip151.reject(new Error('Message before BIP151 handshake.'));
  }

  if (this.bip150
      && this.bip150.job
      && !this.bip150.completed
      && packet.type !== packetTypes.AUTHCHALLENGE
      && packet.type !== packetTypes.AUTHREPLY
      && packet.type !== packetTypes.AUTHPROPOSE) {
    this.bip150.reject(new Error('Message before BIP150 auth.'));
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
    case packetTypes.SENDHEADERS:
      yield this.handleSendHeaders(packet);
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
    case packetTypes.FEEFILTER:
      yield this.handleFeeFilter(packet);
      break;
    case packetTypes.SENDCMPCT:
      yield this.handleSendCmpct(packet);
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
  }

  if (this.onPacket)
    yield this.onPacket(packet);

  this.emit('packet', packet);

  if (entry)
    entry.resolve(packet);
});

/**
 * Handle `version` packet.
 * @method
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
  this.local = packet.remote;

  if (!this.network.selfConnect) {
    if (this.options.hasNonce(packet.nonce))
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

    if (this.options.hasWitness()) {
      if (!(this.services & services.WITNESS))
        throw new Error('Peer does not support segregated witness.');
    }

    if (this.options.compact) {
      if (!this.hasCompactSupport()) {
        this.logger.debug(
          'Peer does not support compact blocks (%s).',
          this.hostname());
      }
    }
  }

  this.send(new packets.VerackPacket());
});

/**
 * Handle `verack` packet.
 * @method
 * @private
 * @param {VerackPacket} packet
 */

Peer.prototype.handleVerack = co(function* handleVerack(packet) {
  if (this.ack) {
    this.logger.debug('Peer sent duplicate ack (%s).', this.hostname());
    return;
  }

  this.ack = true;
  this.logger.debug('Received verack (%s).', this.hostname());
});

/**
 * Handle `ping` packet.
 * @method
 * @private
 * @param {PingPacket} packet
 */

Peer.prototype.handlePing = co(function* handlePing(packet) {
  if (!packet.nonce)
    return;

  this.send(new packets.PongPacket(packet.nonce));
});

/**
 * Handle `pong` packet.
 * @method
 * @private
 * @param {PongPacket} packet
 */

Peer.prototype.handlePong = co(function* handlePong(packet) {
  var nonce = packet.nonce;
  var now = util.ms();

  if (!this.challenge) {
    this.logger.debug('Peer sent an unsolicited pong (%s).', this.hostname());
    return;
  }

  if (!util.equal(nonce, this.challenge)) {
    if (util.equal(nonce, encoding.ZERO_U64)) {
      this.logger.debug('Peer sent a zero nonce (%s).', this.hostname());
      this.challenge = null;
      return;
    }
    this.logger.debug('Peer sent the wrong nonce (%s).', this.hostname());
    return;
  }

  if (now >= this.lastPing) {
    this.lastPong = now;
    if (this.minPing === -1)
      this.minPing = now - this.lastPing;
    this.minPing = Math.min(this.minPing, now - this.lastPing);
  } else {
    this.logger.debug('Timing mismatch (what?) (%s).', this.hostname());
  }

  this.challenge = null;
});

/**
 * Handle `sendheaders` packet.
 * @method
 * @private
 * @param {SendHeadersPacket} packet
 */

Peer.prototype.handleSendHeaders = co(function* handleSendHeaders(packet) {
  if (this.preferHeaders) {
    this.logger.debug(
      'Peer sent a duplicate sendheaders (%s).',
      this.hostname());
    return;
  }

  this.preferHeaders = true;
});

/**
 * Handle `filterload` packet.
 * @method
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
});

/**
 * Handle `filteradd` packet.
 * @method
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
});

/**
 * Handle `filterclear` packet.
 * @method
 * @private
 * @param {FilterClearPacket} packet
 */

Peer.prototype.handleFilterClear = co(function* handleFilterClear(packet) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.noRelay = false;
});

/**
 * Handle `feefilter` packet.
 * @method
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
});

/**
 * Handle `sendcmpct` packet.
 * @method
 * @private
 * @param {SendCmpctPacket}
 */

Peer.prototype.handleSendCmpct = co(function* handleSendCmpct(packet) {
  if (this.compactMode !== -1) {
    this.logger.debug(
      'Peer sent a duplicate sendcmpct (%s).',
      this.hostname());
    return;
  }

  if (packet.version > 2) {
    // Ignore
    this.logger.info(
      'Peer request compact blocks version %d (%s).',
      packet.version, this.hostname());
    return;
  }

  if (packet.mode > 1) {
    this.logger.info(
      'Peer request compact blocks mode %d (%s).',
      packet.mode, this.hostname());
    return;
  }

  this.logger.info(
    'Peer initialized compact blocks (mode=%d, version=%d) (%s).',
    packet.mode, packet.version, this.hostname());

  this.compactMode = packet.mode;
  this.compactWitness = packet.version === 2;
});

/**
 * Handle `encinit` packet.
 * @method
 * @private
 * @param {EncinitPacket} packet
 */

Peer.prototype.handleEncinit = co(function* handleEncinit(packet) {
  if (!this.bip151)
    return;

  this.bip151.encinit(packet.publicKey, packet.cipher);

  this.send(this.bip151.toEncack());
});

/**
 * Handle `encack` packet.
 * @method
 * @private
 * @param {EncackPacket} packet
 */

Peer.prototype.handleEncack = co(function* handleEncack(packet) {
  if (!this.bip151)
    return;

  this.bip151.encack(packet.publicKey);
});

/**
 * Handle `authchallenge` packet.
 * @method
 * @private
 * @param {AuthChallengePacket} packet
 */

Peer.prototype.handleAuthChallenge = co(function* handleAuthChallenge(packet) {
  var sig;

  if (!this.bip150)
    return;

  sig = this.bip150.challenge(packet.hash);

  this.send(new packets.AuthReplyPacket(sig));
});

/**
 * Handle `authreply` packet.
 * @method
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
});

/**
 * Handle `authpropose` packet.
 * @method
 * @private
 * @param {AuthProposePacket} packet
 */

Peer.prototype.handleAuthPropose = co(function* handleAuthPropose(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.propose(packet.hash);

  this.send(new packets.AuthChallengePacket(hash));
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
    this.hostname());

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
  var hash = null;
  var end = null;

  if (packet.locator.length > 0)
    hash = util.revHex(packet.locator[0]);

  if (stop)
    end = util.revHex(stop);

  this.logger.debug(
    'Requesting inv packet from peer with getblocks (%s).',
    this.hostname());

  this.logger.debug(
    'Sending getblocks (hash=%s, stop=%s).',
    hash, end);

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
      this.hostname());
    return;
  }

  this.logger.debug(
    'Requesting inv packet from peer with mempool (%s).',
    this.hostname());

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
    this.logger.debug('Rejecting %s %s (%s): code=%s reason=%s.',
      reject.message, msg.rhash(), this.hostname(), code, reason);
  } else {
    this.logger.debug('Rejecting packet from %s: code=%s reason=%s.',
      this.hostname(), code, reason);
  }

  this.logger.debug(
    'Sending reject packet to peer (%s).',
    this.hostname());

  this.send(reject);
};

/**
 * Send a `sendcmpct` packet.
 * @param {Number} mode
 */

Peer.prototype.sendCompact = function sendCompact(mode) {
  if (this.services & common.services.WITNESS) {
    if (this.version >= common.COMPACT_WITNESS_VERSION) {
      this.logger.info(
        'Initializing witness compact blocks (%s).',
        this.hostname());
      this.send(new packets.SendCmpctPacket(mode, 2));
      return;
    }
  }

  if (this.version >= common.COMPACT_VERSION) {
    this.logger.info(
      'Initializing normal compact blocks (%s).',
      this.hostname());

    this.send(new packets.SendCmpctPacket(mode, 1));
  }
};

/**
 * Increase banscore on peer.
 * @param {Number} score
 * @returns {Boolean}
 */

Peer.prototype.increaseBan = function increaseBan(score) {
  this.banScore += score;

  if (this.banScore >= this.options.banScore) {
    this.logger.debug('Ban threshold exceeded (%s).', this.hostname());
    this.ban();
    return true;
  }

  return false;
};

/**
 * Ban peer.
 */

Peer.prototype.ban = function ban() {
  this.emit('ban');
};

/**
 * Send a `reject` packet to peer.
 * @see Framer.reject
 * @param {(TX|Block)?} msg
 * @param {String} code
 * @param {String} reason
 * @param {Number} score
 * @returns {Boolean}
 */

Peer.prototype.reject = function reject(msg, code, reason, score) {
  this.sendReject(code, reason, msg);
  return this.increaseBan(score);
};

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
 * Test whether the peer supports compact blocks.
 * @returns {Boolean}
 */

Peer.prototype.hasCompactSupport = function hasCompactSupport() {
  if (this.version < common.COMPACT_VERSION)
    return false;

  if (!this.options.hasWitness())
    return true;

  if (!(this.services & services.WITNESS))
    return false;

  return this.version >= common.COMPACT_WITNESS_VERSION;
};

/**
 * Test whether the peer sent us a
 * compatible compact block handshake.
 * @returns {Boolean}
 */

Peer.prototype.hasCompact = function hasCompact() {
  if (this.compactMode === -1)
    return false;

  if (!this.options.hasWitness())
    return true;

  if (!this.compactWitness)
    return false;

  return true;
};

/**
 * Inspect the peer.
 * @returns {String}
 */

Peer.prototype.inspect = function inspect() {
  return '<Peer:'
    + ' handshake=' + this.handshake
    + ' host=' + this.hostname()
    + ' outbound=' + this.outbound
    + ' ping=' + this.minPing
    + '>';
};

/**
 * PeerOptions
 * @alias module:net.PeerOptions
 * @constructor
 */

function PeerOptions(options) {
  if (!(this instanceof PeerOptions))
    return new PeerOptions(options);

  this.network = Network.primary;
  this.logger = Logger.global;

  this.createSocket = tcp.createSocket;
  this.version = common.PROTOCOL_VERSION;
  this.services = common.LOCAL_SERVICES;
  this.agent = common.USER_AGENT;
  this.noRelay = false;
  this.spv = false;
  this.compact = false;
  this.headers = false;
  this.banScore = common.BAN_SCORE;

  this.getHeight = PeerOptions.getHeight;
  this.isFull = PeerOptions.isFull;
  this.hasWitness = PeerOptions.hasWitness;
  this.createNonce = PeerOptions.createNonce;
  this.hasNonce = PeerOptions.hasNonce;
  this.getRate = PeerOptions.getRate;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from object.
 * @private
 * @param {Object} options
 * @returns {PeerOptions}
 */

PeerOptions.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Options are required.');

  if (options.network != null)
    this.network = Network.get(options.network);

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.createSocket != null) {
    assert(typeof options.createSocket === 'function');
    this.createSocket = options.createSocket;
  }

  if (options.version != null) {
    assert(typeof options.version === 'number');
    this.version = options.version;
  }

  if (options.services != null) {
    assert(typeof options.services === 'number');
    this.services = options.services;
  }

  if (options.agent != null) {
    assert(typeof options.agent === 'string');
    this.agent = options.agent;
  }

  if (options.noRelay != null) {
    assert(typeof options.noRelay === 'boolean');
    this.noRelay = options.noRelay;
  }

  if (options.spv != null) {
    assert(typeof options.spv === 'boolean');
    this.spv = options.spv;
  }

  if (options.compact != null) {
    assert(typeof options.compact === 'boolean');
    this.compact = options.compact;
  }

  if (options.headers != null) {
    assert(typeof options.headers === 'boolean');
    this.headers = options.headers;
  }

  if (options.banScore != null) {
    assert(typeof options.banScore === 'number');
    this.banScore = options.banScore;
  }

  if (options.getHeight != null) {
    assert(typeof options.getHeight === 'function');
    this.getHeight = options.getHeight;
  }

  if (options.isFull != null) {
    assert(typeof options.isFull === 'function');
    this.isFull = options.isFull;
  }

  if (options.hasWitness != null) {
    assert(typeof options.hasWitness === 'function');
    this.hasWitness = options.hasWitness;
  }

  if (options.createNonce != null) {
    assert(typeof options.createNonce === 'function');
    this.createNonce = options.createNonce;
  }

  if (options.hasNonce != null) {
    assert(typeof options.hasNonce === 'function');
    this.hasNonce = options.hasNonce;
  }

  if (options.getRate != null) {
    assert(typeof options.getRate === 'function');
    this.getRate = options.getRate;
  }

  return this;
};

/**
 * Instantiate options from object.
 * @param {Object} options
 * @returns {PeerOptions}
 */

PeerOptions.fromOptions = function fromOptions(options) {
  return new PeerOptions().fromOptions(options);
};

/**
 * Get the chain height.
 * @private
 * @returns {Number}
 */

PeerOptions.getHeight = function getHeight() {
  return 0;
};

/**
 * Test whether the chain is synced.
 * @private
 * @returns {Boolean}
 */

PeerOptions.isFull = function isFull() {
  return false;
};

/**
 * Whether segwit is enabled.
 * @private
 * @returns {Boolean}
 */

PeerOptions.hasWitness = function hasWitness() {
  return true;
};

/**
 * Create a version packet nonce.
 * @private
 * @param {String} hostname
 * @returns {Buffer}
 */

PeerOptions.createNonce = function createNonce(hostname) {
  return util.nonce();
};

/**
 * Test whether version nonce is ours.
 * @private
 * @param {Buffer} nonce
 * @returns {Boolean}
 */

PeerOptions.hasNonce = function hasNonce(nonce) {
  return false;
};

/**
 * Get fee rate for txid.
 * @private
 * @param {Hash} hash
 * @returns {Rate}
 */

PeerOptions.getRate = function getRate(hash) {
  return -1;
};

/**
 * RequestEntry
 * @constructor
 * @ignore
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
