/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var tcp = require('./tcp');
var util = require('../utils/util');
var co = require('../utils/co');
var Parser = require('./parser');
var Framer = require('./framer');
var packets = require('./packets');
var packetTypes = packets.types;
var NetworkAddress = require('../primitives/netaddress');
var constants = require('../protocol/constants');
var InvItem = require('../primitives/invitem');
var Locker = require('../utils/locker');
var Bloom = require('../utils/bloom');
var BIP151 = require('./bip151');
var BIP150 = require('./bip150');
var BIP152 = require('./bip152');
var Block = require('../primitives/block');
var TX = require('../primitives/tx');

/**
 * Represents a remote peer.
 * @exports Peer
 * @constructor
 * @param {Pool} pool
 * @param {NetworkAddress} addr
 * @param {net.Socket?} socket
 * @property {Pool} pool
 * @property {net.Socket?} socket
 * @property {String} host
 * @property {Number} port
 * @property {String} hostname
 * @property {Number} port
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
 * @property {String} id - Peer's uid.
 * @property {Number} banScore
 * @emits Peer#ack
 */

function Peer(pool, addr, socket) {
  if (!(this instanceof Peer))
    return new Peer(pool, addr, socket);

  EventEmitter.call(this);

  this.pool = pool;
  this.options = pool.options;
  this.logger = pool.logger;
  this.socket = null;
  this.outbound = false;
  this.host = null;
  this.port = 0;
  this.hostname = null;
  this.createSocket = this.options.createSocket;
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.network = this.chain.network;
  this.locker = new Locker();
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = 0;
  this.preferHeaders = false;
  this.haveWitness = false;
  this.hashContinue = null;
  this.spvFilter = null;
  this.relay = true;
  this.feeRate = -1;
  this.addrFilter = new Bloom.Rolling(5000, 0.001);
  this.invFilter = new Bloom.Rolling(50000, 0.000001);
  this.lastBlock = null;
  this.waiting = 0;
  this.syncSent = false;
  this.connectTimeout = null;
  this.compactMode = null;
  this.compactWitness = false;
  this.compactBlocks = {};
  this.sentAddr = false;
  this.bip151 = null;
  this.bip150 = null;
  this.lastSend = 0;
  this.lastRecv = 0;
  this.drainStart = 0;
  this.drainSize = 0;
  this.drainQueue = [];

  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;

  this.banScore = 0;

  this.pingTimer = null;
  this.pingInterval = 30000;
  this.stallTimer = null;
  this.stallInterval = 5000;

  this.requestTimeout = 10000;
  this.requestMap = {};

  this.queueBlock = [];
  this.queueTX = [];

  this.uid = 0;
  this.id = Peer.uid++;

  this.setMaxListeners(10000);

  assert(addr, 'Host required.');

  this.host = addr.host;
  this.port = addr.port;
  this.hostname = addr.hostname;

  if (!socket) {
    this.socket = this.connect(this.port, this.host);
    this.outbound = true;
  } else {
    this.socket = socket;
    this.connected = true;
  }

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

/**
 * Globally incremented unique id.
 * @private
 * @type {Number}
 */

Peer.uid = 0;

/**
 * Begin peer initialization.
 * @private
 */

Peer.prototype._init = function init() {
  var self = this;

  this.socket.once('error', function(err) {
    self.error(err);

    switch (err.code) {
      case 'ECONNREFUSED':
      case 'EHOSTUNREACH':
      case 'ENETUNREACH':
      case 'ENOTFOUND':
      case 'ECONNRESET':
        self.ignore();
        break;
      default:
        if (!self.connected)
          self.ignore();
        break;
    }
  });

  this.socket.once('close', function() {
    self.error('socket hangup');
  });

  this.socket.on('drain', function() {
    self.finishDrain();
  });

  this.socket.on('data', function(chunk) {
    if (self.maybeStall())
      return;

    self.parser.feed(chunk);
  });

  this.parser.on('packet', co(function* (packet) {
    try {
      yield self._onPacket(packet);
    } catch (e) {
      self.error(e);
    }
  }));

  this.parser.on('error', function(err) {
    self.error(err, true);
    self.reject(null, 'malformed', 'error parsing message', 10);
  });

  if (this.bip151) {
    this.bip151.on('error', function(err) {
      self.reject(null, 'malformed', 'error parsing message', 10);
      self.error(err, true);
    });
    this.bip151.on('rekey', function() {
      self.logger.debug('Rekeying with peer (%s).', self.hostname);
      self.trySend(self.bip151.toRekey());
    });
  }

  this.open();
};

/**
 * Create the socket and begin connecting. This method
 * will use `options.createSocket` if provided.
 * @param {String} host
 * @param {Number} port
 * @returns {net.Socket}
 */

Peer.prototype.connect = function connect(port, host) {
  var self = this;
  var proxy = this.pool.proxyServer;
  var socket;

  assert(!this.socket);

  if (this.createSocket)
    socket = this.createSocket(port, host, proxy);
  else
    socket = tcp.connect(port, host, proxy);

  this.logger.debug('Connecting to %s.', this.hostname);

  socket.once('connect', function() {
    self.logger.info('Connected to %s.', self.hostname);
  });

  return socket;
};

/**
 * Open and initialize the peer.
 */

Peer.prototype.open = co(function* open() {
  try {
    yield this._connect();
    yield this._stallify();
    yield this._bip151();
    yield this._bip150();
    yield this._handshake();
    yield this._finalize();
  } catch (e) {
    this.error(e);
    return;
  }

  assert(!this.destroyed);

  // Finally we can let the pool know
  // that this peer is ready to go.
  this.emit('open');
});

/**
 * Wait for connection.
 * @private
 */

Peer.prototype._connect = function _connect() {
  var self = this;

  if (this.connected) {
    assert(!this.outbound);
    return co.wait();
  }

  return new Promise(function(resolve, reject) {
    self.socket.once('connect', function() {
      self.ts = util.now();
      self.connected = true;
      self.emit('connect');

      clearTimeout(self.connectTimeout);
      self.connectTimeout = null;

      resolve();
    });

    self.connectTimeout = setTimeout(function() {
      self.connectTimeout = null;
      reject(new Error('Connection timed out.'));
      self.ignore();
    }, 10000);
  });
};

/**
 * Setup stall timer.
 * @private
 */

Peer.prototype._stallify = function _stallify() {
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

Peer.prototype._bip151 = co(function* _bip151() {
  // Send encinit. Wait for handshake to complete.
  if (!this.bip151)
    return;

  assert(!this.bip151.completed);

  this.logger.info('Attempting BIP151 handshake (%s).', this.hostname);

  yield this.send(this.bip151.toEncinit());

  try {
    yield this.bip151.wait(3000);
  } catch (err) {
    this.error(err, true);
  }

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

Peer.prototype._bip150 = co(function* _bip150() {
  if (!this.bip151 || !this.bip150)
    return;

  assert(!this.bip150.completed);

  if (!this.bip151.handshake)
    throw new Error('BIP151 handshake was not completed for BIP150.');

  this.logger.info('Attempting BIP150 handshake (%s).', this.hostname);

  if (this.bip150.outbound) {
    if (!this.bip150.peerIdentity)
      throw new Error('No known identity for peer.');
    yield this.send(this.bip150.toChallenge());
  }

  yield this.bip150.wait(3000);

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

Peer.prototype._handshake = co(function* _handshake() {
  // Say hello.
  yield this.sendVersion();

  // Advertise our address.
  if (this.pool.address.host !== '0.0.0.0'
      && !this.options.selfish
      && this.pool.server) {
    yield this.send(new packets.AddrPacket([this.pool.address]));
  }

  yield this.request('verack');

  // Wait for _their_ version.
  if (!this.version) {
    this.logger.debug(
      'Peer sent a verack without a version (%s).',
      this.hostname);

    yield this.request('version');

    assert(this.version);
  }

  this.ack = true;

  this.logger.debug('Received verack (%s).', this.hostname);
});

/**
 * Handle `ack` event (called on verack).
 * @private
 */

Peer.prototype._finalize = co(function* _finalize() {
  var self = this;

  // Setup the ping interval.
  this.pingTimer = setInterval(function() {
    self.sendPing();
  }, this.pingInterval);

  // Ask for headers-only.
  if (this.options.headers) {
    if (this.version.version >= 70012)
      yield this.send(new packets.SendHeadersPacket());
  }

  // Let them know we support segwit (old
  // segwit3 nodes require this instead
  // of service bits).
  if (this.options.witness && this.network.oldWitness) {
    if (this.version.version >= 70012)
      yield this.send(new packets.HaveWitnessPacket());
  }

  // We want compact blocks!
  if (this.options.compact) {
    if (this.version.version >= 70014)
      yield this.sendCompact();
  }

  // Find some more peers.
  yield this.send(new packets.GetAddrPacket());

  // Relay our spv filter if we have one.
  yield this.updateWatch();

  // Announce our currently broadcasted items.
  yield this.announce(this.pool.invItems);

  // Set a fee rate filter.
  if (this.pool.feeRate !== -1)
    yield this.sendFeeRate(this.pool.feeRate);

  // Start syncing the chain.
  yield this.sync();
});

/**
 * Test whether the peer is the loader peer.
 * @returns {Boolean}
 */

Peer.prototype.isLoader = function isLoader() {
  return this === this.pool.peers.load;
};

/**
 * Broadcast items to peer (transactions or blocks).
 * @param {Block[]|TX[]|InvItem[]|BroadcastEntry[]} items
 */

Peer.prototype.tryAnnounce = function tryAnnounce(items) {
  return this.announce(items).catch(util.nop);
};

/**
 * Broadcast items to peer (transactions or blocks).
 * @param {Block[]|TX[]|InvItem[]|BroadcastEntry[]} items
 */

Peer.prototype.announce = co(function* announce(items) {
  var inv = [];
  var headers = [];
  var i, item, entry;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];

    // Check the peer's bloom
    // filter if they're using spv.
    if (!this.isWatched(item))
      continue;

    // Send them the block immediately if
    // they're using compact block mode 1.
    if (this.compactMode && this.compactMode.mode === 1) {
      if (item instanceof Block) {
        if (!this.invFilter.added(item.hash()))
          continue;
        yield this._sendCompactBlock(item, this.compactWitness);
        continue;
      }
    }

    // Convert item to block headers
    // for peers that request it.
    if (this.preferHeaders && item.toHeaders) {
      item = item.toHeaders();
      if (this.invFilter.test(item.hash()))
        continue;
      headers.push(item);
      continue;
    }

    if (item.toInv)
      item = item.toInv();

    // Do not send txs to spv clients
    // that have relay unset.
    if (!this.relay) {
      if (item.type === constants.inv.TX)
        continue;
    }

    // Filter according to peer's fee filter.
    if (this.feeRate !== -1 && this.mempool) {
      if (item.type === constants.inv.TX) {
        entry = this.mempool.getEntry(item.hash);
        if (entry && entry.getRate() < this.feeRate)
          continue;
      }
    }

    // Don't send if they already have it.
    if (this.invFilter.test(item.hash, 'hex'))
      continue;

    inv.push(item);
  }

  yield this.sendInv(inv);

  if (headers.length > 0)
    yield this.sendHeaders(headers);
});

/**
 * Send inv to a peer.
 * @param {InvItem[]} items
 */

Peer.prototype.sendInv = co(function* sendInv(items) {
  var i, chunk;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++)
    this.invFilter.add(items[i].hash, 'hex');

  if (items.length === 0)
    return;

  this.logger.spam('Serving %d inv items to %s.',
    items.length, this.hostname);

  for (i = 0; i < items.length; i += 50000) {
    chunk = items.slice(i, i + 50000);
    yield this.send(new packets.InvPacket(chunk));
  }
});

/**
 * Send headers to a peer.
 * @param {Headers[]} items
 */

Peer.prototype.sendHeaders = co(function* sendHeaders(items) {
  var i, chunk;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++)
    this.invFilter.add(items[i].hash());

  if (items.length === 0)
    return;

  this.logger.spam('Serving %d headers to %s.',
    items.length, this.hostname);

  for (i = 0; i < items.length; i += 2000) {
    chunk = items.slice(i, i + 2000);
    yield this.send(new packets.HeadersPacket(chunk));
  }
});

/**
 * Send a `version` packet.
 */

Peer.prototype.sendVersion = function sendVersion() {
  var packet = new packets.VersionPacket({
    version: constants.VERSION,
    services: this.pool.services,
    ts: this.network.now(),
    recv: new NetworkAddress(),
    from: this.pool.address,
    nonce: this.pool.localNonce,
    agent: constants.USER_AGENT,
    height: this.chain.height,
    relay: this.options.relay
  });

  return this.send(packet);
};

/**
 * Send a `ping` packet.
 */

Peer.prototype.sendPing = function sendPing() {
  if (!this.version)
    return Promise.resolve();

  if (this.version.version <= 60000)
    return this.trySend(new packets.PingPacket());

  if (this.challenge) {
    this.logger.debug('Peer has not responded to ping (%s).', this.hostname);
    this.destroy();
    return Promise.resolve();
  }

  this.lastPing = util.ms();
  this.challenge = util.nonce();

  return this.trySend(new packets.PingPacket(this.challenge));
};

/**
 * Test whether an is being watched by the peer.
 * @param {BroadcastItem|TX} item
 * @returns {Boolean}
 */

Peer.prototype.isWatched = function isWatched(item) {
  if (!this.spvFilter)
    return true;

  if (!item)
    return true;

  if (item instanceof TX)
    return item.isWatched(this.spvFilter);

  if (item.msg instanceof TX)
    return item.msg.isWatched(this.spvFilter);

  return true;
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.options.spv)
    return Promise.resolve();

  return this.trySend(new packets.FilterLoadPacket(this.pool.spvFilter));
};

/**
 * Set a fee rate filter for the peer.
 * @param {Rate} rate
 */

Peer.prototype.sendFeeRate = function sendFeeRate(rate) {
  return this.trySend(new packets.FeeFilterPacket(rate));
};

/**
 * Disconnect from and destroy the peer.
 */

Peer.prototype.destroy = function destroy() {
  var i, j, keys, cmd, queue, hash;

  if (this.destroyed)
    return;

  this.finishDrain(new Error('Peer destroyed.'));

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

    for (j = 0; j < queue.length; j++)
      queue[j].destroy();
  }

  keys = Object.keys(this.compactBlocks);

  for (i = 0; i < keys.length; i++) {
    hash = keys[i];
    this.compactBlocks[hash].destroy();
  }

  this.emit('close');
};

/**
 * Write data to the peer's socket.
 * @param {Buffer} data
 * @returns {Promise}
 */

Peer.prototype.write = function write(data) {
  if (this.destroyed)
    return Promise.reject(new Error('Peer destroyed (write).'));

  this.lastSend = util.ms();

  if (this.socket.write(data) === false)
    return this.onDrain(data.length);

  return Promise.resolve();
};

/**
 * Wait for drain.
 * @private
 * @param {Function} resolve
 * @param {Function} reject
 */

Peer.prototype.onDrain = function onDrain(size) {
  var self = this;

  if (this.maybeStall())
    return Promise.reject(new Error('Peer stalled (drain).'));

  this.drainStart = util.now();
  this.drainSize += size;

  if (this.drainSize >= (10 << 20)) {
    this.logger.warning(
      'Peer is not reading: %s buffered (%s).',
      util.mb(this.drainSize),
      this.hostname);
    this.error('Peer stalled.');
    return Promise.reject(new Error('Peer stalled (drain).'));
  }

  return new Promise(function(resolve, reject) {
    self.drainQueue.push(co.wrap(resolve, reject));
  });
};

/**
 * Potentially timeout peer if it hasn't read.
 * @private
 */

Peer.prototype.maybeStall = function maybeStall() {
  if (this.drainQueue.length === 0)
    return false;

  if (util.now() < this.drainStart + 10)
    return false;

  this.finishDrain(new Error('Peer stalled.'));
  this.error('Peer stalled.');

  return true;
};

/**
 * Notify drainers of the latest drain.
 * @private
 */

Peer.prototype.finishDrain = function finishDrain(err) {
  var jobs = this.drainQueue.slice();
  var i;

  this.drainQueue.length = 0;
  this.drainSize = 0;

  for (i = 0; i < jobs.length; i++)
    jobs[i](err);
};

/**
 * Send a packet (no error handling).
 * @param {Packet} packet
 * @returns {Promise}
 */

Peer.prototype.trySend = function trySend(packet) {
  return this.send(packet).catch(util.nop);
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

  return this.sendRaw(packet.cmd, packet.toRaw(), checksum);
};

/**
 * Send a packet.
 * @param {Packet} packet
 * @returns {Promise}
 */

Peer.prototype.sendRaw = function sendRaw(cmd, body, checksum) {
  var payload = this.framer.packet(cmd, body, checksum);
  return this.write(payload);
};

/**
 * Emit an error and destroy the peer.
 * @private
 * @param {...String|Error} err
 */

Peer.prototype.error = function error(err, keep) {
  var i, args, msg;

  if (this.destroyed)
    return;

  if (typeof err === 'string') {
    args = new Array(arguments.length);

    for (i = 0; i < args.length; i++)
      args[i] = arguments[i];

    if (typeof args[args.length - 1] === 'boolean')
      keep = args.pop();

    msg = util.fmt.apply(util, args);
    err = new Error(msg);
  }

  err.message += ' (' + this.hostname + ')';

  if (!keep)
    this.destroy();

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
      return reject(new Error('Destroyed'));

    entry = new RequestEntry(self, cmd, resolve, reject);

    if (!self.requestMap[cmd])
      self.requestMap[cmd] = [];

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
  var entry, res;

  if (!queue)
    return false;

  entry = queue[0];

  if (!entry)
    return false;

  res = entry.resolve(payload);

  if (res === false)
    return false;

  queue.shift();

  if (queue.length === 0)
    delete this.requestMap[cmd];

  entry.destroy();

  return true;
};

/**
 * Send `getdata` to peer.
 * @param {InvItem[]} items
 */

Peer.prototype.getData = function getData(items) {
  var data = new Array(items.length);
  var i, item;

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (item.toInv)
      item = item.toInv();

    if (this.options.compact
        && this.compactMode
        && item.isBlock()
        && !item.hasWitness()) {
      item.type = constants.inv.CMPCT_BLOCK;
    }

    data[i] = item;
  }

  return this.trySend(new packets.GetDataPacket(data));
};

/**
 * Handle a packet payload.
 * @private
 * @param {Packet} packet
 */

Peer.prototype._onPacket = co(function* onPacket(packet) {
  var unlock;

  if (this.destroyed)
    throw new Error('Destroyed peer sent a packet.');

  switch (packet.type) {
    case packetTypes.VERSION:
    case packetTypes.CMPCTBLOCK:
      // These can't have locks or stop reads.
      return yield this.__onPacket(packet);
    default:
      unlock = yield this.locker.lock();
      this.socket.pause();
      try {
        return yield this.__onPacket(packet);
      } finally {
        this.socket.resume();
        unlock();
      }
      break;
  }
});

/**
 * Handle a packet payload without a lock.
 * @private
 * @param {Packet} packet
 */

Peer.prototype.__onPacket = co(function* onPacket(packet) {
  this.lastRecv = util.ms();

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

  if (this.lastBlock) {
    if (packet.type !== packetTypes.TX)
      this._flushMerkle();
  }

  switch (packet.type) {
    case packetTypes.VERSION:
      return yield this._handleVersion(packet);
    case packetTypes.VERACK:
      return this._handleVerack(packet);
    case packetTypes.PING:
      return yield this._handlePing(packet);
    case packetTypes.PONG:
      return this._handlePong(packet);
    case packetTypes.ALERT:
      return this._handleAlert(packet);
    case packetTypes.GETADDR:
      return yield this._handleGetAddr(packet);
    case packetTypes.ADDR:
      return this._handleAddr(packet);
    case packetTypes.INV:
      return this._handleInv(packet);
    case packetTypes.GETDATA:
      return yield this._handleGetData(packet);
    case packetTypes.NOTFOUND:
      return this._handleNotFound(packet);
    case packetTypes.GETBLOCKS:
      return yield this._handleGetBlocks(packet);
    case packetTypes.GETHEADERS:
      return yield this._handleGetHeaders(packet);
    case packetTypes.HEADERS:
      return this._handleHeaders(packet);
    case packetTypes.SENDHEADERS:
      return this._handleSendHeaders(packet);
    case packetTypes.BLOCK:
      return this._handleBlock(packet);
    case packetTypes.TX:
      return this._handleTX(packet);
    case packetTypes.REJECT:
      return this._handleReject(packet);
    case packetTypes.MEMPOOL:
      return yield this._handleMempool(packet);
    case packetTypes.FILTERLOAD:
      return this._handleFilterLoad(packet);
    case packetTypes.FILTERADD:
      return this._handleFilterAdd(packet);
    case packetTypes.FILTERCLEAR:
      return this._handleFilterClear(packet);
    case packetTypes.MERKLEBLOCK:
      return this._handleMerkleBlock(packet);
    case packetTypes.GETUTXOS:
      return yield this._handleGetUTXOs(packet);
    case packetTypes.UTXOS:
      return this._handleUTXOs(packet);
    case packetTypes.HAVEWITNESS:
      return this._handleHaveWitness(packet);
    case packetTypes.FEEFILTER:
      return this._handleFeeFilter(packet);
    case packetTypes.SENDCMPCT:
      return this._handleSendCmpct(packet);
    case packetTypes.CMPCTBLOCK:
      return yield this._handleCmpctBlock(packet);
    case packetTypes.GETBLOCKTXN:
      return yield this._handleGetBlockTxn(packet);
    case packetTypes.BLOCKTXN:
      return this._handleBlockTxn(packet);
    case packetTypes.ENCINIT:
      return yield this._handleEncinit(packet);
    case packetTypes.ENCACK:
      return this._handleEncack(packet);
    case packetTypes.AUTHCHALLENGE:
      return yield this._handleAuthChallenge(packet);
    case packetTypes.AUTHREPLY:
      return yield this._handleAuthReply(packet);
    case packetTypes.AUTHPROPOSE:
      return yield this._handleAuthPropose(packet);
    case packetTypes.UNKNOWN:
      return this._handleUnknown(packet);
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

Peer.prototype._flushMerkle = function _flushMerkle() {
  if (this.lastBlock)
    this.fire('merkleblock', this.lastBlock);
  this.lastBlock = null;
  this.waiting = 0;
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

Peer.prototype._handleFilterLoad = function _handleFilterLoad(packet) {
  if (!packet.isWithinConstraints()) {
    this.setMisbehavior(100);
    return;
  }

  this.spvFilter = packet.filter;
  this.relay = true;
};

/**
 * Handle `filteradd` packet.
 * @private
 * @param {FilterAddPacket}
 */

Peer.prototype._handleFilterAdd = function _handleFilterAdd(packet) {
  var data = packet.data;

  if (data.length > constants.script.MAX_PUSH) {
    this.setMisbehavior(100);
    return;
  }

  if (this.spvFilter)
    this.spvFilter.add(data);

  this.relay = true;
};

/**
 * Handle `filterclear` packet.
 * @private
 * @param {FilterClearPacket}
 */

Peer.prototype._handleFilterClear = function _handleFilterClear(packet) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.relay = true;
};

/**
 * Handle `merkleblock` packet.
 * @private
 * @param {MerkleBlockPacket}
 */

Peer.prototype._handleMerkleBlock = function _handleMerkleBlock(packet) {
  var block = packet.block;

  block.verifyPartial();

  this.lastBlock = block;
  this.waiting = block.matches.length;

  if (this.waiting === 0)
    this._flushMerkle();
};

/**
 * Handle `feefilter` packet.
 * @private
 * @param {FeeFilterPacket}
 */

Peer.prototype._handleFeeFilter = function _handleFeeFilter(packet) {
  var rate = packet.rate;

  if (!(rate >= 0 && rate <= constants.MAX_MONEY)) {
    this.setMisbehavior(100);
    return;
  }

  this.feeRate = rate;

  this.fire('feefilter', rate);
};

/**
 * Handle `utxos` packet.
 * @private
 * @param {UTXOsPacket}
 */

Peer.prototype._handleUTXOs = function _handleUTXOs(utxos) {
  this.logger.debug('Received %d utxos (%s).',
    utxos.coins.length, this.hostname);
  this.fire('utxos', utxos);
};

/**
 * Handle `getutxos` packet.
 * @private
 */

Peer.prototype._handleGetUTXOs = co(function* _handleGetUTXOs(packet) {
  var i, utxos, prevout, hash, index, coin;

  if (!this.chain.synced)
    return;

  if (this.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (packet.prevout.length > 15)
    return;

  utxos = new packets.GetUTXOsPacket();

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

  yield this.send(utxos);
});

/**
 * Handle `havewitness` packet.
 * @private
 * @param {HaveWitnessPacket}
 */

Peer.prototype._handleHaveWitness = function _handleHaveWitness(packet) {
  this.haveWitness = true;
  this.fire('havewitness');
};

/**
 * Handle `getheaders` packet.
 * @private
 * @param {GetHeadersPacket}
 */

Peer.prototype._handleGetHeaders = co(function* _handleGetHeaders(packet) {
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

  yield this.sendHeaders(headers);
});

/**
 * Handle `getblocks` packet.
 * @private
 * @param {GetBlocksPacket}
 */

Peer.prototype._handleGetBlocks = co(function* _handleGetBlocks(packet) {
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
    blocks.push(new InvItem(constants.inv.BLOCK, hash));

    if (hash === packet.stop)
      break;

    if (blocks.length === 500) {
      this.hashContinue = hash;
      break;
    }

    hash = yield this.chain.db.getNextHash(hash);
  }

  yield this.sendInv(blocks);
});

/**
 * Handle `version` packet.
 * @private
 * @param {VersionPacket}
 */

Peer.prototype._handleVersion = co(function* _handleVersion(version) {
  if (this.version)
    throw new Error('Peer sent a duplicate version.');

  if (!this.network.selfConnect) {
    if (util.equal(version.nonce, this.pool.localNonce)) {
      this.ignore();
      throw new Error('We connected to ourself. Oops.');
    }
  }

  if (version.version < constants.MIN_VERSION) {
    this.ignore();
    throw new Error('Peer does not support required protocol version.');
  }

  if (this.outbound) {
    if (!version.hasNetwork()) {
      this.ignore();
      throw new Error('Peer does not support network services.');
    }
  }

  if (this.options.headers) {
    if (!version.hasHeaders()) {
      this.ignore();
      throw new Error('Peer does not support getheaders.');
    }
  }

  if (this.options.spv) {
    if (!version.hasBloom()) {
      this.ignore();
      throw new Error('Peer does not support BIP37.');
    }
  }

  if (this.options.witness) {
    this.haveWitness = version.hasWitness();

    if (!this.haveWitness) {
      if (!this.network.oldWitness) {
        this.ignore();
        throw new Error('Peer does not support segregated witness.');
      }

      try {
        yield this.request('havewitness');
      } catch (err) {
        this.ignore();
        throw new Error('Peer does not support segregated witness.');
      }

      this.haveWitness = true;
    }
  }

  this.relay = version.relay;
  this.version = version;

  this.fire('version', version);

  yield this.send(new packets.VerackPacket());
});

/**
 * Handle `verack` packet.
 * @private
 * @param {VerackPacket}
 */

Peer.prototype._handleVerack = function _handleVerack(packet) {
  this.fire('verack');
};

/**
 * Handle `mempool` packet.
 * @private
 * @param {MempoolPacket}
 */

Peer.prototype._handleMempool = function _handleMempool(packet) {
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
    items.push(new InvItem(constants.inv.TX, hashes[i]));

  this.logger.debug('Sending mempool snapshot (%s).', this.hostname);

  return this.sendInv(items);
};

/**
 * Get a block/tx from the broadcast map.
 * @param {InvItem} item
 * @returns {Promise}
 */

Peer.prototype._getBroadcasted = function _getBroadcasted(item) {
  var entry = this.pool.invMap[item.hash];

  if (!entry)
    return;

  this.logger.debug(
    'Peer requested %s %s as a %s packet (%s).',
    entry.type === constants.inv.TX ? 'tx' : 'block',
    util.revHex(entry.hash),
    item.hasWitness() ? 'witness' : 'normal',
    this.hostname);

  entry.ack(this);

  if (!entry.msg)
    return;

  if (item.isTX()) {
    if (entry.type !== constants.inv.TX)
      return;
  } else {
    if (entry.type !== constants.inv.BLOCK)
      return;
  }

  return entry.msg;
};

/**
 * Get a block/tx either from the broadcast map, mempool, or blockchain.
 * @param {InvItem} item
 * @returns {Promise}
 */

Peer.prototype._getItem = co(function* _getItem(item) {
  var entry = this._getBroadcasted(item);

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
 * @param {InvItem} item
 * @returns {Boolean}
 */

Peer.prototype._sendBlock = co(function* _sendBlock(item, witness) {
  var block = this._getBroadcasted(item);

  // Check for a broadcasted item first.
  if (block) {
    yield this.send(new packets.BlockPacket(block, witness));
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

    yield this.sendRaw('block', block);

    return true;
  }

  block = yield this.chain.db.getBlock(item.hash);

  if (!block)
    return false;

  yield this.send(new packets.BlockPacket(block, witness));

  return true;
});

/**
 * Send a compact block.
 * @param {Block} block
 * @param {Boolean} witness
 * @returns {Boolean}
 */

Peer.prototype._sendCompactBlock = function _sendCompactBlock(block, witness) {
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

  return this.send(new packets.CmpctBlockPacket(block, witness));
};

/**
 * Handle `getdata` packet.
 * @private
 * @param {GetDataPacket}
 */

Peer.prototype._handleGetData = co(function* _handleGetData(packet) {
  var notFound = [];
  var txs = 0;
  var blocks = 0;
  var unknown = -1;
  var items = packet.items;
  var i, j, item, tx, block, result;

  if (items.length > 50000)
    throw new Error('getdata size too large (' + items.length + ').');

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (item.isTX()) {
      tx = yield this._getItem(item);

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

      yield this.send(new packets.TXPacket(tx, item.hasWitness()));

      txs++;

      continue;
    }

    switch (item.type) {
      case constants.inv.BLOCK:
      case constants.inv.WITNESS_BLOCK:
        result = yield this._sendBlock(item, item.hasWitness());
        if (!result) {
          notFound.push(item);
          continue;
        }
        blocks++;
        break;
      case constants.inv.FILTERED_BLOCK:
      case constants.inv.WITNESS_FILTERED_BLOCK:
        if (!this.spvFilter) {
          notFound.push(item);
          continue;
        }

        block = yield this._getItem(item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        block = block.toMerkle(this.spvFilter);

        yield this.send(new packets.MerkleBlockPacket(block));

        for (j = 0; j < block.txs.length; j++) {
          tx = block.txs[j];
          yield this.send(new packets.TXPacket(tx, item.hasWitness()));
          txs++;
        }

        blocks++;

        break;
      case constants.inv.CMPCT_BLOCK:
        // Fallback to full block.
        if (block.height < this.chain.tip.height - 10) {
          result = yield this._sendBlock(item, this.compactWitness);
          if (!result) {
            notFound.push(item);
            continue;
          }
          blocks++;
          break;
        }

        block = yield this._getItem(item);

        if (!block) {
          notFound.push(item);
          continue;
        }

        yield this._sendCompactBlock(block, this.compactWitness);

        blocks++;

        break;
      default:
        unknown = item.type;
        notFound.push(item);
        continue;
    }

    if (item.hash === this.hashContinue) {
      yield this.sendInv(new InvItem(constants.inv.BLOCK, this.chain.tip.hash));
      this.hashContinue = null;
    }
  }

  if (notFound.length > 0)
    yield this.send(new packets.NotFoundPacket(notFound));

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

Peer.prototype._handleNotFound = function _handleNotFound(packet) {
  this.fire('notfound', packet.items);
};

/**
 * Handle `addr` packet.
 * @private
 * @param {AddrPacket}
 */

Peer.prototype._handleAddr = function _handleAddr(packet) {
  var now = this.network.now();
  var addrs = packet.items;
  var i, addr;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    if (addr.ts <= 100000000 || addr.ts > now + 10 * 60)
      addr.ts = now - 5 * 24 * 60 * 60;

    this.addrFilter.add(addr.host, 'ascii');
  }

  this.logger.info(
    'Received %d addrs (hosts=%d, peers=%d) (%s).',
    addrs.length,
    this.pool.hosts.items.length,
    this.pool.peers.all.length,
    this.hostname);

  this.fire('addr', addrs);
};

/**
 * Handle `ping` packet.
 * @private
 * @param {PingPacket}
 */

Peer.prototype._handlePing = co(function* _handlePing(packet) {
  this.fire('ping', this.minPing);
  if (packet.nonce)
    yield this.send(new packets.PongPacket(packet.nonce));
});

/**
 * Handle `pong` packet.
 * @private
 * @param {PongPacket}
 */

Peer.prototype._handlePong = function _handlePong(packet) {
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
};

/**
 * Handle `getaddr` packet.
 * @private
 * @param {GetAddrPacket}
 */

Peer.prototype._handleGetAddr = co(function* _handleGetAddr(packet) {
  var items = [];
  var i, addr;

  if (this.options.selfish)
    return;

  if (this.sentAddr) {
    this.logger.debug('Ignoring repeated getaddr (%s).', this.hostname);
    return;
  }

  this.sentAddr = true;

  for (i = 0; i < this.pool.hosts.items.length; i++) {
    addr = this.pool.hosts.items[i];

    if (!addr.isIP())
      continue;

    if (!this.addrFilter.added(addr.host, 'ascii'))
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

  yield this.send(new packets.AddrPacket(items));
});

/**
 * Handle `inv` packet.
 * @private
 * @param {InvPacket}
 */

Peer.prototype._handleInv = function _handleInv(packet) {
  var items = packet.items;
  var blocks = [];
  var txs = [];
  var unknown = -1;
  var i, item;

  if (items.length > 50000) {
    this.setMisbehavior(100);
    return;
  }

  for (i = 0; i < items.length; i++) {
    item = items[i];
    switch (item.type) {
      case constants.inv.TX:
        txs.push(item.hash);
        break;
      case constants.inv.BLOCK:
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
};

/**
 * Handle `headers` packet.
 * @private
 * @param {HeadersPacket}
 */

Peer.prototype._handleHeaders = function _handleHeaders(packet) {
  var headers = packet.items;

  this.logger.debug(
    'Received headers packet with %d items (%s).',
    headers.length, this.hostname);

  if (headers.length > 2000) {
    this.setMisbehavior(100);
    return;
  }

  this.fire('headers', headers);
};

/**
 * Handle `sendheaders` packet.
 * @private
 * @param {SendHeadersPacket}
 */

Peer.prototype._handleSendHeaders = function _handleSendHeaders(packet) {
  this.preferHeaders = true;
  this.fire('sendheaders');
};

/**
 * Handle `block` packet.
 * @private
 * @param {BlockPacket}
 */

Peer.prototype._handleBlock = function _handleBlock(packet) {
  this.fire('block', packet.block);
};

/**
 * Handle `tx` packet.
 * @private
 * @param {TXPacket}
 */

Peer.prototype._handleTX = function _handleTX(packet) {
  var tx = packet.tx;

  if (this.lastBlock) {
    if (this.lastBlock.hasTX(tx)) {
      this.lastBlock.addTX(tx);
      if (--this.waiting === 0)
        this._flushMerkle();
      return;
    }
  }

  this.fire('tx', tx);
};

/**
 * Handle `reject` packet.
 * @private
 * @param {RejectPacket}
 */

Peer.prototype._handleReject = function _handleReject(details) {
  var hash, entry;

  this.fire('reject', details);

  if (!details.data)
    return;

  hash = details.data;
  entry = this.pool.invMap[hash];

  if (!entry)
    return;

  entry.reject(this);
};

/**
 * Handle `alert` packet.
 * @private
 * @param {AlertPacket}
 */

Peer.prototype._handleAlert = function _handleAlert(alert) {
  this.invFilter.add(alert.hash());
  this.fire('alert', alert);
};

/**
 * Handle `encinit` packet.
 * @private
 * @param {EncinitPacket}
 */

Peer.prototype._handleEncinit = co(function* _handleEncinit(packet) {
  if (!this.bip151)
    return;

  this.bip151.encinit(packet.publicKey, packet.cipher);

  this.fire('encinit', packet);

  yield this.send(this.bip151.toEncack());
});

/**
 * Handle `encack` packet.
 * @private
 * @param {EncackPacket}
 */

Peer.prototype._handleEncack = function _handleEncack(packet) {
  if (!this.bip151)
    return;

  this.bip151.encack(packet.publicKey);

  this.fire('encack', packet);
};

/**
 * Handle `authchallenge` packet.
 * @private
 * @param {AuthChallengePacket}
 */

Peer.prototype._handleAuthChallenge = co(function* _handleAuthChallenge(packet) {
  var sig;

  if (!this.bip150)
    return;

  sig = this.bip150.challenge(packet.hash);

  this.fire('authchallenge', packet.hash);

  yield this.send(new packets.AuthReplyPacket(sig));
});

/**
 * Handle `authreply` packet.
 * @private
 * @param {AuthReplyPacket}
 */

Peer.prototype._handleAuthReply = co(function* _handleAuthReply(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.reply(packet.signature);

  if (hash)
    yield this.send(new packets.AuthProposePacket(hash));

  this.fire('authreply', packet.signature);
});

/**
 * Handle `authpropose` packet.
 * @private
 * @param {AuthProposePacket}
 */

Peer.prototype._handleAuthPropose = co(function* _handleAuthPropose(packet) {
  var hash;

  if (!this.bip150)
    return;

  hash = this.bip150.propose(packet.hash);

  yield this.send(new packets.AuthChallengePacket(hash));

  this.fire('authpropose', packet.hash);
});

/**
 * Handle an unknown packet.
 * @private
 * @param {UnknownPacket}
 */

Peer.prototype._handleUnknown = function _handleUnknown(packet) {
  this.logger.warning('Unknown packet: %s.', packet.cmd);
  this.fire('unknown', packet);
};

/**
 * Handle `sendcmpct` packet.
 * @private
 * @param {SendCmpctPacket}
 */

Peer.prototype._handleSendCmpct = function _handleSendCmpct(packet) {
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
};

/**
 * Handle `cmpctblock` packet.
 * @private
 * @param {CmpctBlockPacket}
 */

Peer.prototype._handleCmpctBlock = co(function* _handleCmpctBlock(packet) {
  var block = packet.block;
  var hash = block.hash('hex');
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

  result = block.fillMempool(this.options.witness, this.mempool);

  if (result) {
    this.fire('block', block.toBlock());
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash, this.hostname);
    return;
  }

  this.compactBlocks[hash] = block;

  yield this.send(new packets.GetBlockTxnPacket(block.toRequest()));

  this.logger.debug(
    'Received semi-full compact block %s (%s).',
    block.rhash, this.hostname);

  try {
    yield block.wait(10000);
  } catch (e) {
    this.logger.debug(
      'Compact block timed out: %s (%s).',
      block.rhash, this.hostname);

    delete this.compactBlocks[hash];
  }
});

/**
 * Handle `getblocktxn` packet.
 * @private
 * @param {GetBlockTxnPacket}
 */

Peer.prototype._handleGetBlockTxn = co(function* _handleGetBlockTxn(packet) {
  var req = packet.request;
  var res, item, block;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

  if (this.options.selfish)
    return;

  item = new InvItem(constants.inv.BLOCK, req.hash);

  block = yield this._getItem(item);

  if (!block) {
    this.logger.debug(
      'Peer sent getblocktxn for non-existent block (%s).',
      this.hostname);
    this.setMisbehavior(100);
    return;
  }

  if (block.height < this.chain.tip.height - 15) {
    this.logger.debug(
      'Peer sent a getblocktxn for a block > 15 deep (%s)',
      this.hostname);
    return;
  }

  res = BIP152.TXResponse.fromBlock(block, req);

  yield this.send(new packets.BlockTxnPacket(res, this.compactWitness));

  this.fire('blocktxn', req);
});

/**
 * Handle `blocktxn` packet.
 * @private
 * @param {BlockTxnPacket}
 */

Peer.prototype._handleBlockTxn = function _handleBlockTxn(packet) {
  var res = packet.response;
  var block = this.compactBlocks[res.hash];

  if (!block) {
    this.logger.debug('Peer sent unsolicited blocktxn (%s).', this.hostname);
    return;
  }

  block.complete();

  delete this.compactBlocks[res.hash];

  if (!block.fillMissing(res)) {
    this.setMisbehavior(100);
    this.logger.warning('Peer sent non-full blocktxn (%s).', this.hostname);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash, this.hostname);

  this.fire('block', block.toBlock());
  this.fire('getblocktxn', res);
};

/**
 * Send an `alert` to peer.
 * @param {AlertPacket} alert
 */

Peer.prototype.sendAlert = function sendAlert(alert) {
  if (!this.invFilter.added(alert.hash()))
    return Promise.resolve();

  return this.trySend(alert);
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

  return this.send(packet);
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

  return this.send(packet);
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.sendMempool = function sendMempool() {
  if (!this.version)
    return Promise.resolve();

  if (!this.version.hasBloom()) {
    this.logger.debug(
      'Cannot request mempool for non-bloom peer (%s).',
      this.hostname);
    return Promise.resolve();
  }

  this.logger.debug(
    'Requesting inv packet from peer with mempool (%s).',
    this.hostname);

  return this.trySend(new packets.MempoolPacket());
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
      reject.message, obj.rhash, this.hostname, code, reason);
  } else {
    this.logger.debug('Rejecting packet from %s: ccode=%s reason=%s.',
      this.hostname, code, reason);
  }

  this.logger.debug(
    'Sending reject packet to peer (%s).',
    this.hostname);

  return this.trySend(reject);
};

/**
 * Send a `sendcmpct` packet.
 */

Peer.prototype.sendCompact = function sendCompact() {
  var version = this.options.witness ? 2 : 1;
  this.logger.info('Initializing compact blocks (%s).', this.hostname);
  return this.trySend(new packets.SendCmpctPacket(0, version));
};

/**
 * Check whether the peer is misbehaving (banScore >= 100).
 * @returns {Boolean}
 */

Peer.prototype.isMisbehaving = function isMisbehaving() {
  return this.pool.hosts.isMisbehaving(this);
};

/**
 * Check whether the peer is ignored.
 * @returns {Boolean}
 */

Peer.prototype.isIgnored = function isIgnored() {
  return this.pool.hosts.isIgnored(this);
};

/**
 * Increase banscore on peer.
 * @param {Number} score
 */

Peer.prototype.setMisbehavior = function setMisbehavior(score) {
  return this.pool.setMisbehavior(this, score);
};

/**
 * Ignore peer.
 */

Peer.prototype.ignore = function ignore() {
  return this.pool.ignore(this);
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
  var promise = this.sendReject(code, reason, obj);
  if (score > 0)
    this.setMisbehavior(score);
  return promise;
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

  yield this.sendGetBlocks(locator, root);
});

/**
 * Send `getheaders` to peer after building locator.
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Peer.prototype.getHeaders = co(function* getHeaders(tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  yield this.sendGetHeaders(locator, stop);
});

/**
 * Send `getblocks` to peer after building locator.
 * @param {Hash} tip - Tip hash to build chain locator from.
 * @param {Hash?} stop
 * @returns {Promise}
 */

Peer.prototype.getBlocks = co(function* getBlocks(tip, stop) {
  var locator = yield this.chain.getLocator(tip);
  yield this.sendGetBlocks(locator, stop);
});

/**
 * Start syncing from peer.
 * @returns {Promise}
 */

Peer.prototype.trySync = function trySync() {
  return this.sync().catch(util.nop);
};

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

  if (this.options.witness && !this.version.hasWitness())
    return;

  if (!this.isLoader()) {
    if (!this.chain.synced)
      return;
  }

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (this.isLoader() && this.chain.synced)
      yield this.sendMempool();
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
  this.id = peer.uid++;
  this.onTimeout = this._onTimeout.bind(this);
  this.timeout = setTimeout(this.onTimeout, this.peer.requestTimeout);
}

RequestEntry.prototype._onTimeout = function _onTimeout() {
  var queue = this.peer.requestMap[this.cmd];

  if (!queue)
    return;

  if (util.binaryRemove(queue, this, compare)) {
    if (queue.length === 0)
      delete this.peer.requestMap[this.cmd];
    this.reject(new Error('Timed out: ' + this.cmd));
  }
};

RequestEntry.prototype.destroy = function destroy() {
  if (this.timeout != null) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }
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

module.exports = Peer;
