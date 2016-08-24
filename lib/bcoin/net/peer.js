/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
var IP = require('../utils/ip');
var Parser = require('./parser');
var Framer = require('./framer');
var assert = utils.assert;
var constants = bcoin.constants;
var InvItem = bcoin.packets.InvItem;
var VersionPacket = bcoin.packets.VersionPacket;
var GetBlocksPacket = bcoin.packets.GetBlocksPacket;
var RejectPacket = bcoin.packets.RejectPacket;
var NetworkAddress = bcoin.packets.NetworkAddress;

/**
 * Represents a remote peer.
 * @exports Peer
 * @constructor
 * @param {Pool} pool
 * @param {Object} options
 * @param {Function?} options.createSocket - Callback which returns a
 * node.js-like socket object. Necessary for browser.
 * @param {Chain} options.chain
 * @param {Mempool} options.mempool
 * @param {Number?} options.ts - Time at which peer was discovered (unix time).
 * @param {net.Socket?} options.socket
 * @param {NetworkAddress?} options.host - Host to connect to.
 * @property {Pool} pool
 * @property {net.Socket?} socket
 * @property {String?} host
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

function Peer(pool, options) {
  if (!(this instanceof Peer))
    return new Peer(pool, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  assert(typeof options.type === 'number', 'Peer must have a type.');

  this.options = options;
  this.pool = pool;
  this.logger = pool.logger;
  this.type = options.type;
  this.socket = null;
  this.host = null;
  this.port = 0;
  this.hostname = null;
  this._createSocket = this.pool.options.createSocket;
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.network = this.chain.network;
  this.locker = new bcoin.locker(this);
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = options.ts || 0;
  this.preferHeaders = false;
  this.haveWitness = false;
  this.hashContinue = null;
  this.spvFilter = null;
  this.relay = true;
  this.feeRate = -1;
  this.addrFilter = new bcoin.bloom.rolling(5000, 0.001);
  this.invFilter = new bcoin.bloom.rolling(50000, 0.000001);
  this.lastBlock = null;
  this.waiting = 0;
  this.syncSent = false;
  this._connectTimeout = null;
  this.compactMode = null;
  this.compactBlocks = {};
  this.sentAddr = false;
  this.bip151 = null;
  this.bip150 = null;
  this.lastSend = 0;
  this.lastRecv = 0;

  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;

  this.banScore = 0;

  this.pingTimer = null;
  this.pingInterval = options.pingInterval || 120000;

  this.requestTimeout = options.requestTimeout || 10000;
  this.requestMap = {};

  this.queueBlock = [];
  this.queueTX = [];

  this.uid = 0;
  this.id = Peer.uid++;

  this.setMaxListeners(10000);

  if (options.socket) {
    this.socket = options.socket;
    this.host = IP.normalize(this.socket.remoteAddress);
    this.port = this.socket.remotePort;
    this.connected = true;
  } else if (options.host) {
    this.host = options.host.host;
    this.port = options.host.port;
    this.socket = this.createSocket(this.port, this.host);
  } else {
    assert(false, 'No seed or socket.');
  }

  assert(typeof this.host === 'string');
  assert(typeof this.port === 'number');
  assert(this.socket, 'No socket.');

  this.hostname = IP.hostname(this.host, this.port);

  if (this.pool.options.bip151) {
    this.bip151 = new bcoin.bip151();
    if (this.pool.options.bip150) {
      this.bip150 = new bcoin.bip150(
        this.bip151,
        this.hostname,
        this.type !== Peer.types.LEECH,
        this.pool.auth,
        this.pool.identityKey);
      this.bip151.bip150 = this.bip150;
    }
  }

  this.parser = new Parser(this);
  this.framer = new Framer(this);

  this._init();
}

utils.inherits(Peer, EventEmitter);

/**
 * Globally incremented unique id.
 * @private
 * @type {Number}
 */

Peer.uid = 0;

/**
 * Peer types.
 * @enum {Number}
 * @default
 */

Peer.types = {
  LOADER: 0,
  REGULAR: 1,
  LEECH: 2
};

/**
 * Begin peer initialization.
 * @private
 */

Peer.prototype._init = function init() {
  var self = this;

  this.socket.once('connect', function() {
    self._onConnect();
  });

  this.socket.once('error', function(err) {
    self._error(err);

    switch (err.code) {
      case 'ECONNREFUSED':
      case 'EHOSTUNREACH':
      case 'ENETUNREACH':
      case 'ENOTFOUND':
      case 'ECONNRESET':
        self.ignore();
        break;
    }
  });

  this.socket.once('close', function() {
    self._error('socket hangup');
  });

  this.socket.on('data', function(chunk) {
    self.parser.feed(chunk);
  });

  this.parser.on('packet', function(packet) {
    self._onPacket(packet);
  });

  this.parser.on('error', function(err) {
    self._error(err, true);
    self.reject(null, 'malformed', 'error parsing message', 10);
  });

  if (this.bip151) {
    this.bip151.on('error', function(err) {
      self.reject(null, 'malformed', 'error parsing message', 10);
      self._error(err, true);
    });
    this.bip151.on('rekey', function() {
      self.logger.debug('Rekeying with peer (%s).', self.hostname);
      self.write(self.framer.encack(self.bip151.toRekey()));
    });
  }

  if (this.connected) {
    utils.nextTick(function() {
      self._onConnect();
    });
  }
};

/**
 * Invoke mutex lock.
 * @private
 */

Peer.prototype._lock = function _lock(func, args, force) {
  return this.locker.lock(func, args, force);
};

/**
 * Handle `connect` event (called immediately
 * if a socket was passed into peer).
 * @private
 */

Peer.prototype._onConnect = function _onConnect() {
  var self = this;

  this.ts = utils.now();
  this.connected = true;

  this.emit('connect');

  if (this._connectTimeout != null) {
    clearTimeout(this._connectTimeout);
    this._connectTimeout = null;
  }

  // Send encinit. Wait for handshake to complete.
  if (this.bip151) {
    assert(!this.bip151.completed);
    this.logger.info('Attempting BIP151 handshake (%s).', this.hostname);
    this.write(this.framer.encinit(this.bip151.toEncinit()));
    return this.bip151.wait(5000, function(err) {
      if (err)
        self._error(err, true);
      self._onBIP151();
    });
  }

  this._onBIP151();
};

/**
 * Handle post bip151-handshake.
 * @private
 */

Peer.prototype._onBIP151 = function _onBIP151() {
  var self = this;

  if (this.bip151) {
    assert(this.bip151.completed);

    if (this.bip151.handshake) {
      this.logger.info('BIP151 handshake complete (%s).', this.hostname);
      this.logger.info('Connection is encrypted (%s).', this.hostname);
    }

    if (this.bip150) {
      assert(!this.bip150.completed);
      this.logger.info('Attempting BIP150 handshake (%s).', this.hostname);
      if (this.bip150.outbound && this.bip150.peerIdentity)
        this.write(this.framer.authChallenge(this.bip150.toChallenge()));
      return this.bip150.wait(5000, function(err) {
        if (err)
          return self._error(err);
        self._onHandshake();
      });
    }
  }

  this._onHandshake();
};

/**
 * Handle post handshake.
 * @private
 */

Peer.prototype._onHandshake = function _onHandshake() {
  var self = this;

  if (this.bip150) {
    assert(this.bip150.completed);
    if (this.bip150.auth) {
      this.logger.info('BIP150 handshake complete (%s).', this.hostname);
      this.logger.info('Peer is authed (%s): %s.',
        this.hostname, this.bip150.getAddress());
    }
  }

  this.request('verack', function(err) {
    self._onAck(err);
  });

  // Say hello.
  this.sendVersion();

  // Advertise our address.
  if (this.pool.address.host !== '0.0.0.0'
      && !this.pool.options.selfish
      && this.pool.server) {
    this.write(this.framer.addr([this.pool.address]));
  }
};

/**
 * Handle `ack` event (called on verack).
 * @private
 */

Peer.prototype._onAck = function _onAck(err) {
  var self = this;

  if (err) {
    this._error(err);
    return;
  }

  // Wait for _their_ version.
  if (!this.version) {
    this.logger.debug(
      'Peer sent a verack without a version (%s).',
      this.hostname);
    this.request('version', this._onAck.bind(this));
    return;
  }

  this.ack = true;
  this.ts = utils.now();

  // Setup the ping interval.
  this.pingTimer = setInterval(function() {
    self.sendPing();
  }, this.pingInterval);

  // Ask for headers-only.
  if (this.pool.options.headers) {
    if (this.version.version >= 70012)
      this.write(this.framer.sendHeaders());
  }

  // Let them know we support segwit (old
  // segwit3 nodes require this instead
  // of service bits).
  if (this.pool.options.witness && this.network.oldWitness) {
    if (this.version.version >= 70012)
      this.write(this.framer.haveWitness());
  }

  // We want compact blocks!
  if (this.pool.options.compact) {
    if (this.version.version >= 70014)
      this.sendCompact();
  }

  // Find some more peers.
  this.write(this.framer.getAddr());

  // Relay our spv filter if we have one.
  this.updateWatch();

  // Announce our currently broadcasted items.
  this.announce(this.pool.invItems);

  // Set a fee rate filter.
  if (this.pool.feeRate !== -1)
    this.sendFeeRate(this.pool.feeRate);

  // Start syncing the chain.
  this.sync();

  // Ask for the mempool if we're synced.
  if (this.network.requestMempool) {
    if (this.type === Peer.types.LOADER && this.pool.synced)
      this.sendMempool();
  }

  this.logger.debug('Received verack (%s).', this.hostname);

  // Finally we can let the pool know
  // that this peer is ready to go.
  this.emit('ack');
};

/**
 * Create the socket and begin connecting. This method
 * will use `options.createSocket` if provided.
 * @param {String} host
 * @param {Number} port
 * @returns {net.Socket}
 */

Peer.prototype.createSocket = function createSocket(port, host) {
  var self = this;
  var hostname = IP.hostname(host, port);
  var socket, proxy, net;

  if (this._createSocket) {
    socket = this._createSocket(port, host);
  } else {
    if (utils.isBrowser) {
      proxy = require('./proxysocket');
      socket = proxy.connect(this.pool.proxyServer, port, host);
    } else {
      net = require('net');
      socket = net.connect(port, host);
    }
  }

  this.logger.debug('Connecting to %s.', hostname);

  socket.once('connect', function() {
    self.logger.info('Connected to %s.', hostname);
  });

  this._connectTimeout = setTimeout(function() {
    self._error('Connection timed out.');
    self.ignore();
  }, 10000);

  return socket;
};

/**
 * Broadcast items to peer (transactions or blocks).
 * @param {Block[]|TX[]|InvItem[]|BroadcastEntry[]} items
 */

Peer.prototype.announce = function announce(items) {
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

  this.sendInv(inv);

  if (headers.length > 0)
    this.sendHeaders(headers);
};

/**
 * Send inv to a peer.
 * @param {InvItem[]} items
 */

Peer.prototype.sendInv = function sendInv(items) {
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
    this.write(this.framer.inv(chunk));
  }
};

/**
 * Send headers to a peer.
 * @param {Headers[]} items
 */

Peer.prototype.sendHeaders = function sendHeaders(items) {
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
    this.write(this.framer.headers(chunk));
  }
};

/**
 * Send a `version` packet.
 */

Peer.prototype.sendVersion = function sendVersion() {
  var packet = new VersionPacket({
    version: constants.VERSION,
    services: this.pool.services,
    ts: bcoin.now(),
    recv: new NetworkAddress(),
    from: this.pool.address,
    nonce: this.pool.localNonce,
    agent: constants.USER_AGENT,
    height: this.chain.height,
    relay: this.pool.options.relay
  });

  this.write(this.framer.version(packet));
};

/**
 * Send a `ping` packet.
 */

Peer.prototype.sendPing = function sendPing() {
  if (!this.version)
    return;

  if (this.version.version <= 60000) {
    this.write(this.framer.packet('ping', new Buffer([])));
    return;
  }

  if (this.challenge) {
    this.logger.debug('Peer has not responded to ping (%s).', this.hostname);
    return;
  }

  this.lastPing = utils.ms();
  this.challenge = utils.nonce();

  this.write(this.framer.ping({
    nonce: this.challenge
  }));
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

  if (item instanceof bcoin.tx)
    return item.isWatched(this.spvFilter);

  if (item.msg instanceof bcoin.tx)
    return item.msg.isWatched(this.spvFilter);

  return true;
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.pool.options.spv)
    return;

  this.write(this.framer.filterLoad(this.pool.spvFilter));
};

/**
 * Set a fee rate filter for the peer.
 * @param {Rate} rate
 */

Peer.prototype.sendFeeRate = function sendFeeRate(rate) {
  this.write(this.framer.feeFilter({
    rate: rate
  }));
};

/**
 * Disconnect from and destroy the peer.
 */

Peer.prototype.destroy = function destroy() {
  var i, j, keys, cmd, queue;

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

  this.emit('close');

  if (this.pingTimer) {
    clearInterval(this.pingTimer);
    this.pingTimer = null;
  }

  keys = Object.keys(this.requestMap);

  for (i = 0; i < keys.length; i++) {
    cmd = keys[i];
    queue = this.requestMap[cmd];

    for (j = 0; j < queue.length; j++)
      queue[j].destroy();
  }
};

/**
 * Write data to the peer's socket.
 * @param {Buffer} chunk
 * @returns {Boolean}
 */

Peer.prototype.write = function write(chunk) {
  if (this.destroyed)
    return false;

  this.lastSend = utils.ms();

  return this.socket.write(chunk);
};

/**
 * Emit an error and destroy the peer.
 * @private
 * @param {String|Error} err
 */

Peer.prototype._error = function error(err, keep) {
  if (this.destroyed)
    return;

  if (typeof err === 'string')
    err = new Error(err);

  err.message += ' (' + this.hostname + ')';

  if (!keep)
    this.destroy();

  this.emit('error', err);
};

/**
 * Wait for a packet to be received from peer.
 * @private
 * @param {String} cmd - Packet name.
 * @param {Function} callback - Returns [Error, Object(payload)].
 * Executed on timeout or once packet is received.
 */

Peer.prototype.request = function request(cmd, callback) {
  var entry;

  if (this.destroyed)
    return utils.asyncify(callback)(new Error('Destroyed, sorry'));

  entry = new RequestEntry(this, cmd, callback);

  if (!this.requestMap[cmd])
    this.requestMap[cmd] = [];

  this.requestMap[cmd].push(entry);

  return entry;
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

  res = entry.callback(null, payload, cmd);

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

    if (this.pool.options.compact
        && this.compactMode
        && item.isBlock()
        && !item.hasWitness()) {
      item.type = constants.inv.CMPCT_BLOCK;
    }

    data[i] = item;
  }

  this.write(this.framer.getData(data));
};

/**
 * Handle a packet payload.
 * @private
 * @param {Object} packet
 */

Peer.prototype._onPacket = function onPacket(packet) {
  var cmd = packet.cmd;
  var payload = packet.payload;

  if (this.bip151
      && !this.bip151.completed
      && cmd !== 'encinit'
      && cmd !== 'encack') {
    this.bip151.complete(new Error('Message before handshake.'));
  }

  if (this.bip150
      && !this.bip150.completed
      && cmd !== 'authchallenge'
      && cmd !== 'authreply'
      && cmd !== 'authpropose') {
    this.bip150.complete(new Error('Message before auth.'));
  }

  if (this.lastBlock && cmd !== 'tx')
    this._flushMerkle();

  this.lastRecv = utils.ms();

  switch (cmd) {
    case 'version':
      return this._handleVersion(payload);
    case 'inv':
      return this._handleInv(payload);
    case 'headers':
      return this._handleHeaders(payload);
    case 'getdata':
      return this._handleGetData(payload);
    case 'addr':
      return this._handleAddr(payload);
    case 'ping':
      return this._handlePing(payload);
    case 'pong':
      return this._handlePong(payload);
    case 'getaddr':
      return this._handleGetAddr(payload);
    case 'reject':
      return this._handleReject(payload);
    case 'alert':
      return this._handleAlert(payload);
    case 'getutxos':
      return this._handleGetUTXOs(payload);
    case 'utxos':
      return this._handleUTXOs(payload);
    case 'feefilter':
      return this._handleFeeFilter(payload);
    case 'getblocks':
      return this._handleGetBlocks(payload);
    case 'getheaders':
      return this._handleGetHeaders(payload);
    case 'mempool':
      return this._handleMempool(payload);
    case 'filterload':
      return this._handleFilterLoad(payload);
    case 'filteradd':
      return this._handleFilterAdd(payload);
    case 'filterclear':
      return this._handleFilterClear(payload);
    case 'block':
      this.fire(cmd, payload);
      break;
    case 'merkleblock':
      payload.verifyPartial();
      this.lastBlock = payload;
      this.waiting = payload.matches.length;
      if (this.waiting === 0)
        this._flushMerkle();
      break;
    case 'tx':
      if (this.lastBlock) {
        if (this.lastBlock.hasTX(payload)) {
          this.lastBlock.addTX(payload);
          if (--this.waiting === 0)
            this._flushMerkle();
          break;
        }
      }
      this.fire(cmd, payload);
      break;
    case 'sendheaders':
      this.preferHeaders = true;
      this.fire(cmd, payload);
      break;
    case 'havewitness':
      this.haveWitness = true;
      this.fire(cmd, payload);
      break;
    case 'verack':
      this.fire(cmd, payload);
      break;
    case 'notfound':
      this.fire(cmd, payload);
      break;
    case 'encinit':
      return this._handleEncinit(payload);
    case 'encack':
      return this._handleEncack(payload);
    case 'authchallenge':
      return this._handleAuthChallenge(payload);
    case 'authreply':
      return this._handleAuthReply(payload);
    case 'authpropose':
      return this._handleAuthPropose(payload);
    case 'sendcmpct':
      return this._handleSendCmpct(payload);
    case 'cmpctblock':
      return this._handleCmpctBlock(payload);
    case 'getblocktxn':
      return this._handleGetBlockTxn(payload);
    case 'blocktxn':
      return this._handleBlockTxn(payload);
    default:
      this.logger.warning('Unknown packet: %s.', cmd);
      this.fire(cmd, payload);
      break;
  }
};

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
 * @param {Object}
 */

Peer.prototype._handleFilterLoad = function _handleFilterLoad(payload) {
  if (!payload.isWithinConstraints()) {
    this.setMisbehavior(100);
    return;
  }

  this.spvFilter = payload;
  this.relay = true;
};

/**
 * Handle `filteradd` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleFilterAdd = function _handleFilterAdd(payload) {
  if (payload.data.length > constants.script.MAX_PUSH) {
    this.setMisbehavior(100);
    return;
  }

  if (this.spvFilter)
    this.spvFilter.add(payload.data);

  this.relay = true;
};

/**
 * Handle `filterclear` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleFilterClear = function _handleFilterClear(payload) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.relay = true;
};

/**
 * Handle `utxos` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleUTXOs = function _handleUTXOs(payload) {
  this.logger.debug('Received %d utxos (%s).',
    payload.coins.length, this.hostname);
  this.fire('utxos', payload);
};

/**
 * Handle `feefilter` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleFeeFilter = function _handleFeeFilter(payload) {
  if (!(payload.rate >= 0 && payload.rate <= constants.MAX_MONEY)) {
    this.setMisbehavior(100);
    return;
  }

  this.feeRate = payload.rate;

  this.fire('feefilter', payload);
};

/**
 * Request UTXOs from peer.
 * @param {Outpoint[]} outpoints
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Peer.prototype.getUTXOs = function getUTXOs(outpoints, callback) {
  var self = this;
  var reqs = [];
  var coins = [];
  var i;

  for (i = 0; i < outpoints.length; i += 15)
    reqs.push(outpoints.slice(i, i + 15));

  utils.forEachSerial(reqs, function(outpoints, next) {
    self._getUTXOs(outpoints, function(err, coin) {
      if (err)
        return next(err);

      coins = coins.concat(coin);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    callback(null, coins);
  });
};

/**
 * Send non-chunked getuxos to peer.
 * @private
 * @param {Outpoint[]} outpoints
 * @param {Function} callback
 */

Peer.prototype._getUTXOs = function _getUTXOs(outpoints, callback) {
  var index = 0;
  var i, prevout, coin;

  this.request('utxos', function(err, payload) {
    if (err)
      return callback(err);

    for (i = 0; i < payload.hits.length; i++) {
      if (payload.hits[i]) {
        prevout = outpoints[i];
        coin = payload.coins[index++];

        if (!prevout || !coin)
          return callback(new Error('Malformed utxos message.'));

        coin.hash = prevout.hash;
        coin.index = prevout.index;
      }
    }

    callback(null, payload.coins);
  });

  this.write(this.framer.getUTXOs({
    mempool: true,
    prevout: outpoints
  }));
};

/**
 * Handle `getutxos` packet.
 * @private
 */

Peer.prototype._handleGetUTXOs = function _handleGetUTXOs(payload) {
  var self = this;
  var coins = [];
  var hits = [];
  var unlock = this._lock(_handleGetUTXOs, [payload, utils.nop]);

  if (!unlock)
    return;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return unlock();
    }
    unlock();
  }

  if (!this.pool.synced)
    return done();

  if (this.pool.options.selfish)
    return done();

  if (this.chain.db.options.spv)
    return done();

  if (payload.prevout.length > 15)
    return done();

  utils.forEachSerial(payload.prevout, function(prevout, next) {
    var hash = prevout.hash;
    var index = prevout.index;
    var coin;

    if (self.mempool && payload.mempool) {
      coin = self.mempool.getCoin(hash, index);

      if (coin) {
        hits.push(1);
        coins.push(coin);
        return next();
      }

      if (self.mempool.isSpent(hash, index)) {
        hits.push(0);
        return next();
      }
    }

    self.chain.db.getCoin(hash, index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin) {
        hits.push(0);
        return next();
      }

      hits.push(1);
      coins.push(coin);

      next();
    });
  }, function(err) {
    if (err)
      return done(err);

    self.write(self.framer.UTXOs({
      height: self.chain.height,
      tip: self.chain.tip.hash,
      hits: hits,
      coins: coins
    }));

    done();
  });
};

/**
 * Handle `getheaders` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleGetHeaders = function _handleGetHeaders(payload) {
  var self = this;
  var headers = [];
  var unlock = this._lock(_handleGetHeaders, [payload, utils.nop]);

  if (!unlock)
    return;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return unlock();
    }
    self.sendHeaders(headers);
    unlock();
  }

  if (!this.pool.synced)
    return done();

  if (this.pool.options.selfish)
    return done();

  if (this.chain.db.options.spv)
    return done();

  if (this.chain.db.options.prune)
    return done();

  function collect(err, hash) {
    if (err)
      return done(err);

    if (!hash)
      return done();

    self.chain.db.get(hash, function(err, entry) {
      if (err)
        return done(err);

      if (!entry)
        return done();

      (function next(err, entry) {
        if (err)
          return done(err);

        if (!entry)
          return done();

        headers.push(entry.toHeaders());

        if (headers.length === 2000)
          return done();

        if (entry.hash === payload.stop)
          return done();

        entry.getNext(next);
      })(null, entry);
    });
  }

  if (payload.locator.length === 0)
    return collect(null, payload.stop);

  this.chain.findLocator(payload.locator, function(err, hash) {
    if (err)
      return collect(err);

    if (!hash)
      return collect();

    self.chain.db.getNextHash(hash, collect);
  });
};

/**
 * Handle `getblocks` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleGetBlocks = function _handleGetBlocks(payload) {
  var self = this;
  var blocks = [];
  var unlock = this._lock(_handleGetBlocks, [payload, utils.nop]);

  if (!unlock)
    return;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return unlock();
    }
    self.sendInv(blocks);
    unlock();
  }

  if (!this.pool.synced)
    return done();

  if (this.pool.options.selfish)
    return done();

  if (this.chain.db.options.spv)
    return done();

  if (this.chain.db.options.prune)
    return done();

  this.chain.findLocator(payload.locator, function(err, tip) {
    if (err)
      return done(err);

    if (!tip)
      return done();

    (function next(hash) {
      self.chain.db.getNextHash(hash, function(err, hash) {
        if (err)
          return done(err);

        if (!hash)
          return done();

        blocks.push(new InvItem(constants.inv.BLOCK, hash));

        if (hash === payload.stop)
          return done();

        if (blocks.length === 500) {
          self.hashContinue = hash;
          return done();
        }

        next(hash);
      });
    })(tip);
  });
};

/**
 * Handle `version` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleVersion = function _handleVersion(version) {
  var self = this;

  if (!this.network.selfConnect) {
    if (version.nonce.cmp(this.pool.localNonce) === 0) {
      this._error('We connected to ourself. Oops.');
      this.ignore();
      return;
    }
  }

  if (version.version < constants.MIN_VERSION) {
    this._error('Peer doesn\'t support required protocol version.');
    this.ignore();
    return;
  }

  if (this.type !== Peer.types.LEECH) {
    if (!version.hasNetwork()) {
      this._error('Peer does not support network services.');
      this.ignore();
      return;
    }
  }

  if (this.pool.options.headers) {
    if (!version.hasHeaders()) {
      this._error('Peer doesn\'t support getheaders.');
      this.ignore();
      return;
    }
  }

  if (this.pool.options.spv) {
    if (!version.hasBloom()) {
      this._error('Peer does not support bip37.');
      this.ignore();
      return;
    }
  }

  if (this.pool.options.witness) {
    if (!version.hasWitness()) {
      if (!this.network.oldWitness) {
        this._error('Peer does not support segregated witness.');
        this.ignore();
        return;
      }
      this.request('havewitness', function(err) {
        if (err) {
          self._error('Peer does not support segregated witness.');
          self.ignore();
        }
      });
    }
  }

  if (version.hasWitness())
    this.haveWitness = true;

  if (!version.relay)
    this.relay = false;

  // ACK
  this.write(this.framer.verack());
  this.version = version;
  this.fire('version', version);
};

/**
 * Handle `mempool` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleMempool = function _handleMempool() {
  var self = this;
  var items = [];
  var i, hashes;
  var unlock = this._lock(_handleMempool, [utils.nop]);

  if (!unlock)
    return;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return unlock();
    }
    unlock();
  }

  if (!this.mempool)
    return done();

  if (!this.pool.synced)
    return done();

  if (this.pool.options.selfish)
    return done();

  hashes = this.mempool.getSnapshot();

  for (i = 0; i < hashes.length; i++)
    items.push(new InvItem(constants.inv.TX, hashes[i]));

  self.logger.debug('Sending mempool snapshot (%s).', self.hostname);

  self.sendInv(items);
};

/**
 * Get a block/tx either from the broadcast map, mempool, or blockchain.
 * @param {InvItem} item
 * @param {Function} callback - Returns
 * [Error, {@link Block}|{@link MempoolEntry}].
 */

Peer.prototype._getItem = function _getItem(item, callback) {
  var entry = this.pool.invMap[item.hash];

  if (entry) {
    this.logger.debug(
      'Peer requested %s %s as a %s packet (%s).',
      entry.type === constants.inv.TX ? 'tx' : 'block',
      utils.revHex(entry.hash),
      item.hasWitness() ? 'witness' : 'normal',
      this.hostname);

    entry.ack(this);

    if (entry.msg)
      return callback(null, entry.msg);
  }

  if (this.pool.options.selfish)
    return callback();

  if (item.isTX()) {
    if (!this.mempool)
      return callback();
    return callback(null, this.mempool.getEntry(item.hash));
  }

  if (this.chain.db.options.spv)
    return callback();

  if (this.chain.db.options.prune)
    return callback();

  this.chain.db.getBlock(item.hash, callback);
};

/**
 * Handle `getdata` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleGetData = function _handleGetData(items) {
  var self = this;
  var notFound = [];
  var unlock = this._lock(_handleGetData, [items, utils.nop]);

  if (!unlock)
    return;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return unlock();
    }
    unlock();
  }

  if (items.length > 50000) {
    this._error('getdata size too large (%s).', items.length);
    return done();
  }

  utils.forEachSerial(items, function(item, next) {
    var i, tx, block;

    self._getItem(item, function(err, entry) {
      if (err)
        return next(err);

      if (!entry) {
        notFound.push(item);
        return next();
      }

      if (item.isTX()) {
        tx = entry.tx;

        // Coinbases are an insta-ban from any node.
        // This should technically never happen, but
        // it's worth keeping here just in case. A
        // 24-hour ban from any node is rough.
        if (tx.isCoinbase()) {
          notFound.push(item);
          self.logger.warning('Failsafe: tried to relay a coinbase.');
          return next();
        }

        // Fallback in case fee filter fails in `announce`.
        if (self.feeRate !== -1) {
          if (entry.getRate() < self.feeRate)
            return next();
        }

        if (item.hasWitness())
          self.write(self.framer.witnessTX(tx));
        else
          self.write(self.framer.tx(tx));

        return next();
      }

      block = entry;

      switch (item.type) {
        case constants.inv.BLOCK:
        case constants.inv.WITNESS_BLOCK:
          if (item.hasWitness())
            self.write(self.framer.witnessBlock(block));
          else
            self.write(self.framer.block(block));
          break;
        case constants.inv.FILTERED_BLOCK:
        case constants.inv.WITNESS_FILTERED_BLOCK:
          if (!self.spvFilter) {
            notFound.push(item);
            return next();
          }

          block = block.toMerkle(self.spvFilter);

          self.write(self.framer.merkleBlock(block));

          for (i = 0; i < block.txs.length; i++) {
            tx = block.txs[i];

            if (item.hasWitness())
              self.write(self.framer.witnessTX(tx));
            else
              self.write(self.framer.tx(tx));
          }

          break;
        case constants.inv.CMPCT_BLOCK:
          // Fallback to full block.
          if (block.height < self.chain.tip.height - 10) {
            self.write(self.framer.block(block));
            break;
          }

          // Try again with a new nonce
          // if we get a siphash collision.
          for (;;) {
            try {
              block = bcoin.bip152.CompactBlock.fromBlock(block);
            } catch (e) {
              continue;
            }
            break;
          }

          self.write(self.framer.cmpctBlock(block));
          break;
        default:
          self.logger.warning(
            'Peer sent an unknown getdata type: %s (%s).',
            item.type,
            self.hostname);
          notFound.push(item);
          return next();
      }

      if (item.hash === self.hashContinue) {
        self.sendInv(new InvItem(constants.inv.BLOCK, self.chain.tip.hash));
        self.hashContinue = null;
      }

      next();
    });
  }, function(err) {
    if (err)
      return done(err);

    self.logger.debug(
      'Served %d items with getdata (notfound=%d) (%s).',
      items.length - notFound.length,
      notFound.length,
      self.hostname);

    if (notFound.length > 0)
      self.write(self.framer.notFound(notFound));

    done();
  });
};

/**
 * Handle `addr` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleAddr = function _handleAddr(addrs) {
  var i;

  for (i = 0; i < addrs.length; i++)
    this.addrFilter.add(addrs[i].host, 'ascii');

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
 * @param {Object}
 */

Peer.prototype._handlePing = function _handlePing(data) {
  this.write(this.framer.pong(data));
  this.fire('ping', this.minPing);
};

/**
 * Handle `pong` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handlePong = function _handlePong(data) {
  var now = utils.ms();

  if (!this.challenge) {
    this.logger.debug('Peer sent an unsolicited pong (%s).', this.hostname);
    return;
  }

  if (data.nonce.cmp(this.challenge) !== 0) {
    if (data.nonce.cmpn(0) === 0) {
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
 * @param {Object}
 */

Peer.prototype._handleGetAddr = function _handleGetAddr() {
  var items = [];
  var i, host;

  if (this.pool.options.selfish)
    return;

  if (this.sentAddr) {
    this.logger.debug('Ignoring repeated getaddr (%s).', this.hostname);
    return;
  }

  this.sentAddr = true;

  for (i = 0; i < this.pool.hosts.items.length; i++) {
    host = this.pool.hosts.items[i];

    if (!host.isIP())
      continue;

    if (!this.addrFilter.added(host.host, 'ascii'))
      continue;

    items.push(host);

    if (items.length === 1000)
      break;
  }

  if (items.length === 0)
    return;

  this.logger.debug(
    'Sending %d addrs to peer (%s)',
    items.length,
    this.hostname);

  this.write(this.framer.addr(items));
};

/**
 * Handle `inv` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleInv = function _handleInv(items) {
  var blocks = [];
  var txs = [];
  var i, item, unknown;

  if (items.length > 50000) {
    this.setMisbehavior(100);
    return;
  }

  for (i = 0; i < items.length; i++) {
    item = items[i];
    if (item.type === constants.inv.TX) {
      txs.push(item.hash);
    } else if (item.type === constants.inv.BLOCK) {
      blocks.push(item.hash);
    } else {
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

  if (unknown != null) {
    this.logger.warning(
      'Peer sent an unknown inv type: %d (%s).',
      unknown, this.hostname);
  }
};

/**
 * Handle `headers` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleHeaders = function _handleHeaders(headers) {
  if (headers.length > 2000) {
    this.setMisbehavior(100);
    return;
  }
  this.fire('headers', headers);
};

/**
 * Handle `reject` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleReject = function _handleReject(payload) {
  var hash, entry;

  this.fire('reject', payload);

  if (!payload.data)
    return;

  hash = payload.data;
  entry = this.pool.invMap[hash];

  if (!entry)
    return;

  entry.reject(this);
};

/**
 * Handle `alert` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleAlert = function _handleAlert(alert) {
  this.invFilter.add(alert.hash());
  this.fire('alert', alert);
};

/**
 * Handle `encinit` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleEncinit = function _handleEncinit(payload) {
  if (!this.bip151)
    return;

  try {
    this.bip151.encinit(payload);
  } catch (e) {
    this._error(e);
    return;
  }

  this.write(this.framer.encack(this.bip151.toEncack()));

  this.fire('encinit', payload);
};

/**
 * Handle `encack` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleEncack = function _handleEncack(payload) {
  if (!this.bip151)
    return;

  try {
    this.bip151.encack(payload);
  } catch (e) {
    this._error(e);
    return;
  }

  this.fire('encack', payload);
};

/**
 * Handle `authchallenge` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleAuthChallenge = function _handleAuthChallenge(payload) {
  var result;

  if (!this.bip150)
    return;

  try {
    result = this.bip150.challenge(payload);
  } catch (e) {
    this._error(e);
    return;
  }

  this.write(this.framer.authReply(result));

  this.fire('authchallenge', payload);
};

/**
 * Handle `authreply` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleAuthReply = function _handleAuthReply(payload) {
  var result;

  if (!this.bip150)
    return;

  try {
    result = this.bip150.reply(payload);
  } catch (e) {
    this._error(e);
    return;
  }

  if (result)
    this.write(this.framer.authPropose(result));

  this.fire('authreply', payload);
};

/**
 * Handle `authpropose` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleAuthPropose = function _handleAuthPropose(payload) {
  var result;

  if (!this.bip150)
    return;

  try {
    result = this.bip150.propose(payload);
  } catch (e) {
    this._error(e);
    return;
  }

  this.write(this.framer.authChallenge(result));

  this.fire('authpropose', payload);
};

/**
 * Handle `sendcmpct` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleSendCmpct = function _handleSendCmpct(payload) {
  if (payload.version !== 1) {
    // Ignore
    return;
  }

  if (payload.mode !== 0) {
    // Ignore (we can't do mode 1 yet).
    return;
  }

  this.logger.info('Peer initialized compact blocks (%s).', this.hostname);

  this.compactMode = payload;
  this.fire('sendcmpct', payload);
};

/**
 * Handle `cmpctblock` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleCmpctBlock = function _handleCmpctBlock(block) {
  var self = this;
  var hash = block.hash('hex');
  var result;

  if (!this.pool.options.compact) {
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

  // Sort of a lock too.
  this.compactBlocks[hash] = block;

  result = block.fillMempool(this.mempool);

  if (result) {
    delete this.compactBlocks[hash];
    this.fire('block', block.toBlock());
    this.logger.debug(
      'Received full compact block %s (%s).',
      block.rhash, this.hostname);
    return;
  }

  this.write(this.framer.getBlockTxn(block.toRequest()));

  this.logger.debug(
    'Received semi-full compact block %s (%s).',
    block.rhash, this.hostname);

  block.startTimeout(10000, function() {
    self.logger.debug(
      'Compact block timed out: %s (%s).',
      block.rhash, self.hostname);
    delete self.compactBlocks[hash];
  });
};

/**
 * Handle `getblocktxn` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleGetBlockTxn = function _handleGetBlockTxn(req) {
  var self = this;
  var res, item;

  function done(err) {
    if (err) {
      self.emit('error', err);
      return;
    }
    self.fire('blocktxn', req);
  }

  if (this.chain.db.options.spv)
    return done();

  if (this.chain.db.options.prune)
    return done();

  if (this.pool.options.selfish)
    return done();

  item = new InvItem(constants.inv.BLOCK, req.hash);

  this._getItem(item, function(err, block) {
    if (err)
      return done(err);

    if (!block) {
      self.logger.debug(
        'Peer sent getblocktxn for non-existent block (%s).',
        self.hostname);
      self.setMisbehavior(100);
      return done();
    }

    if (block.height < self.chain.tip.height - 15) {
      self.logger.debug(
        'Peer sent a getblocktxn for a block > 15 deep (%s)',
        self.hostname);
      return done();
    }

    res = bcoin.bip152.TXResponse.fromBlock(block, req);

    self.write(self.framer.blockTxn(res));

    done();
  });
};

/**
 * Handle `blocktxn` packet.
 * @private
 * @param {Object}
 */

Peer.prototype._handleBlockTxn = function _handleBlockTxn(res) {
  var block = this.compactBlocks[res.hash];

  if (!block) {
    this.logger.debug('Peer sent unsolicited blocktxn (%s).', this.hostname);
    return;
  }

  this.fire('getblocktxn', res);

  block.stopTimeout();
  delete this.compactBlocks[res.hash];

  if (!block.fillMissing(res)) {
    this.setMisbehavior(100);
    this.logger.warning('Peer sent non-full blocktxn (%s).', this.hostname);
    return;
  }

  this.logger.debug(
    'Filled compact block %s (%s).',
    block.rhash, this.hostname);

  this.emit('block', block.toBlock());
};

/**
 * Send an `alert` to peer.
 * @param {AlertPacket} alert
 */

Peer.prototype.sendAlert = function sendAlert(alert) {
  if (!this.invFilter.added(alert.hash()))
    return;

  this.write(this.framer.alert(alert));
};

/**
 * Send `getheaders` to peer. Note that unlike
 * `getblocks`, `getheaders` can have a null locator.
 * @param {Hash[]?} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.sendGetHeaders = function sendGetHeaders(locator, stop) {
  var packet = new GetBlocksPacket(locator, stop);

  this.logger.debug(
    'Requesting headers packet from peer with getheaders (%s).',
    this.hostname);

  this.logger.debug('Height: %d, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : -1,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this.write(this.framer.getHeaders(packet));
};

/**
 * Send `getblocks` to peer.
 * @param {Hash[]} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.sendGetBlocks = function getBlocks(locator, stop) {
  var packet = new GetBlocksPacket(locator, stop);

  this.logger.debug(
    'Requesting inv packet from peer with getblocks (%s).',
    this.hostname);

  this.logger.debug('Height: %d, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : -1,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this.write(this.framer.getBlocks(packet));
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.sendMempool = function sendMempool() {
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

  this.write(this.framer.mempool());
};

/**
 * Send `reject` to peer.
 * @param {Object} reject - See {@link Framer.reject}.
 */

Peer.prototype.sendReject = function sendReject(code, reason, obj) {
  var reject = RejectPacket.fromReason(code, reason, obj);

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

  this.write(this.framer.reject(reject));
};

/**
 * Send a `sendcmpct` packet.
 */

Peer.prototype.sendCompact = function sendCompact() {
  var cmpct = new bcoin.bip152.SendCompact(0, 1);
  this.logger.info('Initializing compact blocks (%s).', this.hostname);
  this.write(this.framer.sendCmpct(cmpct));
};

/**
 * Check whether the peer is misbehaving (banScore >= 100).
 * @returns {Boolean}
 */

Peer.prototype.isMisbehaving = function isMisbehaving() {
  return this.pool.hosts.isMisbehaving(this.host);
};

/**
 * Check whether the peer is ignored.
 * @returns {Boolean}
 */

Peer.prototype.isIgnored = function isIgnored() {
  return this.pool.hosts.isIgnored(this.host);
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
  this.sendReject(code, reason, obj);
  if (score > 0)
    this.setMisbehavior(score);
};

/**
 * Send `getblocks` to peer after building
 * locator and resolving orphan root.
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash} orphan - Orphan hash to resolve.
 * @param {Function} callback
 */

Peer.prototype.resolveOrphan = function resolveOrphan(tip, orphan, callback) {
  var self = this;
  var root;

  callback = utils.ensure(callback);

  assert(orphan);

  this.chain.getLocator(tip, function(err, locator) {
    if (err)
      return callback(err);

    root = self.chain.getOrphanRoot(orphan);

    // Was probably resolved.
    if (!root) {
      self.logger.debug('Orphan root was already resolved.');
      return callback();
    }

    self.sendGetBlocks(locator, root);

    callback();
  });
};

/**
 * Send `getheaders` to peer after building locator.
 * @param {Hash} tip - Tip to build chain locator from.
 * @param {Hash?} stop
 * @param {Function} callback
 */

Peer.prototype.getHeaders = function getHeaders(tip, stop, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.chain.getLocator(tip, function(err, locator) {
    if (err)
      return callback(err);

    self.sendGetHeaders(locator, stop);

    callback();
  });
};

/**
 * Send `getblocks` to peer after building locator.
 * @param {Hash} tip - Tip hash to build chain locator from.
 * @param {Hash?} stop
 * @param {Function} callback
 */

Peer.prototype.getBlocks = function getBlocks(tip, stop, callback) {
  var self = this;

  callback = utils.ensure(callback);

  this.chain.getLocator(tip, function(err, locator) {
    if (err)
      return callback(err);

    self.sendGetBlocks(locator, stop);

    callback();
  });
};

/**
 * Start syncing from peer.
 * @param {Function} callback
 */

Peer.prototype.sync = function sync(callback) {
  var tip;

  if (!this.pool.syncing)
    return;

  if (!this.ack)
    return;

  if (this.syncSent)
    return;

  if (!this.version.hasNetwork())
    return;

  if (this.type !== Peer.types.LOADER) {
    if (!this.chain.isFull())
      return;
  }

  this.syncSent = true;

  if (this.pool.options.headers) {
    if (!this.chain.tip.isGenesis())
      tip = this.chain.tip.prevBlock;

    return this.getHeaders(tip, null, callback);
  }

  this.getBlocks(null, null, callback);
};

/**
 * Inspect the peer.
 * @returns {String}
 */

Peer.prototype.inspect = function inspect() {
  return '<Peer:'
    + ' id=' + this.id
    + ' ack=' + this.ack
    + ' host=' + this.hostname
    + ' ping=' + this.minPing
    + '>';
};

/**
 * RequestEntry
 * @constructor
 */

function RequestEntry(peer, cmd, callback) {
  this.peer = peer;
  this.cmd = cmd;
  this.callback = callback;
  this.id = peer.uid++;
  this.onTimeout = this._onTimeout.bind(this);
  this.timeout = setTimeout(this.onTimeout, this.peer.requestTimeout);
}

RequestEntry.prototype._onTimeout = function _onTimeout() {
  var queue = this.peer.requestMap[this.cmd];

  if (!queue)
    return;

  if (utils.binaryRemove(queue, this, compare)) {
    if (queue.length === 0)
      delete this.peer.requestMap[this.cmd];
    this.callback(new Error('Timed out: ' + this.cmd));
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
