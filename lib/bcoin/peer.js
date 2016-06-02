/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var IP = require('./ip');
var assert = utils.assert;
var constants = bcoin.protocol.constants;

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

  this.options = options;
  this.pool = pool;
  this.socket = null;
  this.host = null;
  this.port = 0;
  this.hostname = null;
  this._createSocket = this.options.createSocket;
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.network = this.chain.network;
  this.parser = new bcoin.protocol.parser({ network: this.network });
  this.framer = new bcoin.protocol.framer({ network: this.network });
  this.locker = new bcoin.locker(this);
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = this.options.ts || 0;
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

  this.challenge = null;
  this.lastPong = -1;
  this.lastPing = -1;
  this.minPing = -1;

  this.banScore = 0;

  if (options.socket) {
    this.socket = options.socket;
    this.host = IP.normalize(this.socket.remoteAddress);
    this.port = this.socket.remotePort;
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

  this.requests = {
    timeout: this.options.requestTimeout || 10000,
    skip: {},
    map: {}
  };

  this.ping = {
    timer: null,
    interval: this.options.pingInterval || 120000
  };

  this.queue = {
    block: [],
    tx: []
  };

  this.uid = 0;
  this.id = Peer.uid++;

  this.setMaxListeners(10000);

  this._init();
}

utils.inherits(Peer, EventEmitter);

Peer.uid = 0;

Peer.prototype._init = function init() {
  var self = this;

  this.socket.once('connect', function() {
    self.ts = utils.now();
    self.connected = true;
    self.emit('connect');
  });

  this.socket.once('error', function(err) {
    self._error(err);
    self.setMisbehavior(100);
  });

  this.socket.once('close', function() {
    self._error('socket hangup');
    self.connected = false;
  });

  this.socket.on('data', function(chunk) {
    self.parser.feed(chunk);
  });

  this.parser.on('packet', function(packet) {
    self._onPacket(packet);
  });

  this.parser.on('error', function(err) {
    self.sendReject(null, 'malformed', 'error parsing message', 10);
    self._error(err, true);
  });

  this.request('verack', function callee(err) {
    if (err) {
      self._error(err);
      self.destroy();
      return;
    }

    // Wait for _their_ version.
    if (!self.version) {
      bcoin.debug(
        'Peer sent a verack without a version (%s).',
        self.hostname);
      self.request('version', callee);
      return;
    }

    self.ack = true;
    self.ts = utils.now();

    // Setup the ping interval.
    self.ping.timer = setInterval(function() {
      self.sendPing();
    }, self.ping.interval);

    // Ask for headers-only.
    if (self.options.headers) {
      if (self.version.version > 70012)
        self.write(self.framer.sendHeaders());
    }

    // Let them know we support segwit (old
    // segwit3 nodes require this instead
    // of service bits).
    if (self.options.witness) {
      if (self.version.version >= 70012)
        self.write(self.framer.haveWitness());
    }

    // Find some more peers.
    self.write(self.framer.getAddr());

    // Relay our spv filter if we have one.
    self.updateWatch();

    // Announce our currently broadcasted items.
    self.announce(self.pool.inv.items);

    // Set a fee rate filter.
    if (self.pool.feeRate !== -1)
      self.setFeeRate(self.pool.feeRate);

    // Finally we can let the pool know
    // that this peer is ready to go.
    self.emit('ack');
  });

  // Say hello.
  this.write(this.framer.version({
    version: constants.VERSION,
    services: constants.LOCAL_SERVICES,
    ts: bcoin.now(),
    remote: {},
    local: {
      services: constants.LOCAL_SERVICES,
      host: this.pool.host,
      port: this.pool.port
    },
    nonce: this.pool.localNonce,
    agent: constants.USER_AGENT,
    height: this.chain.height,
    relay: this.options.relay,
  }));

  // Advertise our address.
  if (this.pool.host !== '0.0.0.0'
      && !this.pool.options.selfish
      && this.pool.server) {
    this.write(this.framer.addr([{
      ts: utils.now() - (process.uptime() | 0),
      services: constants.LOCAL_SERVICES,
      host: this.pool.host,
      port: this.pool.port
    }]));
  }
};

/**
 * Create the socket and begin connecting. This method
 * will use `options.createSocket` if provided.
 * @param {String} host
 * @param {Number} port
 * @returns {net.Socket}
 */

Peer.prototype.createSocket = function createSocket(port, host) {
  var hostname = IP.hostname(host, port);
  var socket, net;

  if (this._createSocket) {
    socket = this._createSocket(port, host);
  } else {
    if (bcoin.isBrowser)
      throw new Error('Please include a `createSocket` callback.');
    net = require('n' + 'et');
    socket = net.connect(port, host);
  }

  bcoin.debug('Connecting to %s.', hostname);

  socket.once('connect', function() {
    bcoin.debug('Connected to %s.', hostname);
  });

  return socket;
};

/**
 * Broadcast items to peer (transactions or blocks).
 * @param {Block[]|TX[]|InvItem[]|BroadcastEntry[]} items
 */

Peer.prototype.announce = function announce(items) {
  var inv = [];
  var headers = [];
  var i, item;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];

    if (!this.isWatched(item))
      continue;

    if (this.preferHeaders) {
      if (item instanceof bcoin.abstractblock) {
        headers.push(item);
        continue;
      }
    }

    if (item.toInv)
      item = item.toInv();

    if (!this.relay) {
      if (item.type === constants.inv.TX)
        continue;
    }

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
  var inv = [];
  var i, item, chunk;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];
    this.invFilter.add(item.hash, 'hex');
    inv.push(item);
  }

  if (inv.length === 0)
    return;

  bcoin.debug('Serving %d inv items to %s.',
    inv.length, this.hostname);

  for (i = 0; i < inv.length; i += 50000) {
    chunk = inv.slice(i, i + 50000);
    this.write(this.framer.inv(chunk));
  }
};

/**
 * Send headers to a peer.
 * @param {Headers[]} items
 */

Peer.prototype.sendHeaders = function sendHeaders(items) {
  var headers = [];
  var i, item, chunk;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  for (i = 0; i < items.length; i++) {
    item = items[i];
    this.invFilter.add(item.hash());
    headers.push(item);
  }

  if (headers.length === 0)
    return;

  bcoin.debug('Serving %d headers to %s.',
    headers.length, this.hostname);

  for (i = 0; i < headers.length; i += 2000) {
    chunk = headers.slice(i, i + 2000);
    this.write(this.framer.headers(chunk));
  }
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
    bcoin.debug('Peer has not responded to ping (%s).', this.hostname);
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

  if (this.ack)
    this.write(this.framer.filterLoad(this.pool.spvFilter));
};

/**
 * Set a fee rate filter for the peer.
 * @param {Rate} rate
 */

Peer.prototype.setFeeRate = function setFeeRate(rate) {
  this.write(this.framer.feeFilter({
    rate: rate
  }));
};

/**
 * Disconnect from and destroy the peer.
 */

Peer.prototype.destroy = function destroy() {
  if (this.destroyed)
    return;

  this.destroyed = true;
  this.socket.destroy();
  this.socket = null;
  this.emit('close');

  if (this.ping.timer) {
    clearInterval(this.ping.timer);
    this.ping.timer = null;
  }

  Object.keys(this.requests.map).forEach(function(cmd) {
    var queue = this.requests.map[cmd];
    var i;

    for (i = 0; i < queue.length; i++)
      clearTimeout(queue[i].timer);
  }, this);
};

/**
 * Write data to the peer's socket.
 * @param {Buffer} chunk
 * @returns {Boolean}
 */

Peer.prototype.write = function write(chunk) {
  if (this.destroyed)
    return false;

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
  var self = this;
  var entry;

  if (this.destroyed)
    return utils.asyncify(callback)(new Error('Destroyed, sorry'));

  entry = {
    cmd: cmd,
    callback: callback,
    id: this.uid++,
    ontimeout: function() {
      var queue = self.requests.map[cmd];

      if (!queue)
        return;

      if (utils.binaryRemove(queue, entry, compare)) {
        if (queue.length === 0)
          delete self.requests.map[cmd];
        callback(new Error('Timed out: ' + cmd));
      }
    },
    timer: null
  };

  entry.timer = setTimeout(entry.ontimeout, this.requests.timeout);

  if (!this.requests.map[cmd])
    this.requests.map[cmd] = [];

  this.requests.map[cmd].push(entry);

  return entry;
};

/**
 * Fulfill awaiting requests created with {@link Peer#request}.
 * @private
 * @param {String} cmd - Packet name.
 * @param {Object} payload
 */

Peer.prototype.response = function response(cmd, payload) {
  var queue = this.requests.map[cmd];
  var entry, res;

  if (!queue)
    return false;

  entry = queue[0];

  if (!entry)
    return false;

  res = entry.callback(null, payload, cmd);

  if (res !== this.requests.skip) {
    queue.shift();
    if (queue.length === 0)
      delete this.requests.map[cmd];
    clearTimeout(entry.timer);
    entry.timer = null;
    return true;
  }

  return false;
};

/**
 * Send `getdata` to peer.
 * @param {Object[]} items - See {@link Framer.getData}.
 */

Peer.prototype.getData = function getData(items) {
  this.write(this.framer.getData(items));
};

Peer.prototype._onPacket = function onPacket(packet) {
  var cmd = packet.cmd;
  var payload = packet.payload;

  if (this.lastBlock && cmd !== 'tx')
    this._flushMerkle();

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
      payload = new bcoin.compactblock(payload);
      this.fire(cmd, payload);
      break;
    case 'merkleblock':
      payload = new bcoin.merkleblock(payload);
      payload.verifyPartial();
      this.lastBlock = payload;
      this.waiting = payload.matches.length;
      if (this.waiting === 0)
        this._flushMerkle();
      break;
    case 'tx':
      payload = new bcoin.tx(payload);
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
    default:
      bcoin.debug('Unknown packet: %s.', cmd);
      this.fire(cmd, payload);
      break;
  }
};

Peer.prototype.fire = function fire(cmd, payload) {
  this.response(cmd, payload);
  this.emit(cmd, payload);
};

Peer.prototype._flushMerkle = function _flushMerkle() {
  if (this.lastBlock)
    this.fire('merkleblock', this.lastBlock);
  this.lastBlock = null;
  this.waiting = 0;
};

Peer.prototype._handleFilterLoad = function _handleFilterLoad(payload) {
  this.spvFilter = new bcoin.bloom(
    payload.filter,
    payload.n,
    payload.tweak,
    payload.update
  );

  if (!this.spvFilter.isWithinConstraints()) {
    this.spvFilter = null;
    this.setMisbehavior(100);
    return;
  }

  this.relay = true;
};

Peer.prototype._handleFilterAdd = function _handleFilterAdd(payload) {
  if (payload.data.length > constants.script.MAX_PUSH) {
    this.setMisbehavior(100);
    return;
  }

  if (this.spvFilter)
    this.spvFilter.add(payload.data);

  this.relay = true;
};

Peer.prototype._handleFilterClear = function _handleFilterClear(payload) {
  if (this.spvFilter)
    this.spvFilter.reset();

  this.relay = true;
};

Peer.prototype._handleUTXOs = function _handleUTXOs(payload) {
  payload.coins = payload.coins(function(coin) {
    return new bcoin.coin(coin);
  });
  bcoin.debug('Received %d utxos (%s).',
    payload.coins.length, this.hostname);
  this.fire('utxos', payload);
};

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
 * @param {Array[]} - Array in the form `[[hash, index], ...]`.
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Peer.prototype.getUTXOs = function getUTXOs(utxos, callback) {
  var self = this;
  var reqs = [];
  var coins = [];
  var i;

  for (i = 0; i < utxos.length; i += 15)
    reqs.push(utxos.slice(i, i + 15));

  utils.forEachSerial(reqs, function(utxos, next) {
    self._getUTXOs(utxos, function(err, coin) {
      if (err)
        return next(err);

      coins = coins.concat(coin);

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    return callback(null, coins);
  });
};

Peer.prototype._getUTXOs = function _getUTXOs(utxos, callback) {
  var index = 0;
  var i, prevout, coin;

  this.request('utxos', function(err, payload) {
    if (err)
      return callback(err);

    for (i = 0; i < payload.hits.length; i++) {
      if (payload.hits[i]) {
        prevout = utxos[i];
        coin = payload.coins[index++];

        if (!prevout || !coin)
          return callback(new Error('Malformed utxos message.'));

        coin.hash = prevout.hash;
        coin.index = prevout.index;
      }
    }

    return callback(null, payload.coins);
  });

  this.write(this.framer.getUTXOs({
    mempool: true,
    prevout: utxos.map(function(item) {
      return { hash: item[0], index: item[1] };
    })
  }));
};

Peer.prototype._handleGetUTXOs = function _handleGetUTXOs(payload) {
  var self = this;
  var coins = [];
  var hits = [];

  var unlock = this.locker.lock(_handleGetUTXOs, [payload]);
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

  function checkMempool(hash, index, callback) {
    if (!self.mempool)
      return callback();

    if (!payload.mempool)
      return callback();

    self.mempool.getCoin(hash, index, callback);
  }

  function isSpent(hash, index, callback) {
    if (!self.mempool)
      return callback(null, false);

    if (!payload.mempool)
      return callback(null, false);

    self.mempool.isSpent(hash, index, callback);
  }

  if (payload.prevout.length > 15)
    return done();

  utils.forEachSerial(payload.prevout, function(prevout, next) {
    var hash = prevout.hash;
    var index = prevout.index;

    checkMempool(hash, index, function(err, coin) {
      if (err)
        return next(err);

      if (coin) {
        hits.push(1);
        coins.push(coin);
        return next();
      }

      isSpent(hash, index, function(err, result) {
        if (err)
          return next(err);

        if (result) {
          hits.push(0);
          return next();
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
      });
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

Peer.prototype._handleGetHeaders = function _handleGetHeaders(payload) {
  var self = this;
  var headers = [];

  var unlock = this.locker.lock(_handleGetHeaders, [payload]);
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

        headers.push(new bcoin.headers(entry));

        if (headers.length === 2000)
          return done();

        if (entry.hash === payload.stop)
          return done();

        entry.getNext(next);
      })(null, entry);
    });
  }

  if (!payload.locator)
    return collect(null, payload.stop);

  this.chain.findLocator(payload.locator, function(err, hash) {
    if (err)
      return collect(err);

    if (!hash)
      return collect();

    self.chain.db.getNextHash(hash, collect);
  });
};

Peer.prototype._handleGetBlocks = function _handleGetBlocks(payload) {
  var self = this;
  var blocks = [];

  var unlock = this.locker.lock(_handleGetBlocks, [payload]);
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

        blocks.push({ type: constants.inv.BLOCK, hash: hash });

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

Peer.prototype._handleVersion = function _handleVersion(payload) {
  var self = this;
  var version = payload.version;
  var services = payload.services;

  if (this.network.type !== 'regtest') {
    if (payload.nonce.cmp(this.pool.localNonce) === 0) {
      this._error('We connected to ourself. Oops.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (version < constants.MIN_VERSION) {
    this._error('Peer doesn\'t support required protocol version.');
    this.setMisbehavior(100);
    return;
  }

  if (this.options.headers) {
    if (version < 31800) {
      this._error('Peer doesn\'t support getheaders.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.network) {
    if (!(services & constants.services.NETWORK)) {
      this._error('Peer does not support network services.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.spv) {
    if (version < 70011 || !(services & constants.services.BLOOM)) {
      this._error('Peer does not support bip37.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.witness) {
    if (!(services & constants.services.WITNESS)) {
      this.request('havewitness', function(err) {
        if (err) {
          self._error('Peer does not support segregated witness.');
          self.setMisbehavior(100);
        }
      });
    }
  }

  if (payload.witness)
    this.haveWitness = true;

  if (payload.relay === false)
    this.relay = false;

  // ACK
  this.write(this.framer.verack());
  this.version = payload;
  this.fire('version', payload);
};

Peer.prototype._handleMempool = function _handleMempool() {
  var self = this;
  var items = [];
  var i;

  var unlock = this.locker.lock(_handleMempool, []);
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

  this.mempool.getSnapshot(function(err, hashes) {
    if (err)
      return done(err);

    for (i = 0; i < hashes.length; i++)
      items.push({ type: constants.inv.TX, hash: hashes[i] });

    bcoin.debug('Sending mempool snapshot (%s).', self.hostname);

    self.sendInv(items);
    done();
  });
};

Peer.prototype._handleGetData = function _handleGetData(items) {
  var self = this;
  var check = [];
  var notfound = [];
  var i, item, entry, witness;

  var unlock = this.locker.lock(_handleGetData, [items]);
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

  for (i = 0; i < items.length; i++) {
    item = items[i];
    entry = this.pool.inv.map[item.hash];
    witness = (item.type & constants.WITNESS_MASK) !== 0;

    if (!entry) {
      check.push(item);
      continue;
    }

    if ((item.type & ~constants.WITNESS_MASK) !== entry.type) {
      bcoin.debug(
        'Peer requested an existing item with the wrong type (%s).',
        this.hostname);
      continue;
    }

    bcoin.debug(
      'Peer requested %s %s as a %s packet (%s).',
      entry.type === constants.inv.TX ? 'tx' : 'block',
      utils.revHex(entry.hash),
      witness ? 'witness' : 'normal',
      this.hostname);

    if (!entry.send(this, witness))
      check.push(item);
  }

  if (this.pool.options.selfish)
    return done();

  utils.forEachSerial(check, function(item, next) {
    var type = item.type & ~constants.WITNESS_MASK;
    var witness = (item.type & constants.WITNESS_MASK) !== 0;
    var hash = item.hash;
    var i, tx, data;

    if (type === constants.inv.TX) {
      if (!self.mempool) {
        notfound.push({ type: constants.inv.TX, hash: hash });
        return next();
      }
      return self.mempool.getEntry(hash, function(err, entry) {
        if (err)
          return next(err);

        if (!entry) {
          notfound.push({ type: constants.inv.TX, hash: hash });
          return next();
        }

        tx = entry.tx;

        // We should technically calculate this in
        // the `mempool` handler, but it would be
        // too slow.
        if (self.feeRate !== -1) {
          if (bcoin.tx.getRate(entry.size, entry.fees) < self.feeRate)
            return next();
        }

        data = witness
          ? self.framer.witnessTX(tx)
          : self.framer.tx(tx);

        self.write(data);

        next();
      });
    }

    if (type === constants.inv.BLOCK) {
      if (self.chain.db.options.spv) {
        notfound.push({ type: constants.inv.BLOCK, hash: hash });
        return next();
      }
      if (self.chain.db.options.prune) {
        notfound.push({ type: constants.inv.BLOCK, hash: hash });
        return next();
      }
      return self.chain.db.getBlock(hash, function(err, block) {
        if (err)
          return next(err);

        if (!block) {
          notfound.push({ type: constants.inv.BLOCK, hash: hash });
          return next();
        }

        data = witness
          ? self.framer.witnessBlock(block)
          : self.framer.block(block);

        self.write(data);

        if (hash === self.hashContinue) {
          self.sendInv({
            type: constants.inv.BLOCK,
            hash: self.chain.tip.hash
          });
          self.hashContinue = null;
        }

        next();
      });
    }

    if (type === constants.inv.FILTERED_BLOCK) {
      if (self.chain.db.options.spv) {
        notfound.push({ type: constants.inv.BLOCK, hash: hash });
        return next();
      }
      if (self.chain.db.options.prune) {
        notfound.push({ type: constants.inv.BLOCK, hash: hash });
        return next();
      }
      return self.chain.db.getBlock(hash, function(err, block) {
        if (err)
          return next(err);

        if (!block) {
          notfound.push({ type: constants.inv.BLOCK, hash: hash });
          return next();
        }

        block = block.toMerkle(self.spvFilter);

        self.write(self.framer.merkleBlock(block));

        for (i = 0; i < block.txs.length; i++) {
          tx = block.txs[i];

          tx = witness
            ? self.framer.witnessTX(tx)
            : self.framer.tx(tx);

          self.write(tx);
        }

        if (hash === self.hashContinue) {
          self.sendInv({
            type: constants.inv.BLOCK,
            hash: self.chain.tip.hash
          });
          self.hashContinue = null;
        }

        next();
      });
    }

    notfound.push({ type: type, hash: hash });

    return next();
  }, function(err) {
    if (err)
      self.emit('error', err);

    bcoin.debug(
      'Served %d items with getdata (notfound=%d) (%s).',
      items.length - notfound.length,
      notfound.length,
      self.hostname);

    if (notfound.length > 0)
      self.write(self.framer.notFound(notfound));

    done();
  });
};

Peer.prototype._handleAddr = function _handleAddr(addrs) {
  var hosts = [];
  var i, addr;

  for (i = 0; i < addrs.length; i++) {
    addr = new NetworkAddress(addrs[i]);
    this.addrFilter.add(addr.host, 'ascii');
    hosts.push(addr);
  }

  bcoin.debug(
    'Received %d addrs (hosts=%d, peers=%d) (%s).',
    hosts.length,
    this.pool.hosts.length,
    this.pool.peers.all.length,
    this.hostname);

  this.fire('addr', hosts);
};

Peer.prototype._handlePing = function _handlePing(data) {
  this.write(this.framer.pong(data));
  this.fire('ping', this.minPing);
};

Peer.prototype._handlePong = function _handlePong(data) {
  var now = utils.ms();

  if (!this.challenge) {
    bcoin.debug('Peer sent an unsolicited pong (%s).', this.hostname);
    return;
  }

  if (data.nonce.cmp(this.challenge) !== 0) {
    if (data.nonce.cmpn(0) === 0) {
      bcoin.debug('Peer sent a zero nonce (%s).', this.hostname);
      this.challenge = null;
      return;
    }
    bcoin.debug('Peer sent the wrong nonce (%s).', this.hostname);
    return;
  }

  if (now >= this.lastPing) {
    this.lastPong = now;
    if (this.minPing === -1)
      this.minPing = now - this.lastPing;
    this.minPing = Math.min(this.minPing, now - this.lastPing);
  } else {
    bcoin.debug('Timing mismatch (what?) (%s).', this.hostname);
  }

  this.challenge = null;

  this.fire('pong', this.minPing);
};

Peer.prototype._handleGetAddr = function _handleGetAddr() {
  var items = [];
  var i, host;

  if (this.pool.options.selfish)
    return;

  for (i = 0; i < this.pool.hosts.length; i++) {
    host = this.pool.hosts[i];

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

  bcoin.debug(
    'Sending %d addrs to peer (%s)',
    items.length,
    this.hostname);

  this.write(this.framer.addr(items));
};

Peer.prototype._handleInv = function _handleInv(items) {
  var blocks = [];
  var txs = [];
  var i, item, unknown;

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

  if (unknown != null)
    bcoin.debug('Peer sent an unknown inv type: %d (%s).', unknown);
};

Peer.prototype._handleHeaders = function _handleHeaders(headers) {
  headers = headers.map(function(header) {
    return new bcoin.headers(header);
  });

  this.fire('headers', headers);
};

Peer.prototype._handleReject = function _handleReject(payload) {
  var hash, entry;

  this.fire('reject', payload);

  if (!payload.data)
    return;

  hash = payload.data;
  entry = this.pool.inv.map[hash];

  if (!entry)
    return;

  entry.reject(this);
};

Peer.prototype._handleAlert = function _handleAlert(details) {
  var hash = utils.dsha256(details.payload);
  var signature = details.signature;

  if (!bcoin.ec.verify(hash, signature, this.network.alertKey)) {
    bcoin.debug('Peer sent a phony alert packet (%s).', this.hostname);
    // Let's look at it because why not?
    bcoin.debug(details);
    this.setMisbehavior(100);
    return;
  }

  this.fire('alert', details);
};

/**
 * Send `getheaders` to peer. Note that unlike
 * `getblocks`, `getheaders` can have a null locator.
 * @param {Hash[]?} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.getHeaders = function getHeaders(locator, stop) {
  bcoin.debug(
    'Requesting headers packet from peer with getheaders (%s).',
    this.hostname);

  bcoin.debug('Height: %d, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : -1,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this.write(this.framer.getHeaders({ locator: locator, stop: stop }));
};

/**
 * Send `getblocks` to peer.
 * @param {Hash[]} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.getBlocks = function getBlocks(locator, stop) {
  bcoin.debug(
    'Requesting inv packet from peer with getblocks (%s).',
    this.hostname);

  bcoin.debug('Height: %d, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : -1,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this.write(this.framer.getBlocks({ locator: locator, stop: stop }));
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.getMempool = function getMempool() {
  bcoin.debug(
    'Requesting inv packet from peer with mempool (%s).',
    this.hostname);

  this.write(this.framer.mempool());
};

/**
 * Send `reject` to peer.
 * @param {Object} details - See {@link Framer.reject}.
 */

Peer.prototype.reject = function reject(details) {
  bcoin.debug(
    'Sending reject packet to peer (%s).',
    this.hostname);

  this.write(this.framer.reject(details));
};

/**
 * Check whether the peer is misbehaving (banScore >= 100).
 * @returns {Boolean}
 */

Peer.prototype.isMisbehaving = function isMisbehaving() {
  return this.pool.isMisbehaving(this.host);
};

/**
 * Increase banscore on peer.
 * @param {Number} score
 */

Peer.prototype.setMisbehavior = function setMisbehavior(score) {
  return this.pool.setMisbehavior(this, score);
};

/**
 * Send a `reject` packet to peer.
 * @see Framer.reject
 * @param {(TX|Block)?} obj
 * @param {String} code - cccode.
 * @param {String} reason
 * @param {Number} score
 */

Peer.prototype.sendReject = function sendReject(obj, code, reason, score) {
  return this.pool.reject(this, obj, code, reason, score);
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
 * Represents a network address.
 * @exports NetworkAddress
 * @constructor
 * @private
 * @param {NakedNetworkAddress} options
 */

function NetworkAddress(options) {
  var host, ts, now;

  if (!(this instanceof NetworkAddress))
    return new NetworkAddress(options);

  now = utils.now();
  host = options.host;
  ts = options.ts;

  if (ts <= 100000000 || ts > now + 10 * 60)
    ts = now - 5 * 24 * 60 * 60;

  if (IP.version(host) !== -1)
    host = IP.normalize(host);

  assert(typeof host === 'string');
  assert(typeof options.port === 'number');
  assert(typeof options.services === 'number');
  assert(typeof options.ts === 'number');

  this.id = NetworkAddress.uid++;
  this.host = host;
  this.port = options.port;
  this.services = options.services;
  this.ts = ts;
}

NetworkAddress.uid = 0;

/**
 * Test whether the `host` field is an ip address.
 * @returns {Boolean}
 */

NetworkAddress.prototype.isIP = function isIP() {
  return IP.version(this.host) !== -1;
};

/**
 * Test whether the NETWORK service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasNetwork = function hasNetwork() {
  return (this.services & constants.services.NETWORK) !== 0;
};

/**
 * Test whether the BLOOM service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasBloom = function hasBloom() {
  return (this.services & constants.services.BLOOM) !== 0;
};

/**
 * Test whether the GETUTXO service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasUTXO = function hasUTXO() {
  return (this.services & constants.services.GETUTXO) !== 0;
};

/**
 * Test whether the WITNESS service bit is set.
 * @returns {Boolean}
 */

NetworkAddress.prototype.hasWitness = function hasWitness() {
  return (this.services & constants.services.WITNESS) !== 0;
};

/**
 * Inspect the network address.
 * @returns {Object}
 */

NetworkAddress.prototype.inspect = function inspect() {
  return '<NetworkAddress:'
    + ' id=' + this.id
    + ' hostname=' + IP.hostname(this.host, this.port)
    + ' services=' + this.services.toString(2)
    + ' date=' + utils.date(this.ts)
    + '>';
};

/**
 * Instantiate a network address
 * from a hostname (i.e. 127.0.0.1:8333).
 * @param {String} hostname
 * @param {(Network|NetworkType)?} network
 * @returns {NetworkAddress}
 */

NetworkAddress.fromHostname = function fromHostname(hostname, network) {
  var address = IP.parseHost(hostname);
  network = bcoin.network.get(network);
  return new NetworkAddress({
    host: address.host,
    port: address.port || network.port,
    version: constants.VERSION,
    services: constants.services.NETWORK
      | constants.services.BLOOM
      | constants.services.WITNESS,
    ts: utils.now()
  });
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

exports = Peer;
exports.NetworkAddress = NetworkAddress;

module.exports = exports;
