/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * @typedef {Object} Seed
 * @global
 * @property {String} host
 * @property {Number} port
 */

/**
 * Represents a remote peer.
 * @exports Peer
 * @constructor
 * @param {Pool} pool
 * @param {Object} options
 * @param {Function?} options.createSocket - Callback which returns a
 * node.js-like socket object. Necessary for browser.
 * @param {Boolean} priority - Whether this peer is high
 * priority (i.e. a loader).
 * @param {Chain} options.chain
 * @param {Mempool} options.mempool
 * @param {Bloom} options.bloom - The _local_ bloom filter.
 * @param {Number?} options.ts - Time at which peer was discovered (unix time).
 * @param {net.Socket?} options.socket
 * @param {Seed?} options.seed - Host to connect to.
 * @property {Pool} pool
 * @property {net.Socket?} socket
 * @property {String?} host
 * @property {Number} port
 * @property {Boolean} priority
 * @property {Parser} parser
 * @property {Framer} framer
 * @property {Chain} chain
 * @property {Mempool} mempool
 * @property {Bloom} bloom
 * @property {Object?} version - Version packet payload.
 * @property {Boolean} destroyed
 * @property {Boolean} ack - Whether verack has been received.
 * @property {Boolean} connected
 * @property {Number} ts
 * @property {Boolean} sendHeaders - Whether the peer has
 * requested getheaders.
 * @property {Boolean} haveWitness - Whether the peer supports segwit,
 * either notified via service bits or deprecated `havewitness` packet.
 * @property {Hash?} hashContinue - The block hash at which to continue
 * the sync for the peer.
 * @property {Bloom?} filter - The _peer's_ bloom filter.
 * @property {Boolean} relay - Whether to relay transactions
 * immediately to the peer.
 * @property {BN} challenge - Local nonce.
 * @property {Number} lastPong - Timestamp for last `pong`
 * received (unix time).
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
  this._createSocket = this.options.createSocket;
  this.priority = this.options.priority;
  this.parser = new bcoin.protocol.parser();
  this.framer = new bcoin.protocol.framer();
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.bloom = this.pool.bloom;
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = this.options.ts || 0;
  this.sendHeaders = false;
  this.haveWitness = false;
  this.hashContinue = null;
  this.filter = null;
  this.relay = true;

  this.challenge = null;
  this.lastPong = 0;

  this.banScore = 0;

  if (options.socket) {
    this.socket = options.socket;
    this.host = this.socket.remoteAddress;
    this.port = this.socket.remotePort;
    assert(this.host);
    assert(this.port != null);
  } else if (options.seed) {
    options.seed = utils.parseHost(options.seed);
    options.seed.port = options.seed.port || network.port;
    this.socket = this.createSocket(options.seed.port, options.seed.host);
  }

  if (!this.socket)
    throw new Error('No socket');

  this._broadcast = {
    timeout: this.options.broadcastTimeout || 30000,
    interval: this.options.broadcastInterval || 3000,
    map: {}
  };

  this._request = {
    timeout: this.options.requestTimeout || 10000,
    skip: {},
    queue: {}
  };

  this._ping = {
    timer: null,
    interval: this.options.pingInterval || 30000
  };

  this.queue = {
    block: [],
    tx: []
  };

  Peer.uid.iaddn(1);

  this.id = Peer.uid.toString(10);

  this.setMaxListeners(10000);

  this._init();
}

utils.inherits(Peer, EventEmitter);

Peer.uid = new bn(0);

Peer.prototype._init = function init() {
  var self = this;

  if (!this.host)
    this.host = this.socket.remoteAddress || this.socket._host || null;

  if (!this.port)
    this.port = this.socket.remotePort || 0;

  this.socket.once('connect', function() {
    self.ts = utils.now();
    self.connected = true;
    if (!self.host)
      self.host = self.socket.remoteAddress;
    if (!self.port)
      self.port = self.socket.remotePort;
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
    bcoin.debug(err.stack + '');
    self.sendReject(null, 'malformed', 'error parsing message', 100);
    self._error(err);
    // Something is wrong here.
    // Ignore this peer.
    self.setMisbehavior(100);
  });

  this.challenge = utils.nonce();

  this._ping.timer = setInterval(function() {
    self._write(self.framer.ping({
      nonce: self.challenge
    }));
  }, this._ping.interval);

  this._req('verack', function(err, payload) {
    if (err) {
      self._error(err);
      self.destroy();
      return;
    }

    self.ack = true;
    self.emit('ack');
    self.ts = utils.now();

    self._write(self.framer.getAddr());

    if (self.options.headers) {
      if (self.version && self.version.version > 70012)
        self._write(self.framer.sendHeaders());
    }

    if (self.options.witness) {
      if (self.version && self.version.version >= 70012)
        self._write(self.framer.haveWitness());
    }

    if (self.chain.isFull())
      self.getMempool();
  });

  // Send hello
  this._write(this.framer.version({
    height: this.chain.height,
    relay: this.options.relay
  }));
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
  var socket, net;

  assert(port != null);
  assert(host);

  this.host = host;
  this.port = port;

  if (this._createSocket) {
    socket = this._createSocket(port, host);
  } else if (bcoin.isBrowser) {
    throw new Error('Please include a `createSocket` callback.');
  } else {
    net = require('n' + 'et');
    socket = net.connect(port, host);
  }

  bcoin.debug(
    'Connecting to %s:%d (priority=%s)',
    host, port, this.priority);

  socket.on('connect', function() {
    bcoin.debug(
      'Connected to %s:%d (priority=%s)',
      host, port, self.priority);
  });

  return socket;
};

/**
 * @typedef {EventEmitter} BroadcastPromise
 * @emits BroadcastPromise#ack
 * @emits BroadcastPromise#timeout
 * @emits BroadcastPromise#reject
 */

/**
 * Broadcast items to peer (transactions or blocks).
 * @param {TX|Block|TX[]|Block[]} items
 * @returns {BroadcastPromise[]}
 */

Peer.prototype.broadcast = function broadcast(items) {
  var self = this;
  var result = [];
  var payload = [];

  if (!this.relay)
    return;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  items.forEach(function(item) {
    var key = item.hash('hex');
    var old = this._broadcast.map[key];
    var type = item.type;
    var entry, packetType;

    if (typeof type === 'string')
      type = constants.inv[type.toUpperCase()];

    // INV does not set the witness
    // mask (only GETDATA does this).
    type &= ~constants.WITNESS_MASK;

    if (type === constants.inv.BLOCK)
      packetType = 'block';
    else if (type === constants.inv.TX)
      packetType = 'tx';
    else
      assert(false, 'Bad type.');

    if (self.filter && type === constants.inv.TX) {
      if (!item.isWatched(self.filter))
        return;
    }

    if (old) {
      clearTimeout(old.timer);
      clearInterval(old.interval);
    }

    // Auto-cleanup broadcast map after timeout
    entry = {
      e: new EventEmitter(),
      timeout: setTimeout(function() {
        entry.e.emit('timeout');
        clearInterval(entry.interval);
        delete self._broadcast.map[key];
      }, this._broadcast.timeout),

      // Retransmit
      interval: setInterval(function() {
        self._write(entry.inv);
      }, this._broadcast.interval),

      inv: this.framer.inv([{
        type: type,
        hash: item.hash()
      }]),

      packetType: packetType,
      type: type,
      hash: item.hash(),
      value: item.renderNormal(),
      witnessValue: item.renderWitness()
    };

    this._broadcast.map[key] = entry;

    result.push(entry.e);

    payload.push({
      type: entry.type,
      hash: entry.hash
    });
  }, this);

  this._write(this.framer.inv(payload));

  return result;
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.pool.options.spv)
    return;

  if (this.ack) {
    this._write(this.framer.filterLoad({
      filter: this.bloom.toBuffer(),
      n: this.bloom.n,
      tweak: this.bloom.tweak,
      update: constants.filterFlags.NONE
    }));
  }
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

  // Clean-up timeouts
  Object.keys(this._broadcast.map).forEach(function(key) {
    clearTimeout(this._broadcast.map[key].timer);
    clearInterval(this._broadcast.map[key].interval);
  }, this);

  clearInterval(this._ping.timer);
  this._ping.timer = null;

  Object.keys(this._request).forEach(function(cmd) {
    var queue = this._request[cmd];
    var i;

    for (i = 0; i < queue.length; i++)
      clearTimeout(queue[i].timer);
  }, this);
};

/**
 * Write data to the peer's socket.
 * @private
 * @param {Buffer} chunk
 */

Peer.prototype._write = function write(chunk) {
  if (this.destroyed)
    return;

  this.socket.write(chunk);
};

/**
 * Emit an error and destroy the peer.
 * @private
 * @param {String|Error} err
 */

Peer.prototype._error = function error(err) {
  if (this.destroyed)
    return;

  if (typeof err === 'string')
    err = new Error(err);

  err.message += ' (' + this.host + ':' + this.port + ')';

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

Peer.prototype._req = function _req(cmd, cb) {
  var self = this;
  var entry;

  if (this.destroyed)
    return utils.asyncify(cb)(new Error('Destroyed, sorry'));

  entry = {
    cmd: cmd,
    cb: cb,
    ontimeout: function() {
      var queue = self._request.queue[cmd];
      var i;

      if (!queue)
        return;

      i = queue.indexOf(entry);

      if (i !== -1) {
        queue.splice(i, 1);
        cb(new Error('Timed out: ' + cmd), null);
      }
    },
    timer: null
  };

  entry.timer = setTimeout(entry.ontimeout, this._request.timeout);

  if (!this._request.queue[cmd])
    this._request.queue[cmd] = [];

  this._request.queue[cmd].push(entry);

  return entry;
};

/**
 * Fulfill awaiting requests created with {@link Peer#_req}.
 * @private
 * @param {String} cmd - Packet name.
 * @param {Object} payload
 */

Peer.prototype._res = function _res(cmd, payload) {
  var queue = this._request.queue[cmd];
  var entry, res;

  if (!queue)
    return false;

  entry = queue[0];

  if (!entry)
    return false;

  res = entry.cb(null, payload, cmd);

  if (res !== this._request.skip) {
    queue.shift();
    if (queue.length === 0)
      delete this._request.queue[cmd];
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
  this._write(this.framer.getData(items));
};

Peer.prototype._onPacket = function onPacket(packet) {
  var cmd = packet.cmd;
  var payload = packet.payload;

  if (this.lastBlock && cmd !== 'tx')
    this._emitMerkle();

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
      payload = bcoin.compactblock(payload);
      this._emit(cmd, payload);
      break;
    case 'merkleblock':
      payload = bcoin.merkleblock(payload);
      this.lastBlock = payload;
      break;
    case 'tx':
      payload = bcoin.tx(payload, this.lastBlock);
      if (this.lastBlock) {
        if (payload.block) {
          this.lastBlock.txs.push(payload);
          break;
        }
        this._emitMerkle();
      }
      this._emit(cmd, payload);
      break;
    case 'sendheaders':
      this.sendHeaders = true;
      this._res(cmd, payload);
      break;
    case 'havewitness':
      this.haveWitness = true;
      this._res(cmd, payload);
      break;
    case 'verack':
      this._emit(cmd, payload);
      break;
    default:
      bcoin.debug('Unknown packet: %s', cmd);
      this._emit(cmd, payload);
      break;
  }
};

Peer.prototype._emit = function _emit(cmd, payload) {
  if (this._res(cmd, payload))
    return;

  this.emit(cmd, payload);
};

Peer.prototype._emitMerkle = function _emitMerkle() {
  if (this.lastBlock)
    this._emit('merkleblock', this.lastBlock);
  this.lastBlock = null;
};

Peer.prototype._handleFilterLoad = function _handleFilterLoad(payload) {
  this.filter = new bcoin.bloom(
    payload.filter,
    payload.n,
    payload.tweak,
    payload.update
  );

  if (!this.filter.isWithinConstraints()) {
    delete this.filter;
    this.setMisbehavior(100);
    return;
  }

  this.relay = true;
};

Peer.prototype._handleFilterAdd = function _handleFilterAdd(payload) {
  if (this.filter)
    this.filter.add(payload.data);
  this.relay = true;
};

Peer.prototype._handleFilterClear = function _handleFilterClear(payload) {
  if (this.filter)
    this.filter.reset();
  this.relay = true;
};

Peer.prototype._handleUTXOs = function _handleUTXOs(payload) {
  payload.coins = payload.coins(function(coin) {
    return new bcoin.coin(coin);
  });
  bcoin.debug('Received %d utxos from %s.', payload.coins.length, this.host);
  this._emit('utxos', payload);
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

Peer.prototype._getUTXOs = function getUTXOs(utxos, callback) {
  var index = 0;
  var i, prevout, coin;

  this._req('utxos', function(err, payload) {
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

  this._write(this.framer.getUTXOs({
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

  if (this.pool.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

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
    return;

  utils.forEachSerial(payload.prevout, function(prevout, next, i) {
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
      self.emit('error', err);

    self._write(self.framer.UTXOs({
      height: self.chain.height,
      tip: self.chain.tip.hash,
      hits: hits,
      coins: coins
    }));
  });
};

Peer.prototype._handleGetHeaders = function _handleGetHeaders(payload) {
  var self = this;
  var headers = [];

  if (this.pool.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

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

  function done(err) {
    if (err)
      return self.emit('error', err);

    self._write(self.framer.headers(headers));
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

  if (this.pool.options.selfish)
    return;

  if (this.chain.db.options.spv)
    return;

  if (this.chain.db.options.prune)
    return;

  function done(err) {
    if (err)
      return self.emit('error', err);
    self._write(self.framer.inv(blocks));
  }

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

Peer.prototype._handleVersion = function handleVersion(payload) {
  if (payload.version < constants.MIN_VERSION) {
    this._error('Peer doesn\'t support required protocol version.');
    this.setMisbehavior(100);
    return;
  }

  if (this.options.headers) {
    if (payload.version < 31800) {
      this._error('Peer doesn\'t support getheaders.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.network) {
    if (!payload.network) {
      this._error('Peer does not support network services.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.spv) {
    if (!payload.bloom && payload.version < 70011) {
      this._error('Peer does not support bip37.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.witness) {
    if (!payload.witness) {
      this._req('havewitness', function(err) {
        if (err) {
          self._error('Peer does not support segregated witness.');
          self.setMisbehavior(100);
          return;
        }
      });
    }
  }

  if (payload.witness)
    this.haveWitness = true;

  if (payload.relay === false)
    this.relay = false;

  // ACK
  this._write(this.framer.verack());
  this.version = payload;
  this.emit('version', payload);
};

Peer.prototype._handleMempool = function _handleMempool() {
  var self = this;
  var items = [];
  var i;

  if (!this.mempool)
    return;

  if (this.pool.options.selfish)
    return;

  this.mempool.getSnapshot(function(err, hashes) {
    if (err)
      return self.emit('error', err);

    for (i = 0; i < hashes.length; i++)
      items.push({ type: constants.inv.TX, hash: hashes[i] });

    bcoin.debug('Sending mempool snapshot to %s.', self.host);

    self._write(self.framer.inv(items));
  });
};

Peer.prototype._handleGetData = function handleGetData(items) {
  var self = this;
  var check = [];
  var notfound = [];
  var hash, entry, isWitness, value, i, item;

  if (items.length > 50000)
    return this._error('message getdata size() = %d', items.length);

  for (i = 0; i < items.length; i++) {
    item = items[i];

    hash = utils.toHex(item.hash);
    entry = this._broadcast.map[hash];
    isWitness = item.type & constants.WITNESS_MASK;
    value = null;

    if (!entry) {
      check.push(item);
      continue;
    }

    if ((item.type & ~constants.WITNESS_MASK) !== entry.type) {
      bcoin.debug(
        'Peer %s requested an existing item with the wrong type.',
        this.host);
      continue;
    }

    bcoin.debug(
      'Peer %s requested %s:%s as a %s packet.',
      this.host,
      entry.packetType,
      utils.revHex(utils.toHex(entry.hash)),
      isWitness ? 'witness' : 'normal');

    if (isWitness)
      this._write(this.framer.packet(entry.packetType, entry.witnessValue));
    else
      this._write(this.framer.packet(entry.packetType, entry.value));

    entry.e.emit('request');
  }

  if (this.pool.options.selfish)
    return;

  utils.forEachSerial(check, function(item, next) {
    var isWitness = item.type & constants.WITNESS_MASK;
    var type = item.type & ~constants.WITNESS_MASK;
    var hash = utils.toHex(item.hash);
    var i, tx, data;

    if (type === constants.inv.TX) {
      if (!self.mempool) {
        notfound.push({ type: constants.inv.TX, hash: hash });
        return next();
      }
      return self.mempool.getTX(hash, function(err, tx) {
        if (err)
          return next(err);

        if (!tx) {
          notfound.push({ type: constants.inv.TX, hash: hash });
          return next();
        }

        if (isWitness)
          data = tx.renderWitness();
        else
          data = tx.renderNormal();

        self._write(self.framer.packet('tx', data));

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
        return;
      }
      return self.chain.db.getBlock(hash, function(err, block) {
        if (err)
          return next(err);

        if (!block) {
          notfound.push({ type: constants.inv.BLOCK, hash: hash });
          return next();
        }

        if (isWitness)
          data = block.renderWitness();
        else
          data = block.renderNormal();

        self._write(self.framer.packet('block', data));

        if (hash === self.hashContinue) {
          self._write(self.framer.inv([{
            type: constants.inv.BLOCK,
            hash: self.chain.tip.hash
          }]));
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
        return;
      }
      return self.chain.db.getBlock(hash, function(err, block) {
        if (err)
          return next(err);

        if (!block) {
          notfound.push({ type: constants.inv.BLOCK, hash: hash });
          return next();
        }

        block = block.toMerkle(self.filter);

        self._write(self.framer.merkleBlock(block));

        for (i = 0; i < block.txs.length; i++) {
          tx = block.txs[i];

          if (isWitness)
            tx = tx.renderWitness();
          else
            tx = tx.renderNormal();

          self._write(self.framer.packet('tx', tx));
        }

        if (hash === self.hashContinue) {
          self._write(self.framer.inv([{
            type: constants.inv.BLOCK,
            hash: self.chain.tip.hash
          }]));
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
      'Served %d items to %s with getdata (notfound=%d).',
      items.length - notfound.length,
      self.host,
      notfound.length);

    if (notfound.length > 0)
      self._write(self.framer.notFound(notfound));
  });
};

Peer.prototype._handleAddr = function handleAddr(addrs) {
  var now = utils.now();
  var i, addr, ts, host;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];

    ts = addr.ts;
    host = addr.ipv4 !== '0.0.0.0'
      ? addr.ipv4
      : addr.ipv6;

    if (ts <= 100000000 || ts > now + 10 * 60)
      ts = now - 5 * 24 * 60 * 60;

    this.emit('addr', {
      ts: ts,
      services: addr.services,
      host: host,
      port: addr.port || network.port,
      network: addr.network,
      bloom: addr.bloom,
      getutxo: addr.getutxo,
      witness: addr.witness,
      headers: addr.version >= 31800,
      spv: addr.bloom && addr.version >= 70011
    });
  }

  bcoin.debug(
    'Recieved %d peers (seeds=%d, peers=%d).',
    addrs.length,
    this.pool.seeds.length,
    this.pool.peers.all.length);
};

Peer.prototype._handlePing = function handlePing(data) {
  this._write(this.framer.pong({
    nonce: data.nonce
  }));
  this.emit('ping', data);
};

Peer.prototype._handlePong = function handlePong(data) {
  if (!this.challenge || this.challenge.cmp(data.nonce) !== 0)
    return this.emit('pong', false);

  this.lastPong = utils.now();

  return this.emit('pong', true);
};

Peer.prototype._handleGetAddr = function handleGetAddr() {
  var hosts = {};
  var peers = this.pool.peers.all;
  var items = [];
  var i, peer, ip, version;

  if (this.pool.options.selfish)
    return;

  for (i = 0; i < peers.length; i++) {
    peer = peers[i];

    if (!peer.socket || !peer.socket.remoteAddress)
      continue;

    ip = peer.socket.remoteAddress;
    version = utils.isIP(ip);

    if (!version)
      continue;

    if (hosts[ip])
      continue;

    hosts[ip] = true;

    items.push({
      ts: peer.ts,
      services: peer.version ? peer.version.services : null,
      ipv4: version === 4 ? ip : null,
      ipv6: version === 6 ? ip : null,
      port: peer.socket.remotePort || network.port
    });
  }

  return this._write(this.framer.addr(peers));
};

Peer.prototype._handleInv = function handleInv(items) {
  var blocks = [];
  var txs = [];
  var item, i;

  this.emit('inv', items);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    if (item.type === constants.inv.TX)
      txs.push(item.hash);
    else if (item.type === constants.inv.BLOCK)
      blocks.push(item.hash);
  }

  if (blocks.length > 0)
    this.emit('blocks', blocks);

  if (txs.length > 0)
    this.emit('txs', txs);
};

Peer.prototype._handleHeaders = function handleHeaders(headers) {
  headers = headers.map(function(header) {
    return new bcoin.headers(header);
  });

  this.emit('headers', headers);
};

Peer.prototype._handleReject = function handleReject(payload) {
  var hash, entry;

  this.emit('reject', payload);

  if (!payload.data)
    return;

  hash = utils.toHex(payload.data);
  entry = this._broadcast.map[hash];

  if (!entry)
    return;

  entry.e.emit('reject', payload);
};

Peer.prototype._handleAlert = function handleAlert(details) {
  var hash = utils.dsha256(details.payload);
  var signature = details.signature;

  if (!bcoin.ec.verify(hash, signature, network.alertKey)) {
    bcoin.debug('Peer %s sent a phony alert packet.', this.host);
    // Let's look at it because why not?
    bcoin.debug(details);
    this.setMisbehavior(100);
    return;
  }

  this.emit('alert', details);
};

/**
 * Send `getheaders` to peer. Note that unlike
 * `getblocks`, `getheaders` can have a null locator.
 * @param {Hash[]?} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.getHeaders = function getHeaders(locator, stop) {
  bcoin.debug(
    'Requesting headers packet from %s with getheaders',
    this.host);

  bcoin.debug('Height: %s, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : null,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this._write(this.framer.getHeaders({ locator: locator, stop: stop }));
};

/**
 * Send `getblocks` to peer.
 * @param {Hash[]} locator - Chain locator.
 * @param {Hash?} stop - Hash to stop at.
 */

Peer.prototype.getBlocks = function getBlocks(locator, stop) {
  bcoin.debug(
    'Requesting inv packet from %s with getblocks',
    this.host);

  bcoin.debug('Height: %s, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : null,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this._write(this.framer.getBlocks({ locator: locator, stop: stop }));
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.getMempool = function getMempool() {
  bcoin.debug(
    'Requesting inv packet from %s with mempool',
    this.host);

  this._write(this.framer.mempool());
};

/**
 * Send `reject` to peer.
 * @param {Object} details - See {@link Framer.reject}.
 */

Peer.prototype.reject = function reject(details) {
  bcoin.debug(
    'Sending reject packet to %s',
    this.host);

  this._write(this.framer.reject(details));
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

return Peer;
};
