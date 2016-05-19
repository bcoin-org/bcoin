/*!
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var utils = require('./utils');
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
  this.chain = this.pool.chain;
  this.mempool = this.pool.mempool;
  this.bloom = this.pool.bloom;
  this.network = this.chain.network;
  this.parser = new bcoin.protocol.parser(this.chain.options);
  this.framer = new bcoin.protocol.framer(this.chain.options);
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
  this.localNonce = utils.nonce();
  this.filterRate = -1;

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
    options.seed.port = options.seed.port || this.network.port;
    this.socket = this.createSocket(options.seed.port, options.seed.host);
  }

  if (!this.socket)
    throw new Error('No socket');

  this.requests = {
    timeout: this.options.requestTimeout || 10000,
    skip: {},
    map: {}
  };

  this.pings = {
    timer: null,
    interval: this.options.pingInterval || 30000
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
  });

  this.challenge = utils.nonce();

  this.pings.timer = setInterval(function() {
    self.write(self.framer.ping({
      nonce: self.challenge
    }));
  }, this.pings.interval);

  this.request('verack', function(err, payload) {
    if (err) {
      self._error(err);
      self.destroy();
      return;
    }

    self.ack = true;
    self.emit('ack');
    self.ts = utils.now();

    if (self.options.headers) {
      if (self.version && self.version.version > 70012)
        self.write(self.framer.sendHeaders());
    }

    if (self.options.witness) {
      if (self.version && self.version.version >= 70012)
        self.write(self.framer.haveWitness());
    }

    self.write(self.framer.getAddr());

    self.sendInv(self.pool.inv.list);

    if (self.pool.options.filterRate != null) {
      self.write(self.framer.feeFilter({
        rate: self.pool.options.filterRate
      }));
    }

    if (self.chain.isFull())
      self.getMempool();
  });

  // Send hello
  this.write(this.framer.version({
    height: this.chain.height,
    relay: this.options.relay,
    nonce: this.localNonce
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
 * Broadcast items to peer (transactions or blocks).
 * @param {BroadcastEntry[]} items
 */

Peer.prototype.sendInv = function sendInv(items) {
  if (this.destroyed)
    return;

  if (!this.relay)
    return;

  if (!items)
    return;

  if (!Array.isArray(items))
    items = [items];

  if (items.length === 0)
    return;

  if (items.length > 50000)
    items = items.slice(0, 50000);

  if (this.filter)
    items = items.map(this.isWatched, this);

  this.write(this.framer.inv(items));
};

/**
 * Test whether an is being watched by the peer.
 * @param {BroadcastItem|TX} item
 * @returns {Boolean}
 */

Peer.prototype.isWatched = function isWatched(item) {
  if (!this.filter)
    return true;

  if (!item)
    return true;

  if (item instanceof bcoin.tx)
    return item.isWatched(this.filter);

  if (!(item.msg instanceof bcoin.tx))
    return true;

  return item.msg.isWatched(this.filter);
};

/**
 * Send `filterload` to update the local bloom filter.
 */

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.pool.options.spv)
    return;

  if (this.ack) {
    this.write(this.framer.filterLoad({
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

  clearInterval(this.pings.timer);
  this.pings.timer = null;

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
      this.lastBlock = payload;
      break;
    case 'tx':
      payload = new bcoin.tx(payload);
      if (this.lastBlock) {
        if (this.lastBlock.hasTX(payload)) {
          this.lastBlock.addTX(payload);
          break;
        }
        this._flushMerkle();
      }
      this.fire(cmd, payload);
      break;
    case 'sendheaders':
      this.sendHeaders = true;
      this.response(cmd, payload);
      break;
    case 'havewitness':
      this.haveWitness = true;
      this.response(cmd, payload);
      break;
    case 'verack':
      this.fire(cmd, payload);
      break;
    case 'notfound':
      this.fire(cmd, payload);
      break;
    default:
      bcoin.debug('Unknown packet: %s', cmd);
      this.fire(cmd, payload);
      break;
  }
};

Peer.prototype.fire = function fire(cmd, payload) {
  if (this.response(cmd, payload))
    return;

  this.emit(cmd, payload);
};

Peer.prototype._flushMerkle = function _flushMerkle() {
  if (this.lastBlock)
    this.fire('merkleblock', this.lastBlock);
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
  if (payload.data.length > constants.script.MAX_PUSH) {
    this.setMisbehavior(100);
    return;
  }

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
  this.fire('utxos', payload);
};

Peer.prototype._handleFeeFilter = function _handleFeeFilter(payload) {
  if (!(payload.rate >= 0 && payload.rate <= constants.MAX_MONEY)) {
    this.setMisbehavior(100);
    return;
  }

  this.filterRate = payload.rate;

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

Peer.prototype._getUTXOs = function getUTXOs(utxos, callback) {
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

    self.write(self.framer.UTXOs({
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

    self.write(self.framer.headers(headers));
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
    self.sendInv(blocks);
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
  var version = payload.version;
  var services = payload.services;

  if (payload.nonce.cmp(this.localNonce) === 0) {
    this._error('We connected to ourself. Oops.');
    this.setMisbehavior(100);
    return;
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

    self.sendInv(items);
  });
};

Peer.prototype._handleGetData = function handleGetData(items) {
  var self = this;
  var check = [];
  var notfound = [];
  var i, item, entry, witness;

  if (items.length > 50000)
    return this._error('message getdata size() = %d', items.length);

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
        'Peer %s requested an existing item with the wrong type.',
        this.host);
      continue;
    }

    bcoin.debug(
      'Peer %s requested %s:%s as a %s packet.',
      this.host,
      entry.packetType,
      utils.revHex(entry.key),
      witness ? 'witness' : 'normal');

    entry.sendTo(peer, witness);
  }

  if (this.pool.options.selfish)
    return;

  utils.forEachSerial(check, function(item, next) {
    var witness = item.type & constants.WITNESS_MASK;
    var type = (item.type & ~constants.WITNESS_MASK) !== 0;
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
        if (self.filterRate !== -1) {
          if (bcoin.tx.getRate(entry.size, entry.fees) < self.filterRate)
            return next();
        }

        if (witness)
          data = tx.renderWitness();
        else
          data = tx.renderNormal();

        self.write(self.framer.packet('tx', data));

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

        if (witness)
          data = block.renderWitness();
        else
          data = block.renderNormal();

        self.write(self.framer.packet('block', data));

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

        self.write(self.framer.merkleBlock(block));

        for (i = 0; i < block.txs.length; i++) {
          tx = block.txs[i];

          if (witness)
            tx = tx.renderWitness();
          else
            tx = tx.renderNormal();

          self.write(self.framer.packet('tx', tx));
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
      'Served %d items to %s with getdata (notfound=%d).',
      items.length - notfound.length,
      self.host,
      notfound.length);

    if (notfound.length > 0)
      self.write(self.framer.notFound(notfound));
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
      version: addr.version,
      ts: ts,
      services: addr.services,
      host: host,
      port: addr.port || this.network.port
    });
  }

  bcoin.debug(
    'Recieved %d peers (seeds=%d, peers=%d).',
    addrs.length,
    this.pool.seeds.length,
    this.pool.peers.all.length);
};

Peer.prototype._handlePing = function handlePing(data) {
  this.write(this.framer.pong({
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
  var items = [];
  var ts = utils.now() - (process.uptime() | 0);
  var i, seed, version, peer;

  if (this.pool.options.selfish)
    return;

  for (i = 0; i < this.pool.seeds.length; i++) {
    seed = utils.parseHost(this.pool.seeds[i]);
    seed = this.pool.getPeer(seed) || seed;
    version = utils.isIP(seed.host);

    if (!version)
      continue;

    if (hosts[seed.host])
      continue;

    hosts[seed.host] = true;

    items.push({
      network: this.network,
      ts: seed.ts || ts,
      services: seed.version ? seed.version.services : null,
      ipv4: version === 4 ? seed.host : null,
      ipv6: version === 6 ? seed.host : null,
      port: seed.port || this.network.port
    });

    if (items.length === 1000)
      break;
  }

  return this.write(this.framer.addr(items));
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

  hash = payload.data;
  entry = this.pool.inv.map[hash];

  if (!entry)
    return;

  entry.reject(this);
};

Peer.prototype._handleAlert = function handleAlert(details) {
  var hash = utils.dsha256(details.payload);
  var signature = details.signature;

  if (!bcoin.ec.verify(hash, signature, this.network.alertKey)) {
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
    'Requesting inv packet from %s with getblocks',
    this.host);

  bcoin.debug('Height: %s, Hash: %s, Stop: %s',
    locator && locator.length ? this.chain._getCachedHeight(locator[0]) : null,
    locator && locator.length ? utils.revHex(locator[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this.write(this.framer.getBlocks({ locator: locator, stop: stop }));
};

/**
 * Send `mempool` to peer.
 */

Peer.prototype.getMempool = function getMempool() {
  bcoin.debug(
    'Requesting inv packet from %s with mempool',
    this.host);

  this.write(this.framer.mempool());
};

/**
 * Send `reject` to peer.
 * @param {Object} details - See {@link Framer.reject}.
 */

Peer.prototype.reject = function reject(details) {
  bcoin.debug(
    'Sending reject packet to %s',
    this.host);

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
