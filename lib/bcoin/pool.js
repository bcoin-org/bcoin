/*!
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var VerifyError = bcoin.errors.VerifyError;

/**
 * A pool of peers for handling all network activity.
 * @exports Pool
 * @constructor
 * @param {Object} options
 * @param {Chain} chain
 * @param {Mempool?} mempool
 * @param {Number?} [size=8] - Maximum number of peers.
 * @param {Boolean?} options.spv - Do an SPV sync.
 * @param {Boolean?} options.relay - Whether to ask
 * for relayed transactions.
 * @param {Boolean?} options.headers - Whether
 * to use `getheaders` for sync.
 * @param {Number?} [loadTimeout=120000] - Sync timeout before
 * finding a new loader peer.
 * @param {Number?} [loadInterval=20000] - Timeout before attempting to
 * send another getblocks request.
 * @param {Number?} [requestTimeout=120000] - Timeout for in-flight blocks.
 * @param {Number?} [invTimeout=60000] - Timeout for broadcasted objects.
 * @param {Boolean?} listen - Whether to spin up a server socket
 * and listen for peers.
 * @param {Boolean?} selfish - A selfish pool. Will not serve blocks,
 * headers, hashes, utxos, or transactions to peers.
 * @param {Boolean?} broadcast - Whether to automatically broadcast
 * transactions accepted to our mempool.
 * @param {Boolean?} witness - Request witness blocks and transactions.
 * Only deal with witness peers.
 * @param {Boolean} [discoverPeers=true] Automatically discover new peers.
 * @param {(String[]|Seed[])?} seeds
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
 * @emits Pool#leech
 */

function Pool(options) {
  var self = this;
  var seeds;

  if (!(this instanceof Pool))
    return new Pool(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.chain = options.chain;
  this.mempool = options.mempool;

  assert(this.chain, 'Pool requires a blockchain.');

  this.network = this.chain.network;

  if (options.relay == null) {
    if (options.spv)
      options.relay = false;
    else
      options.relay = true;
  }

  if (options.headers == null) {
    if (options.spv)
      options.headers = true;
    else
      options.headers = false;
  }

  seeds = (options.seeds || this.network.seeds).slice();

  if (process.env.BCOIN_SEED)
    seeds.unshift(process.env.BCOIN_SEED);

  this.originalSeeds = seeds.map(utils.parseHost);
  this.seeds = [];
  this.hosts = {};
  this.setSeeds([]);

  this.server = null;
  this.destroyed = false;
  this.loaded = false;
  this.size = options.size || 8;
  this.maxLeeches = options.maxLeeches || 8;
  this.connected = false;
  this.uid = 0;

  this.syncing = false;
  this.synced = false;
  this._scheduled = false;

  this.load = {
    timeout: options.loadTimeout || 120000,
    interval: options.loadInterval || 20000
  };

  this.requestTimeout = options.requestTimeout || 20 * 60000;

  this.watchMap = {};

  this.bloom = new bcoin.bloom(
    8 * 1024,
    10,
    (Math.random() * 0xffffffff) | 0
  );

  this.peers = {
    // Peers that are loading blocks themselves
    regular: [],
    // Peers that are still connecting
    pending: [],
    // Peers that connected to us
    leeches: [],
    // Peers that are loading block ids
    load: null,
    // All peers
    all: [],
    // Misbehaving hosts
    misbehaving: {},
    // Map of hosts
    map: {}
  };

  this.block = {
    versionHeight: 0,
    bestHash: null,
    type: !options.spv
      ? constants.inv.BLOCK
      : constants.inv.FILTERED_BLOCK
  };

  this.tx = {
    state: {},
    count: 0,
    type: constants.inv.TX
  };

  if (this.options.witness) {
    this.block.type |= constants.WITNESS_MASK;
    this.tx.type |= constants.WITNESS_MASK;
  }

  this.request = {
    map: {},
    active: 0,
    activeBlocks: 0,
    activeTX: 0
  };

  this.validate = {
    // 5 days scan delta for obtaining TXs
    delta: 5 * 24 * 3600,
    // getTX map
    map: {}
  };

  // Currently broadcasted objects
  this.inv = {
    list: [],
    map: {},
    timeout: options.invTimeout || 60000,
    interval: options.invInterval || 3000
  };

  function done(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');

    self._init();
  }

  if (this.mempool)
    this.mempool.open(done);
  else
    this.chain.open(done);
}

utils.inherits(Pool, EventEmitter);

/**
 * Open the pool, wait for the chain to load.
 * @param {Function} callback
 */

Pool.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

/**
 * Connect to the network.
 */

Pool.prototype.connect = function connect() {
  var self = this;

  assert(this.loaded, 'Pool is not loaded.');

  if (this.connected)
    return;

  if (this.options.broadcast) {
    if (this.mempool) {
      this.mempool.on('tx', function(tx) {
        self.announce(tx);
      });
    }

    // Normally we would also broadcast
    // competing chains, but we want to
    // avoid getting banned if an evil
    // miner sends us an invalid competing
    // chain that we can't connect and
    // verify yet.
    if (!this.options.spv) {
      this.chain.on('block', function(block) {
        if (!self.synced)
          return;
        self.announce(block);
      });
    }
  }

  if (this.originalSeeds.length > 0) {
    this._addLoader();

    for (i = 0; i < this.size; i++)
      this._addPeer();

    this.connected = true;
  }
};

Pool.prototype._init = function _init() {
  var self = this;
  var i;

  this.chain.on('block', function(block, entry, peer) {
    // Emit merkle txs after the fact
    if (self.options.spv) {
      utils.forEachSerial(block.txs, function(tx, next) {
        self._handleTX(tx, peer, next);
      }, function(err) {
        if (err)
          return self.emit('error', err);
        self.emit('block', block, peer);
      });
    } else {
      self.emit('block', block, peer);
    }
  });

  this.chain.on('fork', function(block, data, peer) {
    self.emit('fork', data, peer);
  });

  this.chain.on('invalid', function(block, data, peer) {
    self.emit('invalid', data, peer);
  });

  this.chain.on('exists', function(block, data, peer) {
    self.emit('exists', data, peer);
  });

  this.chain.on('orphan', function(block, data, peer) {
    self.emit('orphan', data, peer);
  });

  this.chain.on('full', function() {
    self._stopTimer();
    self._stopInterval();
    if (!self.synced)
      self.getMempool();
    self.synced = true;
    self.emit('full');
    bcoin.debug('Chain is fully synced (height=%d).', self.chain.height);
  });
};

/**
 * Send `getblocks` to peer after building locator.
 * @param {Peer} peer
 * @param {Hash} top - Top hash to build chain locator from.
 * @param {Hash?} stop
 * @param {Function} callback
 */

Pool.prototype.getBlocks = function getBlocks(peer, top, stop, callback) {
  callback = utils.ensure(callback);

  this.chain.getLocator(top, function(err, locator) {
    if (err)
      return callback(err);

    peer.getBlocks(locator, stop);

    callback();
  });
};

/**
 * Send `getblocks` to peer after building
 * locator and resolving orphan root.
 * @param {Peer} peer
 * @param {Hash} top - Top hash to build chain locator from.
 * @param {Hash} orphan - Orphan hash to resolve.
 * @param {Function} callback
 */

Pool.prototype.resolveOrphan = function resolveOrphan(peer, top, orphan, callback) {
  var self = this;

  callback = utils.ensure(callback);

  assert(orphan);

  this.chain.getLocator(top, function(err, locator) {
    if (err)
      return callback(err);

    orphan = self.chain.getOrphanRoot(orphan);

    // Was probably resolved.
    if (!orphan) {
      bcoin.debug('Orphan root was already resolved.');
      return callback();
    }

    peer.getBlocks(locator, orphan.root);

    callback();
  });
};

/**
 * Send `getheaders` to peer after building locator.
 * @param {Peer} peer
 * @param {Hash} top - Top hash to build chain locator from.
 * @param {Hash?} stop
 * @param {Function} callback
 */

Pool.prototype.getHeaders = function getHeaders(peer, top, stop, callback) {
  callback = utils.ensure(callback);

  this.chain.getLocator(top, function(err, locator) {
    if (err)
      return callback(err);

    peer.getHeaders(locator, stop);

    callback();
  });
};

/**
 * Start listening on a server socket.
 * @param {Function} callback
 */

Pool.prototype.listen = function listen(callback) {
  var self = this;
  var net;

  callback = utils.ensure(callback);

  if (bcoin.isBrowser)
    return utils.nextTick(callback);

  net = require('n' + 'et');

  assert(!this.server, 'Server already listening.');

  this.server = new net.Server();

  this.server.on('connection', function(socket) {
    if (self.peers.leeches.length >= self.maxLeeches) {
      socket.destroy();
      return;
    }
    self._addLeech(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    bcoin.debug(
      'Bitcoin server listening on %s (port=%d)',
      data.address, data.port);
  });

  this.server.listen(this.network.port, '0.0.0.0', callback);
};

/**
 * Stop listening on server socket.
 * @param {Function} callback
 */

Pool.prototype.unlisten = function unlisten(callback) {
  callback = utils.ensure(callback);

  if (bcoin.isBrowser)
    return utils.nextTick(callback);

  if (!this.server)
    return utils.nextTick(callback);

  this.server.close(callback);
  this.server = null;
};

Pool.prototype._startTimer = function _startTimer() {
  var self = this;

  this._stopTimer();

  function destroy() {
    if (!self.syncing)
      return;

    // Chain is full and up-to-date
    if (self.chain.isFull())
      return;

    if (self.peers.load) {
      self.peers.load.destroy();
      bcoin.debug('Timer ran out. Finding new loader peer.');
    }
  }

  this._timer = setTimeout(destroy, this.load.timeout);
};

Pool.prototype._stopTimer = function _stopTimer() {
  if (!this._timer)
    return;

  clearTimeout(this._timer);
  delete this._timer;
};

Pool.prototype._startInterval = function _startInterval() {
  var self = this;

  this._stopInterval();

  function load() {
    if (!self.syncing)
      return;

    // Chain is full and up-to-date
    if (self.chain.isFull())
      return;

    if (self.chain.isBusy())
      return self._startTimer();

    bcoin.debug('Stall recovery: loading again.');

    // self._load();
  }

  this._interval = setInterval(load, this.load.interval);
};

Pool.prototype._stopInterval = function _stopInterval() {
  if (!this._interval)
    return;

  clearInterval(this._interval);
  delete this._interval;
};

Pool.prototype._addLoader = function _addLoader() {
  var self = this;
  var peer;

  if (this.destroyed)
    return;

  if (this.peers.load != null)
    return;

  peer = this._createPeer({
    seed: this.getSeed(true),
    priority: true,
    network: true,
    spv: this.options.spv,
    witness: this.options.witness
  });

  bcoin.debug('Added loader peer: %s', peer.host);

  this.peers.load = peer;
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  peer.once('close', function() {
    self._stopInterval();
    self._stopTimer();
    self._removePeer(peer);
    if (self.destroyed)
      return;
    self._addLoader();
  });

  peer.once('ack', function() {
    peer.updateWatch();
    if (!self.syncing)
      return;
    self._load();
  });

  peer.on('merkleblock', function(block) {
    if (!self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err) {
      if (err)
        return self.emit('error', err);

      self._startInterval();
      self._startTimer();
    });
  });

  peer.on('block', function(block) {
    if (self.options.spv)
      return;

    if (!self.syncing)
      return;

    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err) {
      if (err)
        return self.emit('error', err);

      self._startInterval();
      self._startTimer();
    });
  });

  if (self.options.headers) {
    peer.on('blocks', function(hashes) {
      if (!self.syncing)
        return;

      self._handleInv(hashes, peer, function(err) {
        if (err)
          self.emit('error', err);
      });
    });

    peer.on('headers', function(headers) {
      if (!self.syncing)
        return;

      self._handleHeaders(headers, peer, function(err) {
        if (err)
          self.emit('error', err);
      });
    });
  } else {
    peer.on('blocks', function(hashes) {
      if (!self.syncing)
        return;

      self._handleBlocks(hashes, peer, function(err) {
        if (err)
          self.emit('error', err);
      });
    });
  }
};

/**
 * Start the blockchain sync.
 */

Pool.prototype.startSync = function startSync() {
  this.syncing = true;

  this._startInterval();
  this._startTimer();

  this.connect();

  if (!this.peers.load) {
    this._addLoader();
    return;
  }

  if (this.peers.load.ack)
    this._load();
};

/**
 * Stop the blockchain sync.
 */

Pool.prototype.stopSync = function stopSync() {
  if (!this.syncing)
    return;

  this.syncing = false;

  if (!this.loaded)
    return;

  this._stopInterval();
  this._stopTimer();
};

Pool.prototype._handleHeaders = function _handleHeaders(headers, peer, callback) {
  var self = this;
  var ret = {};
  var last;

  assert(this.options.headers);

  callback = utils.ensure(callback);

  if (headers.length === 0)
    return callback();

  bcoin.debug(
    'Recieved %s headers from %s',
    headers.length,
    peer.host);

  if (headers.length > 2000) {
    peer.setMisbehavior(100);
    return callback();
  }

  this.emit('headers', headers);

  // Reset interval to avoid calling getheaders unnecessarily
  this._startInterval();

  utils.forEachSerial(headers, function(header, next) {
    var hash = header.hash('hex');

    if (last && header.prevBlock !== last)
      return next(new Error('Bad header chain.'));

    if (!header.verify(ret))
      return next(new VerifyError(header, 'invalid', ret.reason, ret.score));

    last = hash;

    self.getData(peer, self.block.type, hash, next);
  }, function(err) {
    if (err)
      return callback(err);

    // Schedule the getdata's we just added.
    self.scheduleRequests(peer);

    // Restart the getheaders process
    // Technically `last` is not indexed yet so
    // the locator hashes will not be entirely
    // accurate. However, it shouldn't matter
    // that much since FindForkInGlobalIndex
    // simply tries to find the latest block in
    // the peer's chain.
    if (last && headers.length === 2000)
      self.getHeaders(peer, last, null, callback);
    else
      callback();
  });
};

Pool.prototype._handleBlocks = function _handleBlocks(hashes, peer, callback) {
  var self = this;

  assert(!this.options.headers);

  callback = utils.ensure(callback);

  if (hashes.length === 0)
    return callback();

  bcoin.debug(
    'Recieved %s block hashes from %s',
    hashes.length,
    peer.host);

  // Normally this is 500, but with older
  // versions locator.GetDistanceBack() is called.
  // if (hashes.length > 500) {
  //   peer.setMisbehavior(100);
  //   return;
  // }

  this.emit('blocks', hashes);

  // Reset interval to avoid calling getblocks unnecessarily
  this._startInterval();

  // Reset timeout to avoid killing the loader
  this._startTimer();

  utils.forEachSerial(hashes, function(hash, next, i) {
    // Resolve orphan chain.
    if (self.chain.hasOrphan(hash)) {
      bcoin.debug('Peer sent a hash that is already a known orphan.');
      return self.resolveOrphan(peer, null, hash, next);
    }

    self.getData(peer, self.block.type, hash, function(err, exists) {
      if (err)
        return next(err);

      // Normally we request the hashContinue.
      // In the odd case where we already have
      // it, we can do one of two things: either
      // force re-downloading of the block to
      // continue the sync, or do a getblocks
      // from the last hash (this will reset
      // the hashContinue on the remote node).
      if (exists && i === hashes.length - 1) {
        // Request more hashes:
        self.getBlocks(peer, hash, null, next);
        // Re-download the block (traditional method):
        // self.getData(peer, self.block.type, hash, true, next);
        return;
      }

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);

    self.scheduleRequests(peer);

    callback();
  });
};

Pool.prototype._handleInv = function _handleInv(hashes, peer, callback) {
  var self = this;

  callback = utils.ensure(callback);

  // Ignore for now if we're still syncing
  if (!this.synced)
    return callback();

  utils.forEachSerial(hashes, function(hash, next) {
    if (self.options.headers)
      self.getHeaders(peer, null, hash, next);
    else
      self.getData(peer, self.block.type, hash, next);
  }, function(err) {
    if (err)
      return callback(err);

    self.scheduleRequests(peer);

    callback();
  });
};

Pool.prototype._handleBlock = function _handleBlock(block, peer, callback) {
  var self = this;
  var requested;

  callback = utils.asyncify(callback);

  // Fulfill our request.
  requested = self.fulfill(block);

  // Someone is sending us blocks without
  // us requesting them.
  if (!requested) {
    bcoin.debug(
      'Recieved unrequested block: %s (%s)',
      block.rhash, peer.host);
    return callback();
  }

  this.chain.add(block, function(err) {
    if (err) {
      if (err.type === 'VerifyError') {
        if (err.score >= 0)
          peer.sendReject(block, err.code, err.reason, err.score);

        if (err.reason === 'bad-prevblk') {
          if (peer === self.peers.load)
            self.resolveOrphan(peer, null, block.hash('hex'));
        }

        self.scheduleRequests(peer);

        return callback(err);
      }
      return callback(err);
    }

    self.scheduleRequests(peer);

    self.emit('chain-progress', self.chain.getProgress(), peer);

    if (self.chain.total % 20 === 0) {
      bcoin.debug(
        'Status: tip=%s ts=%s height=%d blocks=%d orphans=%d active=%d'
        + ' queue=%d target=%s peers=%d pending=%d highest=%d jobs=%d',
        block.rhash,
        utils.date(block.ts),
        self.chain.height,
        self.chain.total,
        self.chain.orphan.count,
        self.request.activeBlocks,
        peer.queue.block.length,
        block.bits,
        self.peers.all.length,
        self.chain.locker.pending.length,
        self.chain.bestHeight,
        self.chain.locker.jobs.length);
    }

    return callback();
  });
};

Pool.prototype._load = function _load() {
  if (!this.syncing)
    return;

  if (!this.peers.load) {
    this._addLoader();
    return;
  }

  if (this.options.headers)
    this.getHeaders(this.peers.load, null, null);
  else
    this.getBlocks(this.peers.load, null, null);
};

/**
 * Send `mempool` to all peers.
 */

Pool.prototype.getMempool = function getMempool() {
  var i;

  if (this.peers.load)
    this.peers.load.getMempool();

  for (i = 0; i < this.peers.regular.length; i++)
    this.peers.regular[i].getMempool();
};

Pool.prototype._createPeer = function _createPeer(options) {
  var self = this;

  var peer = new bcoin.peer(this, {
    seed: options.seed,
    createSocket: this.options.createSocket,
    relay: this.options.relay,
    priority: options.priority,
    socket: options.socket,
    network: options.network,
    spv: options.spv,
    witness: options.witness,
    headers: this.options.headers
  });

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('reject', function(payload) {
    var data = payload.data
      ? utils.revHex(payload.data)
      : null;

    bcoin.debug(
      'Reject (%s): msg=%s ccode=%s reason=%s data=%s',
      peer.host,
      payload.message,
      payload.ccode,
      payload.reason,
      data);

    self.emit('reject', payload, peer);
  });

  peer.on('alert', function(payload) {
    bcoin.debug('Received alert from: %s', peer.host);
    bcoin.debug(payload);
    self.emit('alert', payload, peer);
  });

  peer.on('notfound', function(items) {
    var i, item;

    for (i = 0; i < items.length; i++) {
      item = items[i];
      req = self.request.map[item.hash];
      if (req && req.peer === peer)
        req.finish();
    }
  });

  peer.on('tx', function(tx) {
    self._handleTX(tx, peer, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  peer.on('addr', function(data) {
    if (self.options.discoverPeers === false)
      return;

    if (!(data.services & constants.services.NETWORK))
      return;

    if (self.options.headers) {
      if (data.version < 31800)
        return;
    }

    if (self.options.spv) {
      if (data.version < 70011 || !(data.services & constants.services.BLOOM))
        return;
    }

    if (self.options.witness) {
      if (!(data.services & constants.services.WITNESS))
        return;
    }

    if (self.seeds.length > 300)
      self.setSeeds(self.seeds.slice(-150));

    self.addSeed(data);

    self.emit('addr', data, peer);
  });

  peer.on('txs', function(txs) {
    var i, hash;

    self.emit('txs', txs, peer);

    if (!self.options.spv) {
      if (self.syncing && !self.synced)
        return;
    }

    for (i = 0; i < txs.length; i++) {
      hash = txs[i];
      if (self._markTX(hash, 0))
        self.getData(peer, self.tx.type, hash);
    }
  });

  peer.on('version', function(version) {
    if (version.height > self.block.versionHeight)
      self.block.versionHeight = version.height;

    bcoin.debug(
      'Received version from %s: version=%d height=%d agent=%s',
      peer.host, version.version, version.height, version.agent);

    bcoin.time.add(peer.host, version.ts);

    self.emit('version', version, peer);
  });

  return peer;
};

Pool.prototype._handleTX = function _handleTX(tx, peer, callback) {
  var self = this;
  var requested, updated;

  callback = utils.asyncify(callback);

  requested = this.fulfill(tx);
  updated = this._markTX(tx, 1);

  function addMempool(tx, callback) {
    if (!self.mempool)
      return callback();

    if (tx.ts !== 0)
      return callback();

    self.mempool.addTX(tx, callback);
  }

  addMempool(tx, function(err) {
    if (err) {
      if (err.type === 'VerifyError') {
        if (err.score >= 0)
          peer.sendReject(tx, err.code, err.reason, err.score);
        return callback();
      }
    }

    if (updated || tx.block)
      self.emit('tx', tx, peer);

    if (self.options.spv && tx.block)
      self.emit('watched', tx, peer);

    return callback();
  });
};

Pool.prototype._addLeech = function _addLeech(socket) {
  var self = this;
  var peer;

  if (this.destroyed)
    return socket.destroy();

  peer = this._createPeer({
    socket: socket,
    priority: false,
    network: false,
    spv: false,
    witness: false
  });

  bcoin.debug('Added leech peer: %s', peer.host);

  this.peers.leeches.push(peer);
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  peer.once('close', function() {
    self._removePeer(peer);
  });

  peer.once('ack', function() {
    if (self.destroyed)
      return;

    peer.updateWatch();
  });

  peer.on('merkleblock', function(block) {
    if (!self.options.spv)
      return;

    self._handleBlock(block, peer);
  });

  peer.on('block', function(block) {
    if (self.options.spv)
      return;

    self._handleBlock(block, peer);
  });

  peer.on('blocks', function(hashes) {
    self._handleInv(hashes, peer, function(err) {
      if (err)
        self.emit('error', err);
    });
  });

  utils.nextTick(function() {
    self.emit('leech', peer);
  });

  return peer;
};

Pool.prototype._addPeer = function _addPeer() {
  var self = this;
  var peer, seed;

  if (this.destroyed)
    return;

  if (this.peers.regular.length + this.peers.pending.length >= this.size)
    return;

  seed = this.getSeed(false);

  if (!seed) {
    setTimeout(this._addPeer.bind(this), 5000);
    return;
  }

  peer = this._createPeer({
    seed: seed,
    priority: false,
    network: true,
    spv: this.options.spv,
    witness: this.options.witness
  });

  this.peers.pending.push(peer);
  this.peers.all.push(peer);
  this.peers.map[peer.host] = peer;

  peer.once('close', function() {
    self._removePeer(peer);
    if (self.destroyed)
      return;
    self._addPeer();
  });

  peer.once('ack', function() {
    var i;

    if (self.destroyed)
      return;

    if (utils.binaryRemove(self.peers.pending, peer, compare))
      utils.binaryInsert(self.peers.regular, peer, compare);

    peer.updateWatch();
  });

  peer.on('merkleblock', function(block) {
    if (!self.options.spv)
      return;
    self._handleBlock(block, peer);
  });

  peer.on('block', function(block) {
    if (self.options.spv)
      return;
    self._handleBlock(block, peer);
  });

  peer.on('blocks', function(hashes) {
    self._handleInv(hashes, peer);
  });

  utils.nextTick(function() {
    self.emit('peer', peer);
  });
};

Pool.prototype._markTX = function(hash, state) {
  if (hash.hash)
    hash = hash.hash('hex');

  if (this.tx.count >= 5000) {
    this.tx.state = {};
    this.tx.count = 0;
  }

  if (this.tx.state[hash] == null) {
    this.tx.state[hash] = state;
    this.tx.count++;
    return true;
  }

  if (this.tx.state[hash] < state) {
    this.tx.state[hash] = state;
    return true;
  }

  return false;
};

Pool.prototype.bestPeer = function bestPeer() {
  return this.peers.regular.reduce(function(best, peer) {
    if (!peer.version || !peer.socket)
      return;

    if (!best || peer.version.height > best.version.height)
      return peer;

    return best;
  }, null);
};

Pool.prototype._removePeer = function _removePeer(peer) {
  utils.binaryRemove(this.peers.pending, peer);
  utils.binaryRemove(this.peers.regular, peer);
  utils.binaryRemove(this.peers.leeches, peer);
  utils.binaryRemove(this.peers.all, peer);
  delete this.peers.map[peer.host];

  if (this.peers.load === peer) {
    Object.keys(this.request.map).forEach(function(hash) {
      var item = this.request.map[hash];
      if (item.peer === peer)
        item.finish();
    }, this);
    bcoin.debug('Removed loader peer (%s).', peer.host);
    this.peers.load = null;
  }
};

/**
 * Watch a piece of data (filterload, SPV-only).
 * @param {Buffer} id
 */

Pool.prototype.watch = function watch(id) {
  var self = this;
  var hid, i;

  if (id instanceof bcoin.wallet) {
    this.watchWallet(id);
    return;
  }

  if (id) {
    hid = id.toString('hex');

    if (this.watchMap[hid]) {
      this.watchMap[hid]++;
      return;
    }

    this.watchMap[hid] = 1;

    this.bloom.add(id);
  }

  // Send it to peers
  this.updateWatch();
};

/**
 * Unwatch a piece of data (filterload, SPV-only).
 * @param {Buffer} id
 */

Pool.prototype.unwatch = function unwatch(id) {
  var self = this;
  var i, hid;

  hid = id.toString('hex');

  if (!this.watchMap[hid] || --this.watchMap[hid] !== 0)
    return;

  delete this.watchMap[hid];

  // Reset bloom filter
  this.bloom.reset();
  Object.keys(this.watchMap).forEach(function(id) {
    this.bloom.add(id);
  }, this);

  // Resend it to peers
  this.updateWatch();
};

/**
 * Resend the bloom filter to peers.
 */

Pool.prototype.updateWatch = function updateWatch() {
  var self = this;

  if (this._pendingWatch)
    return;

  this._pendingWatch = true;

  utils.nextTick(function() {
    self._pendingWatch = false;

    if (self.peers.load)
      self.peers.load.updateWatch();

    for (i = 0; i < self.peers.regular.length; i++)
      self.peers.regular[i].updateWatch();
  });
};

/**
 * Add a wallet to bloom filter (SPV-only). Resend pending transactions.
 * @param {Wallet} wallet
 * @param {Function} callback
 */

Pool.prototype.addWallet = function addWallet(wallet, callback) {
  var self = this;
  var i;

  callback = utils.asyncify(callback);

  if (this.options.spv)
    this.watchWallet(wallet);

  wallet.getUnconfirmed(function(err, txs) {
    if (err)
      return callback(err);

    for (i = 0; i < txs.length; i++)
      self.sendTX(txs[i]);

    if (!self.options.spv)
      return callback();

    self.searchWallet(wallet, callback);
  });
};

/**
 * Remove a wallet from the bloom filter (SPV-only).
 * @param {Wallet} wallet
 */

Pool.prototype.removeWallet = function removeWallet(wallet) {
  if (!this.options.spv)
    return;

  assert(this.loaded, 'Pool is not loaded.');

  this.unwatchWallet(wallet);
};

/**
 * Add an address to the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.watchAddress = function watchAddress(address) {
  this.watch(bcoin.address.getHash(address));
};

/**
 * Remove an address from the bloom filter (SPV-only).
 * @param {Address|Base58Address} address
 */

Pool.prototype.unwatchAddress = function unwatchAddress(address) {
  this.unwatch(bcoin.address.getHash(address));
};

/**
 * Add a wallet to the bloom filter (SPV-only).
 * @param {Base58Address} address
 */

Pool.prototype.watchWallet = function watchWallet(wallet) {
  Object.keys(wallet.addressMap).forEach(function(address) {
    this.watch(new Buffer(address, 'hex'));
  }, this);
};

/**
 * Remove a wallet from the bloom filter (SPV-only).
 * @param {Base58Address} address
 */

Pool.prototype.unwatchWallet = function unwatchWallet(wallet) {
  Object.keys(wallet.addressMap).forEach(function(address) {
    this.unwatch(new Buffer(address, 'hex'));
  }, this);
};

/**
 * Reset the chain to the wallet's last
 * active transaction's timestamp/height (SPV-only).
 * @param {Wallet} wallet
 * @param {Function} callback
 */

Pool.prototype.searchWallet = function(wallet, callback) {
  var self = this;

  assert(this.loaded, 'Pool is not loaded.');

  callback = utils.asyncify(callback);

  if (!this.options.spv)
    return callback();

  wallet.getLastTime(function(err, ts, height) {
    if (err)
      return callback(err);

    // Always prefer height
    if (height > 0) {
      // Back one week
      if (!height || height === -1)
        height = self.chain.height - (7 * 24 * 6);

      self.chain.reset(height, function(err) {
        if (err) {
          bcoin.debug('Failed to reset height: %s', err.stack + '');
          return callback(err);
        }

        bcoin.debug('Wallet height: %s', height);
        bcoin.debug(
          'Reverted chain to height=%d (%s)',
          self.chain.height,
          utils.date(self.chain.tip.ts)
        );

        callback();
      });

      return;
    }

    if (!ts)
      ts = utils.now() - 7 * 24 * 3600;

    self.chain.resetTime(ts, function(err) {
      if (err) {
        bcoin.debug('Failed to reset time: %s', err.stack + '');
        return callback(err);
      }

      bcoin.debug('Wallet time: %s', utils.date(ts));
      bcoin.debug(
        'Reverted chain to height=%d (%s)',
        self.chain.height,
        utils.date(self.chain.tip.ts)
      );

      callback();
    });
  });
};

/**
 * Queue a `getdata` request to be sent. Checks existence
 * in the chain before requesting.
 * @param {Peer} peer
 * @param {Number} type - `getdata` type (see {@link constants.inv}).
 * @param {Hash} hash - {@link Block} or {@link TX} hash.
 * @param {Object?} options
 * @param {Function} callback
 */

Pool.prototype.getData = function getData(peer, type, hash, options, callback) {
  var self = this;
  var item;

  if (typeof options === 'function') {
    callback = options;
    options = null;
  }

  callback = utils.ensure(callback);

  if (this.destroyed)
    return callback();

  if (options == null)
    options = {};

  if (typeof options === 'boolean')
    options = { force: options };

  function done(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback(null, true);

    if (self.request.map[hash])
      return callback(null, true);

    item = new LoadRequest(self, peer, type, hash);

    if (options.noQueue)
      return callback(null, false);

    if (type === self.tx.type) {
      if (peer.queue.tx.length === 0) {
        utils.nextTick(function() {
          bcoin.debug(
            'Requesting %d/%d txs from %s with getdata',
            peer.queue.tx.length,
            self.request.activeTX,
            peer.host);

          peer.getData(peer.queue.tx);
          peer.queue.tx.length = 0;
        });
      }

      peer.queue.tx.push(item.start());

      return callback(null, false);
    }

    peer.queue.block.push(item);

    return callback(null, false);
  }

  if (options.force) {
    return utils.nextTick(function() {
      return done(null, false);
    });
  }

  if (type === this.tx.type) {
    if (!this.mempool)
      return utils.asyncify(done)(null, false);
    return this.mempool.has(hash, done);
  }

  return this.chain.has(hash, done);
};

/**
 * Schedule next batch of `getdata` requests for peer.
 * @param {Peer} peer
 */

Pool.prototype.scheduleRequests = function scheduleRequests(peer) {
  var self = this;

  if (this._scheduled)
    return;

  this._scheduled = true;

  this.chain.onFlush(function() {
    utils.nextTick(function() {
      self._sendRequests(peer);
      self._scheduled = false;
    });
  });
};

Pool.prototype._sendRequests = function _sendRequests(peer) {
  var size, items;

  if (this.chain.isBusy())
    return;

  if (peer.queue.block.length === 0)
    return;

  if (this.options.spv) {
    items = peer.queue.block.slice();
    peer.queue.block.length = 0;
  } else {
    // Blocks start getting big after 150k.
    if (this.chain.height <= 100000)
      size = 500;
    else if (this.chain.height <= 150000)
      size = 250;
    else if (this.chain.height <= 170000)
      size = 20;
    else
      size = 10;

    items = peer.queue.block.slice(0, size);
    peer.queue.block = peer.queue.block.slice(size);
  }

  items = items.map(function(item) {
    return item.start();
  });

  bcoin.debug(
    'Requesting %d/%d blocks from %s with getdata',
    items.length,
    this.request.activeBlocks,
    peer.host);

  peer.getData(items);
};

/**
 * Fulfill a requested block.
 * @param {Hash}
 */

Pool.prototype.fulfill = function fulfill(hash) {
  var i, item;

  if (hash.hash)
    hash = hash.hash('hex');

  item = this.request.map[hash];
  if (!item)
    return false;

  item.finish();

  for (i = 0; i < item.callback.length; i++)
    item.callback[i]();

  return item;
};

/**
 * Broadcast a transaction or block.
 * @param {TX|Block} msg
 * @param {Function} callback - Returns [Error]. Executes on request, reject,
 * or timeout.
 * @returns {BroadcastItem}
 */

Pool.prototype.broadcast = function broadcast(msg, callback) {
  var hash = msg.hash('hex');
  var item = this.inv.map[hash];

  if (item) {
    item.refresh(msg);
    item.addCallback(callback);
    return item;
  }

  item = new BroadcastItem(this, msg, callback);

  return item.start();
};

/**
 * Announce an item by sending an inv to all
 * peers. This does not add it to the broadcast
 * queue.
 * @param {TX|Block} tx
 */

Pool.prototype.announce = function announce(msg) {
  for (var i = 0; i < this.peers.all.length; i++)
    this.peers.all[i].sendInv(msg);
};

/**
 * Close and destroy the pool.
 * @method
 * @param {Function} callback
 */

Pool.prototype.close =
Pool.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (this.destroyed)
    return utils.nextTick(callback);

  this.destroyed = true;

  this.stopSync();

  this.inv.list.slice().forEach(function(entry) {
    entry.finish();
  });

  Object.keys(this.request.map).forEach(function(hash) {
    this.request.map[hash].finish();
  }, this);

  if (this.peers.load)
    this.peers.load.destroy();

  this.peers.regular.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.peers.pending.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.peers.leeches.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.unlisten(callback);
};

/**
 * Get peer by host.
 * @param {Seed|String} addr
 * @returns {Peer?}
 */

Pool.prototype.getPeer = function getPeer(host) {
  return this.peers.map[host.host || host];
};

/**
 * Request UTXOs from peer.
 * @param {Array[]} - Array in the form `[[hash, index], ...]`.
 * @param {Function} callback - Returns [Error, {@link Coin}[]].
 */

Pool.prototype.getUTXOs = function getUTXOs(utxos, callback) {
  var peer = this.peers.load || this.peers.regular[0];

  if (!peer)
    return utils.asyncify(callback)(new Error('No peer available.'));

  peer.getUTXOs(utxos, callback);
};

/**
 * Attempt to fill transaction using getutxos (note: unreliable).
 * @param {TX} tx
 * @param {Function} callback - Returns [Error, {@link TX}].
 */

Pool.prototype.fillHistory = function fillHistory(tx, callback) {
  var utxos = [];
  var reqs = [];
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (!input.coin)
      utxos.push([input.prevout.hash, input.prevout.index]);
  }

  if (utxos.length === 0)
    return utils.asyncify(callback)(null, tx);

  this.getUTXOs(utxos, function(err, coins) {
    if (err)
      return callback(err);

    tx.fillCoins(coins);

    return callback(null, tx);
  });
};

/**
 * Allocate a new seed which is not currently being used.
 * @param {Boolean?} priority - If true, the peer that
 * is going to use this seed is high-priority.
 * @returns {Seed}
 */

Pool.prototype.getSeed = function getSeed(priority) {
  var addr;

  if (priority) {
    if (!this.connected)
      return this.originalSeeds[0];

    addr = this._getRandom(this.originalSeeds);
    if (addr)
      return addr;

    addr = this._getRandom(this.seeds);
    if (addr)
      return addr;

    addr = this.seeds[Math.random() * this.seeds.length | 0];
    if (addr)
      return addr;

    return this.originalSeeds[Math.random() * this.originalSeeds.length | 0];
  }

  // Hang back if we don't have a loader peer yet.
  if (!this.peers.load)
    return;

  addr = this._getRandom(this.originalSeeds, true);
  if (addr)
    return addr;

  addr = this._getRandom(this.seeds, true);
  if (addr)
    return addr;
};

Pool.prototype._getRandom = function _getRandom(seeds, uniq) {
  var tried = {};
  var tries = 0;
  var index, addr;

  for (;;) {
    if (tries === seeds.length)
      return;

    index = Math.random() * seeds.length | 0;
    addr = seeds[index];

    if (!tried[index]) {
      tried[index] = true;
      tries++;
    }

    if (this.isMisbehaving(addr.host))
      continue;

    if (uniq && this.getPeer(addr.host))
      continue;

    return addr;
  }
};

/**
 * Reset seeds list.
 * @param {String[]|Seed[]} seeds
 */

Pool.prototype.setSeeds = function setSeeds(seeds) {
  var i, seed;

  this.seeds = [];
  this.hosts = {};

  for (i = 0; i < seeds.length; i++)
    this.addSeed(seeds[i]);
};

/**
 * Add seed to seed list.
 * @param {String|Seed} seed
 * @returns {Boolean}
 */

Pool.prototype.addSeed = function addSeed(seed) {
  seed = utils.parseHost(seed);

  if (this.hosts[seed.host] != null)
    return false;

  this.seeds.push({
    host: seed.host,
    port: seed.port || this.network.port
  });

  this.hosts[seed.host] = true;

  return true;
};

/**
 * Remove seed from seed list.
 * @param {String|Seed} seed
 * @returns {Boolean}
 */

Pool.prototype.removeSeed = function removeSeed(seed) {
  var i;

  seed = utils.parseHost(seed);

  if (this.hosts[seed.host] == null)
    return false;

  for (i = 0; i < this.seeds.length; i++) {
    if (this.seeds[i].host === seed.host) {
      this.seeds.splice(i, 1);
      break;
    }
  }

  delete this.hosts[seed.host];

  return true;
};

/**
 * Increase peer's ban score.
 * @param {Peer} peer
 * @param {Number} score
 * @returns {Boolean} Whether the peer was banned.
 */

Pool.prototype.setMisbehavior = function setMisbehavior(peer, score) {
  peer.banScore += score;

  if (peer.banScore >= constants.BAN_SCORE) {
    this.peers.misbehaving[peer.host] = utils.now();
    bcoin.debug('Ban threshold exceeded for %s', peer.host);
    peer.destroy();
    return true;
  }

  return false;
};

/**
 * Test whether the host/peer is banned.
 * @param {String} host
 * @returns {Boolean}
 */

Pool.prototype.isMisbehaving = function isMisbehaving(host) {
  var peer, time;

  if (host.host)
    host = host.host;

  time = this.peers.misbehaving[host];

  if (time) {
    if (utils.now() > time + constants.BAN_TIME) {
      delete this.peers.misbehaving[host];
      peer = this.getPeer(host);
      if (peer)
        peer.banScore = 0;
      return false;
    }
    return true;
  }

  return false;
};

/**
 * Send a `reject` packet to peer.
 * @see Framer.reject
 * @param {Peer} peer
 * @param {(TX|Block)?} obj
 * @param {String} code - cccode.
 * @param {String} reason
 * @param {Number} score
 */

Pool.prototype.reject = function reject(peer, obj, code, reason, score) {
  var type;

  if (obj) {
    type = (obj instanceof bcoin.tx) ? 'tx' : 'block';

    bcoin.debug('Rejecting %s %s from %s: ccode=%s reason=%s',
      type, obj.rhash, peer.host, code, reason);

    peer.reject({
      message: type,
      ccode: code,
      reason: reason,
      data: obj.hash()
    });
  } else {
    bcoin.debug('Rejecting packet from %s: ccode=%s reason=%s',
      peer.host, code, reason);

    peer.reject({
      ccode: code,
      reason: reason,
      data: null
    });
  }

  if (score != null)
    peer.setMisbehavior(score);
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
 * @param {Function} callback
 */

function LoadRequest(pool, peer, type, hash, callback) {
  if (!(this instanceof LoadRequest))
    return new LoadRequest(pool, peer, type, hash, callback);

  this.pool = pool;
  this.peer = peer;
  this.type = type;
  this.hash = hash;
  this.callback = [];
  this.active = false;
  this.id = this.pool.uid++;

  if (callback)
    this.callback.push(callback);

  assert(!this.pool.request.map[this.hash]);
  this.pool.request.map[this.hash] = this;

  this._finish = this.finish.bind(this);
}

/**
 * Mark the request as in-flight. Start timeout timer.
 */

LoadRequest.prototype.start = function start() {
  this.timeout = setTimeout(this._finish, this.pool.requestTimeout);
  this.peer.on('close', this._finish);

  this.active = true;
  this.pool.request.active++;
  if (this.type === this.pool.tx.type)
    this.pool.request.activeTX++;
  else
    this.pool.request.activeBlocks++;

  return this;
};

/**
 * Mark the request as completed.
 * Remove from queue and map. Clear timeout.
 */

LoadRequest.prototype.finish = function finish() {
  var index;

  if (this.pool.request.map[this.hash]) {
    delete this.pool.request.map[this.hash];
    if (this.active) {
      this.pool.request.active--;
      if (this.type === this.pool.tx.type)
        this.pool.request.activeTX--;
      else
        this.pool.request.activeBlocks--;
      this.active = false;
    }
  }

  if (this.type === this.pool.tx.type)
    utils.binaryRemove(this.peer.queue.tx, this, compare);
  else
    utils.binaryRemove(this.peer.queue.block, this, compare);

  this.peer.removeListener('close', this._finish);

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    delete this.timeout;
  }
};

/**
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @exports BroadcastItem
 * @constructor
 * @private
 * @param {Pool} pool
 * @param {TX|Block} item
 * @param {Function?} callback
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

function BroadcastItem(pool, item, callback) {
  if (!(this instanceof BroadcastItem))
    return new BroadcastItem(pool, item);

  if (item instanceof bcoin.tx) {
    if (item.mutable)
      item = item.toTX();
  }

  this.pool = pool;
  this.callback = [];

  this.id = this.pool.uid++;
  this.key = item.hash('hex');
  this.type = (item instanceof bcoin.tx)
    ? constants.inv.TX
    : constants.inv.BLOCK;
  this.msg = item;
  this.hash = item.hash();
  this.normalValue = item.renderNormal();
  this.witnessValue = item.render();

  // INV does not set the witness
  // mask (only GETDATA does this).
  assert((this.type & constants.WITNESS_MASK) === 0);

  this.addCallback(callback);
}

utils.inherits(BroadcastItem, EventEmitter);

/**
 * Add a callback to be executed on ack, timeout, or reject.
 * @param {
 */

BroadcastItem.prototype.addCallback = function addCallback(callback) {
  if (callback)
    this.callback.push(callback);
};

/**
 * Start the broadcast.
 */

BroadcastItem.prototype.start = function start() {
  var self = this;
  var i;

  assert(!this.timeout, 'Already started.');
  assert(!this.pool.inv.map[this.key], 'Already started.');

  this.pool.inv.map[this.key] = this;
  utils.binaryInsert(this.pool.inv.list, this, compare);

  this.refresh();

  return this;
};

/**
 * Refresh the timeout on the broadcast.
 */

BroadcastItem.prototype.refresh = function refresh() {
  var self = this;

  if (this.timeout) {
    clearTimeout(this.timeout);
    this.timeout = null;
  }

  this.timeout = setTimeout(function() {
    self.emit('timeout');
    self.finish(new Error('Timed out.'));
  }, this.pool.inv.timeout);

  for (i = 0; i < this.pool.peers.all.length; i++)
    this.pool.peers.all[i].sendInv(this);
};

/**
 * Finish the broadcast, potentially with an error.
 * @param {Error?} err
 */

BroadcastItem.prototype.finish = function finish(err) {
  var i;

  assert(this.timeout, 'Already finished.');
  assert(this.pool.inv.map[this.key], 'Already finished.');

  clearInterval(this.timeout);
  this.timeout = null;

  delete this.pool.inv.map[this.key];
  utils.binaryRemove(this.pool.inv.list, this, compare);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);

  this.callback.length = 0;
};

/**
 * Send the item to a peer.
 * @param {Peer} peer
 * @param {Boolean} witness - Whether to use the witness serialization.
 */

BroadcastItem.prototype.sendTo = function sendTo(peer, witness) {
  var self = this;
  var value = witness ? this.witnessValue : this.normalValue;
  var packetType = this.type === constants.inv.TX ? 'tx' : 'block';
  var i;

  peer.write(peer.framer.packet(packetType, value));

  setTimeout(function() {
    self.emit('ack', peer);

    for (i = 0; i < this.callback.length; i++)
      self.callback[i]();

    self.callback.length = 0;
  }, 1000);
};

/**
 * Handle a reject from a peer.
 * @param {Peer} peer
 */

BroadcastItem.prototype.reject = function reject(peer) {
  var i, err;

  this.emit('reject', peer);

  err = new Error('Rejected by ' + peer.host);

  for (i = 0; i < this.callback.length; i++)
    this.callback[i](err);

  this.callback.length = 0;
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

module.exports = Pool;
