/**
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = require('./utils');
var assert = utils.assert;
var network = bcoin.protocol.network;
var constants = bcoin.protocol.constants;

/**
 * Pool
 */

function Pool(node, options) {
  var self = this;
  var seeds;

  if (!(this instanceof Pool))
    return new Pool(node, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.network = node.network;

  options.spv = options.spv !== false;

  if (options.type === 'spv')
    options.spv = true;
  else if (options.type === 'full')
    options.spv = false;

  options.headers = options.headers;
  options.relay = options.relay == null
    ? (!options.spv ? true : false)
    : options.relay;

  seeds = (options.seeds || network.seeds).slice();

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
  this.connected = false;

  this.chain = node.chain;
  this.mempool = node.mempool;

  if (options.spv) {
    if (options.headers == null)
      options.headers = true;
  } else {
    if (options.headers == null)
      options.headers = false;
  }

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
    misbehaving: {}
  };

  this.block = {
    versionHeight: 0,
    bestHash: null,
    type: !options.spv
      ? constants.inv.block
      : constants.inv.filteredblock
  };

  this.tx = {
    state: {},
    count: 0,
    type: constants.inv.tx
  };

  if (this.options.witness) {
    this.block.type |= constants.invWitnessMask;
    this.tx.type |= constants.invWitnessMask;
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
    timeout: options.invTimeout || 60000
  };

  Pool.global = this;

  this.chain.open(function(err) {
    if (err)
      return self.emit('error', err);

    self.loaded = true;
    self.emit('open');

    self._init();
  });
}

utils.inherits(Pool, EventEmitter);

Pool.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

Pool.prototype._init = function _init() {
  var self = this;
  var i;

  if (this.originalSeeds.length > 0) {
    this._addLoader();

    for (i = 0; i < this.size; i++)
      this._addPeer();

    this.connected = true;
  }

  this.chain.on('block', function(block, entry, peer) {
    // Emit merkle txs after the fact
    if (block.type === 'merkleblock') {
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
    // Resolve orphan chain
    self.resolveOrphan(self.peers.load, null, data.hash);
  });

  this.chain.on('full', function() {
    self._stopTimer();
    self._stopInterval();
    if (!self.synced)
      self.getMempool();
    self.synced = true;
    self.emit('full');
    utils.debug('Chain is fully synced (height=%d).', self.chain.height);
  });

  (this.options.wallets || []).forEach(function(wallet) {
    self.addWallet(wallet);
  });

  this.startServer();
};

Pool.prototype.getBlocks = function getBlocks(peer, top, stop, callback) {
  callback = utils.ensure(callback);

  this.chain.getLocator(top, function(err, locator) {
    if (err)
      return callback(err);

    peer.getBlocks(locator, stop);

    callback();
  });
};

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
      utils.debug('Orphan root was already resolved.');
      return callback();
    }

    // If we're already processing the block
    // that would resolve this, ignore.
    // if (self.request.map[orphan.soil]) {
    //   utils.debug('Already requested orphan "soil".');
    //   return callback();
    // }

    // if (self.chain.hasPending(orphan.soil)) {
    //   utils.debug('Already processing orphan "soil".');
    //   return callback();
    // }

    peer.getBlocks(locator, orphan.root);

    callback();
  });
};

Pool.prototype.getHeaders = function getHeaders(peer, top, stop, callback) {
  callback = utils.ensure(callback);

  this.chain.getLocator(top, function(err, locator) {
    if (err)
      return callback(err);

    peer.getHeaders(locator, stop);

    callback();
  });
};

Pool.prototype.startServer = function startServer(callback) {
  var self = this;
  var net;

  callback = utils.ensure(callback);

  if (bcoin.isBrowser)
    return utils.nextTick(callback);

  net = require('n' + 'et');

  if (!this.options.listen)
    return utils.nextTick(callback);

  assert(!this.server);

  this.server = new net.Server();

  this.server.on('connection', function(socket) {
    self._addLeech(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    utils.debug(
      'Bitcoin server listening on %s (port=%d)',
      data.address, data.port);
  });

  this.server.listen(network.port, '0.0.0.0', callback);
};

Pool.prototype.stopServer = function stopServer(callback) {
  callback = utils.ensure(callback);

  if (bcoin.isBrowser)
    return utils.nextTick(callback);

  if (!this.server)
    return utils.nextTick(callback);

  this.server.close(callback);
  delete this.server;
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
      utils.debug('Timer ran out. Finding new loader peer.');
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

    utils.debug('Stall recovery: loading again.');
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

  assert(peer);

  utils.debug('Added loader peer: %s', peer.host);

  this.peers.load = peer;
  this.peers.all.push(peer);

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

Pool.prototype.startSync = function startSync() {
  this.syncing = true;

  this._startInterval();
  this._startTimer();

  if (!this.peers.load) {
    this._addLoader();
    return;
  }

  if (this.peers.load.ack)
    this._load();
};

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
  var last;

  assert(this.options.headers);

  callback = utils.ensure(callback);

  if (headers.length === 0)
    return callback();

  utils.debug(
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

    if (!header.verify())
      return next(new Error('Headers invalid.'));

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

  utils.debug(
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
    hash = utils.toHex(hash);

    // Resolve orphan chain.
    if (self.chain.hasOrphan(hash)) {
      utils.debug('Peer sent a hash that is already a known orphan.');
      self.resolveOrphan(peer, null, hash, next);
      return;
    }

    // Normally we request the hashContinue.
    // In the odd case where we already have
    // it, we can do one of two things: either
    // force re-downloading of the block to
    // continue the sync, or do a getblocks
    // from the last hash.
    if (i === hashes.length - 1) {
      // Request more hashes:
      // self.getBlocks(peer, hash, null, next);
      // Re-download the block (traditional method):
      self.getData(peer, self.block.type, hash, { force: true }, next);
      return;
    }

    // Request block.
    self.getData(peer, self.block.type, hash, next);
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
    hash = utils.toHex(hash);
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

Pool.prototype._prehandleTX = function _prehandleTX(tx, peer, callback) {
  return callback(null, tx);
};

Pool.prototype._prehandleBlock = function _prehandleBlock(block, peer, callback) {
  return callback(null, block);
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
    utils.debug(
      'Recieved unrequested block: %s (%s)',
      block.rhash, peer.host);
    return callback();
  }

  this._prehandleBlock(block, peer, function(err) {
    if (err)
      return callback(err);

    self.chain.add(block, function(err) {
      if (err) {
        if (err.type === 'VerifyError') {
          if (err.score >= 0)
            peer.sendReject(block, err.code, err.reason, err.score);

          if (err.reason === 'bad-prevblk') {
            // self.chain.purgePending();
            // self.resolveOrphan(peer, null, block.hash('hex'));
          }

          self.scheduleRequests(peer);

          return callback(err);
        }
        return callback(err);
      }

      self.scheduleRequests(peer);

      self.emit('chain-progress', self.chain.getProgress(), peer);

      if (self.chain.total % 20 === 0) {
        utils.debug(
          'Status: tip=%s ts=%s height=%d blocks=%d orphans=%d active=%d'
          + ' queue=%d target=%s peers=%d pending=%d highest=%d jobs=%d',
          block.rhash,
          new Date(block.ts * 1000).toISOString().slice(0, -5) + 'Z',
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

Pool.prototype.getMempool = function getMempool() {
  if (this.peers.load)
    this.peers.load.getMempool();

  this.peers.regular.forEach(function(peer) {
    peer.getMempool();
  });
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
      ? utils.revHex(utils.toHex(payload.data))
      : null;

    utils.debug(
      'Reject (%s): msg=%s ccode=%s reason=%s data=%s',
      peer.host,
      payload.message,
      payload.ccode,
      payload.reason,
      data);

    self.emit('reject', payload, peer);
  });

  peer.on('alert', function(payload) {
    utils.debug('Received alert from: %s', peer.host);
    utils.debug(payload);
    self.emit('alert', payload, peer);
  });

  peer.on('notfound', function(items) {
    items.forEach(function(item) {
      var req = self.request.map[utils.toHex(item.hash)];
      if (req && req.peer === peer)
        item.finish();
    });
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

    if (!data.network)
      return;

    if (self.options.spv && !data.spv)
      return;

    if (self.options.witness && !data.witness)
      return;

    if (self.seeds.length > 300)
      self.setSeeds(self.seeds.slice(-150));

    self.addSeed(data);

    self.emit('addr', data, peer);
  });

  peer.on('txs', function(txs) {
    self.emit('txs', txs, peer);

    if (!self.options.spv) {
      if (self.syncing && !self.synced)
        return;
    }

    txs.forEach(function(hash) {
      hash = utils.toHex(hash);
      if (self.markTX(hash, 0))
        self.getData(peer, self.tx.type, hash);
    });
  });

  peer.on('version', function(version) {
    if (version.height > self.block.versionHeight)
      self.block.versionHeight = version.height;

    utils.debug(
      'Received version from %s: version=%d height=%d agent=%s',
      peer.host, version.version, version.height, version.agent);

    self.emit('version', version, peer);
  });

  return peer;
};

Pool.prototype._handleTX = function _handleTX(tx, peer, callback) {
  var self = this;
  var requested, updated;

  callback = utils.asyncify(callback);

  requested = this.fulfill(tx);
  updated = this.markTX(tx, 1);

  function addMempool(tx, peer, callback) {
    if (!self.mempool)
      return callback();

    if (tx.ts !== 0)
      return callback();

    self.mempool.addTX(tx, peer, callback);
  }

  this._prehandleTX(tx, peer, function(err) {
    if (err)
      return callback(err);

    addMempool(tx, peer, function(err) {
      if (err) {
        if (err.type === 'VerifyError') {
          if (err.score >= 0)
            peer.sendReject(block, err.code, err.reason, err.score);
          return callback();
        }
      }

      if (updated || tx.block)
        self.emit('tx', tx, peer);

      if (self.options.spv && tx.block)
        self.emit('watched', tx, peer);

      return callback();
    });
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

  assert(peer);

  this.peers.leeches.push(peer);
  this.peers.all.push(peer);

  peer.once('close', function() {
    self._removePeer(peer);
  });

  peer.once('ack', function() {
    if (self.destroyed)
      return;

    peer.updateWatch();

    self.inv.list.forEach(function(entry) {
      var result = peer.broadcast(entry.msg);
      if (!result)
        return;

      result[0].once('request', function() {
        entry.e.emit('ack', peer);
      });

      result[0].once('reject', function(payload) {
        entry.e.emit('reject', payload, peer);
      });
    });
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

    i = self.peers.pending.indexOf(peer);
    if (i !== -1) {
      self.peers.pending.splice(i, 1);
      self.peers.regular.push(peer);
    }

    peer.updateWatch();

    self.inv.list.forEach(function(entry) {
      var result = peer.broadcast(entry.msg);
      if (!result)
        return;

      result[0].once('request', function() {
        entry.e.emit('ack', peer);
      });

      result[0].once('reject', function(payload) {
        entry.e.emit('reject', payload, peer);
      });
    });
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

Pool.prototype.markTX = function(hash, state) {
  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
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
  var i = this.peers.pending.indexOf(peer);
  if (i !== -1)
    this.peers.pending.splice(i, 1);

  i = this.peers.regular.indexOf(peer);
  if (i !== -1)
    this.peers.regular.splice(i, 1);

  i = this.peers.leeches.indexOf(peer);
  if (i !== -1)
    this.peers.leeches.splice(i, 1);

  i = this.peers.all.indexOf(peer);
  if (i !== -1)
    this.peers.all.splice(i, 1);

  if (this.peers.load === peer) {
    utils.debug('Removed loader peer (%s).', peer.host);
    this.peers.load = null;
  }
};

Pool.prototype.watch = function watch(id) {
  var self = this;
  var hid, i;

  if (id instanceof bcoin.wallet) {
    this.watchWallet(id);
    return;
  }

  if (id) {
    hid = utils.toHex(id);

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

Pool.prototype.unwatch = function unwatch(id) {
  var self = this;
  var i;

  id = utils.toHex(id);

  if (!this.watchMap[id] || --this.watchMap[id] !== 0)
    return;

  delete this.watchMap[id];

  // Reset bloom filter
  this.bloom.reset();
  Object.keys(this.watchMap).forEach(function(id) {
    this.bloom.add(id);
  }, this);

  // Resend it to peers
  this.updateWatch();
};

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

// See "Filter matching algorithm":
// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
Pool.prototype.isWatched = function(tx, bloom) {
  var i, input, output;

  if (!bloom)
    bloom = this.bloom;

  function testScript(code) {
    return code.some(function(chunk) {
      if (!Buffer.isBuffer(chunk) || chunk.length === 0)
        return false;
      return bloom.test(chunk);
    });
  }

  // 1. Test the tx hash
  if (bloom.test(tx.hash()))
    return true;

  // 2. Test data elements in output scripts
  //    (may need to update filter on match)
  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    // Test the output script
    if (testScript(output.script.code))
      return true;
  }

  // 3. Test prev_out structure
  // 4. Test data elements in input scripts
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    // Test the prev_out tx hash
    if (bloom.test(input.prevout.hash, 'hex'))
      return true;

    // Test the prev_out script
    if (input.coin) {
      if (testScript(input.coin.script.code))
        return true;
    }

    // Test the input script
    if (testScript(input.script.code))
      return true;

    // Test the witness
    if (testScript(input.witness.items))
      return true;
  }

  // 5. No match
  return false;
};

Pool.prototype.addWallet = function addWallet(wallet, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (this.options.spv)
    this.watchWallet(wallet);

  wallet.getPending(function(err, txs) {
    if (err)
      return callback(err);

    txs.forEach(function(tx) {
      self.sendTX(tx);
    });

    if (!self.options.spv)
      return callback();

    self.searchWallet(wallet, callback);
  });
};

Pool.prototype.removeWallet = function removeWallet(wallet) {
  if (!this.options.spv)
    return;

  assert(this.loaded);

  this.unwatchWallet(wallet);
};

Pool.prototype.watchAddress = function watchAddress(address) {
  var hash = bcoin.address.parse(address).hash;
  this.watch(hash);
};

Pool.prototype.unwatchAddress = function unwatchAddress(address) {
  var hash = bcoin.address.parse(address).hash;
  this.unwatch(hash);
};

Pool.prototype.watchWallet = function watchWallet(wallet) {
  Object.keys(wallet.addressMap).forEach(function(address) {
    this.watchAddress(address);
  }, this);
};

Pool.prototype.unwatchWallet = function unwatchWallet(wallet) {
  Object.keys(wallet.addressMap).forEach(function(address) {
    this.unwatchAddress(address);
  }, this);
};

Pool.prototype.searchWallet = function(wallet, callback) {
  var self = this;

  assert(this.loaded);

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
          utils.debug('Failed to reset height: %s', err.stack + '');
          return callback(err);
        }

        utils.debug('Wallet height: %s', height);
        utils.debug(
          'Reverted chain to height=%d (%s)',
          self.chain.height,
          new Date(self.chain.tip.ts * 1000)
        );

        callback();
      });

      return;
    }

    if (!ts)
      ts = utils.now() - 7 * 24 * 3600;

    self.chain.resetTime(ts, function(err) {
      if (err) {
        utils.debug('Failed to reset time: %s', err.stack + '');
        return callback(err);
      }

      utils.debug('Wallet time: %s', new Date(ts * 1000));
      utils.debug(
        'Reverted chain to height=%d (%s)',
        self.chain.height,
        new Date(self.chain.tip.ts * 1000)
      );

      callback();
    });
  });
};

Pool.prototype.search = function search(id, range, callback) {
  var self = this;

  assert(this.loaded);

  if (!this.options.spv)
    return;

  if (range == null) {
    range = id;
    id = null;
  }

  if (typeof id === 'string')
    id = new Buffer(id, 'hex');

  if (typeof range === 'number')
    range = { start: range, end: null };
  else if (range)
    range = { start: range.start, end: range.end };
  else
    range = { start: 0, end: 0 };

  if (!range.end)
    range.end = utils.now();

  if (!range.start)
    range.start = utils.now() - 432000;

  if (id)
    this.watch(id);

  callback = utils.asyncify(callback);

  function done(err, completed) {
    self.removeListener('block', onBlock);
    if (id)
      self.unwatch(id);
    callback(err, completed);
  }

  function onBlock(block) {
    if (block.ts >= range.end)
      done(null, true);
  }

  this.on('block', onBlock);

  if (range.start < this.chain.tip.ts) {
    this.chain.resetTime(range.start, function(err) {
      if (err)
        return done(err);

      self.stopSync();
      self.startSync();
    });
  } else {
    done(null, false);
  }
};

Pool.prototype.getData = function getData(peer, type, hash, options, callback) {
  var self = this;
  var item;

  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  callback = utils.ensure(callback);

  if (this.destroyed)
    return callback();

  if (!options)
    options = {};

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);

  function done(err, exists) {
    if (err)
      return callback(err);

    if (exists)
      return callback();

    if (self.request.map[hash])
      return callback();

    item = new LoadRequest(self, peer, type, hash);

    if (options.noQueue)
      return callback();

    if (type === self.tx.type) {
      if (peer.queue.tx.length === 0) {
        utils.nextTick(function() {
          utils.debug(
            'Requesting %d/%d txs from %s with getdata',
            peer.queue.tx.length,
            self.request.activeTX,
            peer.host);

          peer.getData(peer.queue.tx);
          peer.queue.tx.length = 0;
        });
      }

      peer.queue.tx.push(item.start());

      return callback();
    }

    peer.queue.block.push(item);

    return callback();
  }

  if (!options.force && type !== self.tx.type)
    return self.chain.has(hash, done);

  return utils.nextTick(function() {
    return done(null, false);
  });
};

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

  if (this.chain.locker.pending.length > 0)
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

  utils.debug(
    'Requesting %d/%d blocks from %s with getdata',
    items.length,
    this.request.activeBlocks,
    peer.host);

  peer.getData(items);
};

Pool.prototype.fulfill = function fulfill(hash) {
  var item;

  if (Buffer.isBuffer(hash))
    hash = utils.toHex(hash);
  else if (hash.hash)
    hash = hash.hash('hex');

  item = this.request.map[hash];
  if (!item)
    return false;

  item.finish();

  item.callback.forEach(function(callback) {
    callback();
  });

  return item;
};

Pool.prototype.getBlock = function getBlock(hash, callback) {
  if (!this.peers.load)
    return setTimeout(this.getBlock.bind(this, hash, callback), 1000);

  this.getData(this.peers.load, this.block.type, hash, { force: true }, function(block) {
    callback(null, block);
  });

  this.scheduleRequests(this.peers.load);
};

Pool.prototype.sendBlock = function sendBlock(block, callback) {
  return this.broadcast(block, callback);
};

Pool.prototype.getTX = function getTX(hash, range, callback) {
  var self = this;
  var cbs, tx, found, delta;

  if (!this.peers.load)
    return setTimeout(this.getTX.bind(this, hash, range, callback), 1000);

  if (!this.options.spv)
    return callback(new Error('Cannot get tx with full node'));

  hash = utils.toHex(hash);

  if (typeof range === 'function') {
    callback = range;
    range = null;
  }

  // Do not perform duplicate searches
  if (this.validate.map[hash])
    return this.validate.map[hash].push(callback);

  cbs = [callback];
  this.validate.map[hash] = cbs;

  // Add request without queueing it to get notification at the time of load
  tx = null;
  found = false;
  this.getData(this.peers.load, self.tx.type, hash, { noQueue: true }, function(t) {
    found = true;
    tx = t;
  });

  // Do incremental search until the TX is found
  delta = this.validate.delta;

  // Start from the existing range if given
  if (range)
    range = { start: range.start, end: range.end };
  else
    range = { start: utils.now() - delta, end: 0 };

  function done(err, tx, range) {
    delete self.validate.map[hash];
    cbs.forEach(function(callback) {
      callback(err, tx, range);
    });
  }

  (function next() {
    self.search(hash, range, function(err, completed) {
      if (err)
        return done(err);

      if (found)
        return done(null, tx, range);

      if (!completed)
        return done();

      // Not found yet, continue scanning
      range.end = range.start;
      range.start -= delta;
      if (range.start < 0)
        range.start = 0;

      next();
    });
  })();
};

Pool.prototype.sendTX = function sendTX(tx, callback) {
  // Failsafe to avoid getting banned by bitcoind nodes.
  if (!tx.isSane())
    return utils.asyncify(callback)(new Error('CheckTransaction failed.'));

  return this.broadcast(tx, callback);
};

Pool.prototype.broadcast = function broadcast(msg, callback) {
  var self = this;
  var e = new EventEmitter();

  callback = utils.once(callback);

  var entry = {
    msg: msg,
    e: e,
    timer: setTimeout(function() {
      var i = self.inv.list.indexOf(entry);
      if (i !== -1)
        self.inv.list.splice(i, 1);
      callback(new Error('Timed out.'));
    }, this.inv.timeout)
  };

  this.inv.list.push(entry);

  this.peers.all.forEach(function(peer) {
    var result = peer.broadcast(msg);
    if (!result)
      return;

    result[0].once('request', function() {
      e.emit('ack', peer);
      // Give them a chance to send a reject.
      setTimeout(function() {
        callback();
      }, 100);
    });

    result[0].once('reject', function(payload) {
      e.emit('reject', payload, peer);
      callback(new Error('TX was rejected: ' + payload.reason));
    });
  });

  return e;
};

Pool.prototype.close =
Pool.prototype.destroy = function destroy(callback) {
  callback = utils.ensure(callback);

  if (this.destroyed)
    return utils.nextTick(callback);

  this.destroyed = true;

  this.stopSync();

  this.inv.list.forEach(function(entry) {
    clearTimeout(entry.timer);
    entry.timer = null;
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

  this.stopServer(callback);
};

Pool.prototype.getPeer = function getPeer(addr) {
  var i, peer;

  if (!addr)
    return;

  addr = utils.parseHost(addr);

  for (i = 0; i < this.peers.all.length; i++) {
    peer = this.peers.all[i];
    if (peer.host === addr.host)
      return peer;
  }
};

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

  // Need at least one block peer.
  if (this.originalSeeds.length + this.seeds.length === 1) {
    assert(this.originalSeeds[0]);
    return this.originalSeeds[0];
  }

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

Pool.prototype.setSeeds = function setSeeds(seeds) {
  this.seeds = [];
  this.hosts = {};
  seeds.forEach(function(seed) {
    this.addSeed(seed);
  }, this);
};

Pool.prototype.addSeed = function addSeed(seed) {
  seed = utils.parseHost(seed);

  if (this.hosts[seed.host] != null)
    return false;

  this.seeds.push({
    host: seed.host,
    port: seed.port || network.port
  });

  this.hosts[seed.host] = true;

  return true;
};

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

Pool.prototype.setMisbehavior = function setMisbehavior(peer, score) {
  peer.banScore += score;

  if (peer.banScore >= constants.banScore) {
    this.peers.misbehaving[peer.host] = utils.now();
    utils.debug('Ban threshold exceeded for %s', peer.host);
    peer.destroy();
    return true;
  }

  return false;
};

Pool.prototype.isMisbehaving = function isMisbehaving(host) {
  var peer, time;

  if (host.host)
    host = host.host;

  time = this.peers.misbehaving[host];

  if (time) {
    if (utils.now() > time + constants.banTime) {
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

Pool.prototype.reject = function reject(peer, obj, code, reason, score) {
  if (obj) {
    utils.debug('Rejecting %s %s from %s: ccode=%s reason=%s',
      obj.type, obj.hash('hex'), peer.host, code, reason);

    peer.reject({
      ccode: code,
      reason: reason,
      data: obj.hash()
    });
  } else {
    utils.debug('Rejecting packet from %s: ccode=%s reason=%s',
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
 * LoadRequest
 */

function LoadRequest(pool, peer, type, hash, callback) {
  this.pool = pool;
  this.peer = peer;
  this.type = type;
  this.hash = hash;
  this.callback = [];

  if (callback)
    this.callback.push(callback);

  assert(!this.pool.request.map[this.hash]);
  this.pool.request.map[this.hash] = this;

  this._finish = this.finish.bind(this);
}

LoadRequest.prototype.start = function start() {
  this.timeout = setTimeout(this._finish, this.pool.requestTimeout);
  this.peer.on('close', this._finish);

  this.pool.request.active++;
  if (this.type === this.pool.tx.type)
    this.pool.request.activeTX++;
  else
    this.pool.request.activeBlocks++;

  return this;
};

LoadRequest.prototype.finish = function finish() {
  var index;

  if (this.pool.request.map[this.hash]) {
    delete this.pool.request.map[this.hash];
    this.pool.request.active--;
    if (this.type === this.pool.tx.type)
      this.pool.request.activeTX--;
    else
      this.pool.request.activeBlocks--;
  }

  if (this.type === this.pool.tx.type) {
    index = this.peer.queue.tx.indexOf(this);
    if (index !== -1)
      this.peer.queue.tx.splice(index, 1);
  } else {
    index = this.peer.queue.block.indexOf(this);
    if (index !== -1)
      this.peer.queue.block.splice(index, 1);
  }

  this.peer.removeListener('close', this._finish);

  if (this.timeout != null) {
    clearTimeout(this.timeout);
    delete this.timeout;
  }
};

/**
 * Expose
 */

module.exports = Pool;
