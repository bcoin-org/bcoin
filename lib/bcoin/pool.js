/**
 * pool.js - peer management for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var async = require('async');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var network = bcoin.protocol.network;
var constants = bcoin.protocol.constants;

/**
 * Pool
 */

function Pool(options) {
  var self = this;
  var Chain;

  if (!(this instanceof Pool))
    return new Pool(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  if (options.debug)
    bcoin.debug = this.options.debug;

  if (options.network)
    network.set(options.network);

  options.spv = options.spv !== false;

  if (options.type === 'spv')
    options.spv = true;
  else if (options.type === 'full')
    options.spv = false;

  options.headers = options.headers;
  options.multiplePeers = options.multiplePeers;
  options.relay = options.relay == null
    ? (!options.spv ? true : false)
    : options.relay;

  this.originalSeeds = (options.seeds || network.seeds).map(utils.parseHost);
  this.setSeeds([]);

  this.server = null;
  this.destroyed = false;
  this.size = options.size || 8;

  this.blockdb = options.blockdb;
  this.mempool = options.mempool;

  if (options.spv) {
    if (options.headers == null)
      options.headers = true;
    if (options.multiplePeers == null)
      options.multiplePeers = true;
  } else {
    if (options.headers == null)
      options.headers = false;
    if (options.multiplePeers == null)
      options.multiplePeers = false;
  }

  if (!options.headers)
    options.multiplePeers = false;

  this.syncing = false;
  this.synced = false;

  this.load = {
    timeout: options.loadTimeout || 40000,
    interval: options.loadInterval || 20000
  };

  this.requestTimeout = options.requestTimeout || 600000;

  this.chain = new bcoin.chain({
    spv: options.spv,
    multiplePeers: options.multiplePeers,
    preload: options.preload,
    blockdb: options.blockdb,
    mempool: options.mempool
  });

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
    type: !options.spv ? 'block' : 'filtered'
  };

  this.tx = {
    state: {},
    count: 0
  };

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

  // Added and watched wallets
  options.wallets = options.wallets || [];
  this.wallets = [];

  Pool.global = this;

  this.loading = true;

  this.chain.once('load', function() {
    self.loading = false;
    self.emit('load');
    self._init();
  });
}

inherits(Pool, EventEmitter);

Pool.prototype._init = function _init() {
  var self = this;
  var i;

  if (this.originalSeeds.length > 0) {
    this._addLoader();

    for (i = 0; i < this.size; i++)
      this._addPeer();
  }

  this.chain.on('block', function(block, entry, peer) {
    self.emit('block', block, peer);
    // Emit merkle txs after the fact
    if (block.subtype === 'merkleblock') {
      block.txs.forEach(function(tx) {
        self._handleTX(tx, peer);
      });
    }
  });

  this.chain.on('fork', function(block, data, peer) {
    self.emit('fork', data, peer);

    if (!peer)
      return;

    // If we failed a checkpoint, peer is misbehaving.
    if (data.checkpoint) {
      self.setMisbehavior(peer, 100);
      return;
    }

    // Only destroy peer here. Wait for higher chain.
    peer.destroy();
  });

  this.chain.on('invalid', function(block, data, peer) {
    if (!peer)
      return;

    self.setMisbehavior(peer, 100);
  });

  this.chain.on('exists', function(block, data, peer) {
    if (!peer)
      return;

    self.setMisbehavior(peer, 1);
  });

  this.chain.on('orphan', function(block, data, peer) {
    var host = peer ? peer.host : 'unknown';

    if (!peer)
      return;

    // Increase banscore by 10 if we're using getheaders.
    if (self.options.headers) {
      if (!self.options.multiplePeers)
        self.setMisbehavior(peer, 10);
      return;
    }

    // Resolve orphan chain
    self.loadOrphan(self.peers.load, null, data.hash);
  });

  this.options.wallets.forEach(function(wallet) {
    self.addWallet(wallet);
  });

  // Chain is full and up-to-date
  if (this.chain.isFull()) {
    this.synced = true;
    this.emit('full');
    utils.debug('Chain is fully synced (height=%d).', this.chain.height);
  }

  this.startServer();
};

Pool.prototype.getBlocks = function getBlocks(peer, top, stop) {
  var self = this;
  this.chain.onFlush(function() {
    self.chain.getLocatorAsync(top, function(err, locator) {
      if (err)
        throw err;

      peer.getBlocks(locator, stop);
    });
  });
};

Pool.prototype.loadOrphan = function loadOrphan(peer, top, orphan) {
  var self = this;
  assert(orphan);
  this.chain.onFlush(function() {
    self.chain.getLocatorAsync(top, function(err, locator) {
      if (err)
        throw err;

      peer.getBlocks(
        locator,
        self.chain.getOrphanRoot(orphan)
      );
    });
  });
};

Pool.prototype.getHeaders = function getHeaders(peer, top, stop) {
  var self = this;
  this.chain.onFlush(function() {
    self.chain.getLocatorAsync(top, function(err, locator) {
      if (err)
        throw err;

      peer.getHeaders(locator, stop);
    });
  });
};

Pool.prototype.startServer = function startServer() {
  var self = this;

  if (!bcoin.net)
    return;

  if (!this.options.listen)
    return;

  assert(!this.server);

  this.server = new bcoin.net.Server();

  this.server.on('connection', function(socket) {
    self._addLeech(socket);
  });

  this.server.on('listening', function() {
    var data = self.server.address();
    utils.debug(
      'Bitcoin server listening on %s (port=%d)',
      data.address, data.port);
  });

  this.server.listen(network.port, '0.0.0.0');
};

Pool.prototype.stopServer = function stopServer() {
  if (!bcoin.net)
    return;

  if (!this.server)
    return;

  this.server.close();
  delete this.server;
};

Pool.prototype._startTimer = function _startTimer() {
  var self = this;

  this._stopTimer();

  function destroy() {
    if (!self.syncing)
      return;

    // Chain is full and up-to-date
    if (self.chain.isFull()) {
      self._stopTimer();
      self._stopInterval();
      self.synced = true;
      self.emit('full');
      utils.debug('Chain is fully synced (height=%d).', self.chain.height);
      return;
    }

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
    priority: true
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
    if (!self.syncing)
      return;
    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err, added) {
      if (err)
        self.emit('error', err);

      if (added) {
        self._startInterval();
        self._startTimer();
      }
    });
  });

  peer.on('block', function(block) {
    if (!self.syncing)
      return;
    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    self._handleBlock(block, peer, function(err, added) {
      if (err)
        self.emit('error', err);

      if (added) {
        self._startInterval();
        self._startTimer();
      }
    });
  });

  if (self.options.headers) {
    peer.on('blocks', function(hashes) {
      if (!self.syncing)
        return;
      self._handleInv(hashes, peer);
    });

    peer.on('headers', function(headers) {
      if (!self.syncing)
        return;
      self._handleHeaders(headers, peer);
    });
  } else {
    peer.on('blocks', function(hashes) {
      if (!self.syncing)
        return;
      self._handleBlocks(hashes, peer);
    });
  }
};

Pool.prototype.startSync = function startSync() {
  if (this.loading)
    return this.once('load', this.startSync.bind(this));

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

  if (this.loading)
    return;

  this._stopInterval();
  this._stopTimer();
};

Pool.prototype._handleHeaders = function _handleHeaders(headers, peer) {
  var i, header, last, block, blockPeer;

  assert(this.options.headers);

  if (headers.length === 0)
    return;

  utils.debug(
    'Recieved %s headers from %s',
    headers.length,
    peer.host);

  if (headers.length > 2000) {
    this.setMisbehavior(peer, 100);
    return;
  }

  this.emit('headers', headers);

  for (i = 0; i < headers.length; i++) {
    block = bcoin.block(headers[i], 'header');
    blockPeer = peer;

    // if (this.options.multiplePeers) {
    //   if (this.peers.regular.length) {
    //     blockPeer = this.peers.regular[i % (this.peers.regular.length + 1)];
    //     if (!blockPeer)
    //       blockPeer = this.peers.load;
    //   }
    // }

    if (last && block.prevBlock !== last.hash('hex'))
      break;

    if (!block.verify())
      break;

    if (!this.chain.has(block))
      this.getData(blockPeer, this.block.type, block.hash('hex'));

    last = block;
  }

  // Restart the getheaders process
  // Technically `last` is not indexed yet so
  // the locator hashes will not be entirely
  // accurate. However, it shouldn't matter
  // that much since FindForkInGlobalIndex
  // simply tries to find the latest block in
  // the peer's chain.
  if (last && headers.length === 2000)
    this.getHeaders(peer, last, null);

  // Reset interval to avoid calling getheaders unnecessarily
  this._startInterval();
};

Pool.prototype._handleBlocks = function _handleBlocks(hashes, peer) {
  var self = this;
  var i, hash;

  assert(!this.options.headers);

  if (hashes.length === 0)
    return;

  utils.debug(
    'Recieved %s block hashes from %s',
    hashes.length,
    peer.host);

  if (hashes.length > 500) {
    this.setMisbehavior(peer, 100);
    return;
  }

  this.emit('blocks', hashes);

  this.chain.onFlush(function() {
    for (i = 0; i < hashes.length; i++) {
      hash = hashes[i];

      // Resolve orphan chain.
      if (self.chain.hasOrphan(hash)) {
        utils.debug('Peer sent a hash that is already a known orphan.');
        self.loadOrphan(peer, null, hash);
        continue;
      }

      // Request a block if we don't have it.
      if (!self.chain.has(hash)) {
        self.getData(peer, self.block.type, hash);
        continue;
      }

      // Normally we request the hashContinue.
      // In the odd case where we already have
      // it, we can do one of two things: either
      // force re-downloading of the block to
      // continue the sync, or do a getblocks
      // from the last hash.
      if (i === hashes.length - 1) {
        // Request more hashes:
        self.getBlocks(peer, hash, null);

        // Re-download the block (traditional method):
        // self.getData(peer, self.block.type, hash, { force: true });

        continue;
      }
    }
  });

  // Reset interval to avoid calling getblocks unnecessarily
  this._startInterval();

  // Reset timeout to avoid killing the loader
  this._startTimer();
};

Pool.prototype._handleInv = function _handleInv(hashes, peer) {
  var i, hash;

  // Ignore for now if we're still syncing
  if (!this.synced)
    return;

  for (i = 0; i < hashes.length; i++) {
    hash = utils.toHex(hashes[i]);
    if (!this.chain.has(hash)) {
      if (this.options.headers)
        this.getHeaders(this.peers.load, null, hash);
      else
        this.getData(peer, this.block.type, hash);
    }
  }
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
    return callback(null, false);
  }

  this._prehandleBlock(block, peer, function(err) {
    if (err)
      return callback(err);

    self.chain.add(block, peer, function(err, added) {
      if (err)
        return callback(err);

      self.scheduleRequests(peer);

      if (added === 0)
        return callback(null, false);

      self.emit('chain-progress', self.chain.getProgress(), peer);

      if (self.chain.height % 20 === 0) {
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
          self.chain.getCurrentTarget(),
          self.peers.all.length,
          self.chain.pending.length,
          self.chain.bestHeight,
          self.chain.jobs.length);
      }

      return callback(null, true);
    });
  });
};

Pool.prototype._load = function _load() {
  var self = this;
  var next;

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
    socket: options.socket
  });

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('reject', function(payload) {
    var data = utils.revHex(utils.toHex(payload.data));

    utils.debug(
      'Reject: msg=%s ccode=%s reason=%s data=%s',
      payload.message,
      payload.ccode,
      payload.reason,
      data);

    self.emit('reject', payload, peer);
  });

  peer.on('notfound', function(items) {
    items.forEach(function(item) {
      var req = self.request.map[utils.toHex(item.hash)];
      if (req && req.peer === peer)
        item.finish();
    });
  });

  peer.on('tx', function(tx) {
    self._handleTX(tx);
  });

  peer.on('addr', function(data) {
    if (self.options.discoverPeers === false)
      return;

    if (self.seeds.length > 1000)
      self.setSeeds(self.seeds.slice(-500));

    self.addSeed(data);

    self.emit('addr', data, peer);
  });

  peer.on('txs', function(txs) {
    self.emit('txs', txs, peer);

    if (!self.options.spv) {
      if (!self.synced)
        return;
    }

    txs.forEach(function(hash) {
      hash = utils.toHex(hash);
      if (self.markTX(hash, 0))
        self.getData(peer, 'tx', hash);
    });
  });

  peer.on('version', function(version) {
    if (version.height > self.block.versionHeight)
      self.block.versionHeight = version.height;
    self.emit('version', version, peer);
    utils.debug(
      'Received version from %s: version=%d height=%d agent=%s',
      peer.host, version.v, version.height, version.agent);
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
      if (err && self.synced)
        utils.debug('Mempool error: %s', err.message);

      if (updated || tx.block)
        self.emit('tx', tx, peer);

      if (self.options.spv && tx.block)
        self.emit('watched', tx, peer);

      return callback();
    });
  });
};

Pool.prototype._addLeech = function _addLeech(socket) {
  var peer;

  if (this.destroyed)
    return socket.destroy();

  peer = this._createPeer({
    socket: socket,
    priority: false
  });

  assert(peer);

  this.peers.leeches.push(peer);
  this.peers.all.push(peer);

  peer.once('close', function() {
    self._removePeer(peer);
  });

  peer.once('ack', function() {
    var i;

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
    self._handleBlock(block, peer);
  });

  peer.on('block', function(block) {
    self._handleBlock(block, peer);
  });

  peer.on('blocks', function(hashes) {
    self._handleInv(hashes, peer);
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
    priority: false
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
    self._handleBlock(block, peer);
  });

  peer.on('block', function(block) {
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
  if (utils.isBuffer(hash))
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
    if (this.watchMap[hid])
      this.watchMap[hid]++;
    else
      this.watchMap[hid] = 1;

    if (this.bloom.test(id, 'hex'))
      return;

    this.bloom.add(id, 'hex');
  }

  // Send it to peers
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

Pool.prototype.unwatch = function unwatch(id) {
  var self = this;
  var i;

  id = utils.toHex(id);

  if (!this.bloom.test(id, 'hex'))
    return;

  if (!this.watchMap[id] || --this.watchMap[id] !== 0)
    return;

  delete this.watchMap[id];

  // Reset bloom filter
  this.bloom.reset();
  Object.keys(this.watchMap).forEach(function(id) {
    this.bloom.add(id, 'hex');
  }, this);

  // Resend it to peers
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

  function testScript(script) {
    return script.some(function(chunk) {
      if (!Array.isArray(chunk) || chunk.length === 0)
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
    if (testScript(output.script))
      return true;
  }

  // 3. Test prev_out structure
  // 4. Test data elements in input scripts
  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    prev = input.prevout.hash;

    if (typeof prev === 'string')
      prev = utils.toArray(prev, 'hex');

    // Test the prev_out tx hash
    if (bloom.test(prev))
      return true;

    // Test the prev_out script
    if (input.output) {
      if (testScript(input.output.script))
        return true;
    }

    // Test the input script
    if (testScript(input.script))
      return true;
  }

  // 5. No match
  return false;
};

Pool.prototype.addWallet = function addWallet(wallet) {
  var self = this;

  if (this.loading)
    return this.once('load', this.addWallet.bind(this, wallet));

  if (this.wallets.indexOf(wallet) !== -1)
    return false;

  this.watchWallet(wallet);
  this.wallets.push(wallet);

  function search() {
    // Relay pending TXs
    // NOTE: It is important to do it after search, because search could
    // add TS to pending TXs, thus making them confirmed
    wallet.pending().forEach(function(tx) {
      self.sendTX(tx);
    });

    if (!self.options.spv)
      return;

    if (self._pendingSearch)
      return;

    self._pendingSearch = true;

    utils.nextTick(function() {
      self._pendingSearch = false;
      self.searchWallet();
    });
  }

  if (wallet.loading)
    wallet.once('load', search);
  else
    search();
};

Pool.prototype.removeWallet = function removeWallet(wallet) {
  var i = this.wallets.indexOf(wallet);
  assert(!this.loading);
  if (i == -1)
    return;
  this.wallets.splice(i, 1);
  this.unwatchWallet(wallet);
};

Pool.prototype.watchAddress = function watchAddress(address) {
  if (address.type === 'scripthash') {
    // For the redeem script hash in outputs:
    this.watch(address.getScriptHash());
    // For the redeem script in inputs:
    this.watch(address.getScript());
  }

  // For the pubkey hash in outputs:
  this.watch(address.getKeyHash());
  // For the pubkey in inputs:
  this.watch(address.getPublicKey());
};

Pool.prototype.unwatchAddress = function unwatchAddress(address) {
  if (address.type === 'scripthash') {
    // For the redeem script hash in p2sh outputs:
    this.unwatch(address.getScriptHash());
    // For the redeem script in p2sh inputs:
    this.unwatch(address.getScript());
  }

  // For the pubkey hash in p2pk/multisig outputs:
  this.unwatch(address.getKeyHash());
  // For the pubkey in p2pkh inputs:
  this.unwatch(address.getPublicKey());
};

Pool.prototype.watchWallet = function watchWallet(wallet) {
  var self = this;

  wallet.addresses.forEach(function(address) {
    this.watchAddress(address);
  }, this);

  wallet.on('add address', wallet._poolOnAdd = function(address) {
    self.watchAddress(address);
  });

  wallet.on('remove address', wallet._poolOnRemove = function(address) {
    self.unwatchAddress(address);
  });
};

Pool.prototype.unwatchWallet = function unwatchWallet(wallet) {
  wallet.addresses.forEach(function(address) {
    this.unwatchAddress(address);
  }, this);
  wallet.removeListener('add address', wallet._poolOnAdd);
  wallet.removeListener('remove address', wallet._poolOnRemove);
  delete wallet._poolOnAdd;
  delete wallet._poolOnRemove;
};

Pool.prototype.searchWallet = function(ts, height) {
  var self = this;
  var wallet;

  assert(!this.loading);

  if (!this.options.spv)
    return;

  if (ts == null) {
    height = this.wallets.reduce(function(height, wallet) {
      if (wallet.lastHeight < height)
        return wallet.lastHeight;
      return height;
    }, Infinity);
    assert(height !== Infinity);
    ts = this.wallets.reduce(function(ts, wallet) {
      if (wallet.lastTs < ts)
        return wallet.lastTs;
      return ts;
    }, Infinity);
    assert(ts !== Infinity);
  } else if (typeof ts !== 'number') {
    wallet = ts;
    if (wallet.loading) {
      wallet.once('load', function() {
        self.searchWallet(wallet);
      });
      return;
    }
    ts = wallet.lastTs;
    height = wallet.lastHeight;
  }

  // Always prefer height
  if (height > 0) {
    // Back one week
    if (!height || height === -1)
      height = this.chain.height - (7 * 24 * 6);

    this.chain.resetHeightAsync(height, function(err) {
      if (err)
        throw err;

      utils.debug('Wallet height: %s', height);
      utils.debug(
        'Reverted chain to height=%d (%s)',
        self.chain.height,
        new Date(self.chain.tip.ts * 1000)
      );
    });

    return;
  }

  if (!ts)
    ts = utils.now() - 7 * 24 * 3600;

  this.chain.resetTimeAsync(ts, function(err) {
    if (err)
      throw err;

    utils.debug('Wallet time: %s', new Date(ts * 1000));
    utils.debug(
      'Reverted chain to height=%d (%s)',
      self.chain.height,
      new Date(self.chain.tip.ts * 1000)
    );
  });
};

Pool.prototype.search = function search(id, range, callback) {
  var self = this;

  assert(!this.loading);

  if (!this.options.spv)
    return;

  if (range == null) {
    range = id;
    id = null;
  }

  if (typeof id === 'string')
    id = utils.toArray(id, 'hex');

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
    this.chain.resetTimeAsync(range.start, function(err) {
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

  if (this.destroyed)
    return;

  if (!options)
    options = {};

  if (utils.isBuffer(hash))
    hash = utils.toHex(hash);

  if (this.request.map[hash]) {
    if (callback)
      this.request.map[hash].callback.push(callback);
    return;
  }

  if (!options.force && type !== 'tx') {
    if (this.chain.has(hash))
      return;
  }

  if (options.noQueue)
    return;

  item = new LoadRequest(this, peer, type, hash, callback);

  if (type === 'tx') {
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

    return;
  }

  if (peer.queue.block.length === 0) {
    this.chain.onFlush(function() {
      utils.nextTick(function() {
        self.scheduleRequests(peer);
      });
    });
  }

  peer.queue.block.push(item);
};

Pool.prototype.scheduleRequests = function scheduleRequests(peer) {
  var size, items;

  if (this.chain.pending.length > 0)
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
      size = this.blockdb ? 4 : 40;
    else
      size = this.blockdb ? 1 : 10;

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
  var hash;

  if (utils.isBuffer(hash))
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

  this.getData(this.peers.load, 'block', hash, { force: true }, function(block) {
    callback(null, block);
  });
};

Pool.prototype.sendBlock = function sendBlock(block) {
  return this.broadcast(block);
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
  this.getData(this.peers.load, 'tx', hash, { noQueue: true }, function(t) {
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

Pool.prototype.sendTX = function sendTX(tx) {
  var flags = constants.flags.STANDARD_VERIFY_FLAGS;
  // This is to avoid getting banned by
  // bitcoind nodes. Possibly check
  // sigops. Call isStandard and/or
  // isStandardInputs as well.
  if (tx.hasPrevout()) {
    if (!tx.verify(null, true, flags)) {
      utils.debug(
        'Could not relay TX (%s). It does not verify.',
        tx.rhash);
      return;
    }
  }
  return this.broadcast(tx);
};

Pool.prototype.broadcast = function broadcast(msg) {
  var self = this;
  var e = new EventEmitter();

  var entry = {
    msg: msg,
    e: e,
    timer: setTimeout(function() {
      var i = self.inv.list.indexOf(entry);
      if (i !== -1)
        self.inv.list.splice(i, 1);
    }, this.inv.timeout)
  };

  this.inv.list.push(entry);

  this.peers.regular.forEach(function(peer) {
    var result = peer.broadcast(msg);
    if (!result) return;
    result[0].once('request', function() {
      e.emit('ack', peer);
    });
  });

  return e;
};

Pool.prototype.destroy = function destroy() {
  if (this.destroyed)
    return;

  this.destroyed = true;

  if (this.peers.load)
    this.peers.load.destroy();

  this.inv.list.forEach(function(entry) {
    clearTimeout(entry.timer);
    entry.timer = null;
  });

  this.peers.pending.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.peers.regular.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.stopServer();
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
  var i, addr;
  var original = this.originalSeeds;
  var seeds = this.seeds;
  var all = original.concat(seeds);

  // Hang back if we don't have a loader peer yet.
  if (!priority && !this.peers.load)
    return;

  // Randomize the non-original peers.
  seeds = seeds.slice().sort(function() {
    return Math.random() > 0.50 ? 1 : -1;
  });

  // Try to avoid connecting to a peer twice.
  // Try the original peers first.
  for (i = 0; i < original.length; i++) {
    addr = original[i];
    assert(addr.host);
    if (this.getPeer(addr))
      continue;
    if (this.isMisbehaving(addr.host))
      continue;
    return addr;
  }

  // If we are a priority socket, try to find a
  // peer this time with looser requirements.
  if (priority) {
    for (i = 0; i < original.length; i++) {
      addr = original[i];
      assert(addr.host);
      if (this.peers.load && this.getPeer(addr) === this.peers.load)
        continue;
      if (this.isMisbehaving(addr.host))
        continue;
      return addr;
    }
  }

  // Try the rest of the peers second.
  for (i = 0; i < seeds.length; i++) {
    addr = seeds[i];
    assert(addr.host);
    if (this.getPeer(addr))
      continue;
    if (this.isMisbehaving(addr.host))
      continue;
    return addr;
  }

  // If we are a priority socket, try to find a
  // peer this time with looser requirements.
  if (priority) {
    for (i = 0; i < seeds.length; i++) {
      addr = seeds[i];
      assert(addr.host);
      if (this.peers.load && this.getPeer(addr) === this.peers.load)
        continue;
      if (this.isMisbehaving(addr.host))
        continue;
      return addr;
    }
  }

  // If we have no block peers, always return
  // an address.
  if (!priority) {
    if (all.length === 1)
      return all[Math.random() * (all.length - 1) | 0];
  }

  // This should never happen: priority sockets
  // should _always_ get an address.
  if (priority) {
    utils.debug(
      'We had to connect to a random peer. Something is not right.');

    return all[Math.random() * (all.length - 1) | 0];
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
    port: seed.port
  });

  this.hosts[seed.host] = true;

  return true;
};

Pool.prototype.removeSeed = function removeSeed(seed) {
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

Pool.prototype.setMisbehavior = function setMisbehavior(peer, dos) {
  peer.banScore += dos;

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

  this._finish = this.finish.bind(this);
}

LoadRequest.prototype.start = function start() {
  this.timeout = setTimeout(this._finish, this.pool.requestTimeout);
  this.peer.on('close', this._finish);

  this.pool.request.active++;
  if (this.type === 'tx')
    this.pool.request.activeTX++;
  else
    this.pool.request.activeBlocks++;

  assert(!this.pool.request.map[this.hash]);
  this.pool.request.map[this.hash] = this;

  return this;
};

LoadRequest.prototype.finish = function finish() {
  var index;

  if (this.pool.request.map[this.hash]) {
    delete this.pool.request.map[this.hash];
    this.pool.request.active--;
    if (this.type === 'tx')
      this.pool.request.activeTX--;
    else
      this.pool.request.activeBlocks--;
  }

  if (this.type === 'tx') {
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
