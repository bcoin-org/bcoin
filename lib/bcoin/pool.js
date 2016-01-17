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

/**
 * Pool
 */

function Pool(options) {
  var self = this;
  var Chain;

  if (!(this instanceof Pool))
    return new Pool(options);

  EventEmitter.call(this);

  this.options = options || {};

  if (this.options.network)
    network.set(this.options.network);

  this.options.fullNode = !!this.options.fullNode;
  this.options.headers = this.options.headers;
  this.options.multiplePeers = this.options.multiplePeers;
  this.options.relay = this.options.relay == null
    ? (this.options.fullNode ? true : false)
    : this.options.relay;
  this.options.seeds = options.seeds || network.seeds;

  this.setSeeds(this.options.seeds);

  this.storage = this.options.storage;
  this.destroyed = false;
  this.size = options.size || 32;
  this.parallel = options.parallel || 2000;
  this.redundancy = options.redundancy || 1;

  this._createConnection = options.createConnection;
  this._createSocket = options.createSocket;

  if (!this.options.fullNode) {
    if (this.options.headers == null)
      this.options.headers = true;
    if (this.options.multiplePeers == null)
      this.options.multiplePeers = true;
  } else {
    if (this.options.headers == null)
      this.options.headers = false;
    if (this.options.multiplePeers == null)
      this.options.multiplePeers = false;
  }

  if (!this.options.headers)
    this.options.multiplePeers = false;

  this.syncing = false;

  this.backoff = {
    delta: options.backoffDelta || 500,
    max: options.backoffMax || 5000
  };

  this.load = {
    timeout: options.loadTimeout || 30000,
    interval: options.loadInterval || 5000,
    window: options.loadWindow || 250,
    lastRange: null,
    rangeWindow: options.rangeWindow || 1000,
    timer: null,
    lwm: options.lwm || this.parallel * 2,
    hwm: options.hwm || this.parallel * 8,
    hiReached: false
  };

  this.maxRetries = options.maxRetries || 42;
  this.requestTimeout = options.requestTimeout || 10000;

  this.chain = new bcoin.chain({
    storage: this.storage,
    fullNode: this.options.fullNode,
    multiplePeers: this.options.multiplePeers
  });

  this.watchMap = {};

  this.bloom = new bcoin.bloom(
    8 * 1024,
    10,
    (Math.random() * 0xffffffff) | 0
  );

  this.peers = {
    // Peers that are loading blocks themselves
    block: [],
    // Peers that are still connecting
    pending: [],
    // Peers that are loading block ids
    load: null,
    // All peers
    all: []
  };

  this.block = {
    bestHeight: 0,
    bestHash: null,
    type: this.options.fullNode ? 'block' : 'filtered'
  };

  this.request = {
    map: {},
    active: 0,
    queue: []
  };

  this.validate = {
    // 5 days scan delta for obtaining TXs
    delta: 5 * 24 * 3600,

    // Minimum verification depth
    minDepth: options.minValidateDepth || 0,

    // getTX map
    map: {}
  };

  // Currently broadcasted TXs
  this.inv = {
    list: [],
    timeout: options.txTimeout || 60000
  };

  // Added and watched wallets
  this.options.wallets = this.options.wallets || [];
  this.wallets = [];

  this.chain.on('debug', function() {
    var args = Array.prototype.slice.call(arguments);
    self.emit.apply(self, ['debug'].concat(args));
  });

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

  this._addLoader();

  for (i = 0; i < this.size; i++)
    this._addPeer(0);

  this.chain.on('block', function(block, peer) {
    self.emit('block', block, peer);
  });

  this.chain.on('fork', function(data) {
    var peer = self.peers.load;

    this.emit('debug',
      'Fork at height %d: expected=%s received=%s checkpoint=%s',
      data.height,
      utils.revHex(data.expected),
      utils.revHex(data.received),
      data.checkpoint
    );

    if (!peer)
      return;

    peer.destroy();
  });

  this.options.wallets.forEach(function(w) {
    self.addWallet(w);
  });
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
      self.emit('full');
      return;
    }

    if (self.peers.load)
      self.peers.load.destroy();
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

Pool.prototype.createConnection = function createConnection(peer, pool) {
  var addr, net, socket;

  if (pool._createConnection)
    return pool._createConnection(peer, pool);

  addr = pool.usableSeed(true);

  peer.host = addr.host;
  peer.port = addr.port;

  if (this._createSocket) {
    socket = this._createSocket(addr.port, addr.host);
  } else {
    net = require('net');
    socket = net.connect(addr.port, addr.host);
  }

  socket.on('connect', function() {
    pool.emit('debug', 'Connected to %s:%d', addr.host, addr.port);
  });

  return socket;
};

Pool.prototype._addLoader = function _addLoader() {
  var self = this;
  var peer;

  if (this.destroyed)
    return;

  if (this.peers.load != null)
    return;

  peer = this._createPeer(750 * Math.random());

  peer.once('socket', function() {
    self.emit('debug', 'Added loader peer: %s', peer.host);
  });

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
    if (!self.syncing)
      return;
    peer.updateWatch();
    if (!self._load())
      self._stopTimer();
  });

  peer.on('merkleblock', function(block) {
    if (!self.syncing)
      return;
    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    if (self._handleBlock(block, peer)) {
      self._startInterval();
      self._startTimer();
    }
  });

  peer.on('block', function(block) {
    if (!self.syncing)
      return;
    // If the peer sent us a block that was added
    // to the chain (not orphans), reset the timeout.
    if (self._handleBlock(block, peer)) {
      self._startInterval();
      self._startTimer();
    }
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
  this.syncing = true;

  this._startInterval();
  this._startTimer();

  if (!this.peers.load) {
    this._addLoader();
    return;
  }

  if (this.peers.load.ack) {
    if (!this._load())
      this._stopTimer();
  }
};

Pool.prototype.stopSync = function stopSync() {
  if (!this.syncing)
    return;

  this.syncing = false;

  this._stopInterval();
  this._stopTimer();
};

Pool.prototype._handleHeaders = function _handleHeaders(headers, peer) {
  var i, header, last, block;

  assert(this.options.headers);

  if (headers.length === 0)
    return;

  this.emit('debug',
    'Recieved %s headers from %s',
    headers.length,
    peer.host);

  if (headers.length > 2000) {
    peer.destroy();
    return;
  }

  this.emit('headers', headers);

  for (i = 0; i < headers.length; i++) {
    block = bcoin.block(headers[i], 'header');

    if (last && block.prevBlock !== last.hash('hex'))
      break;

    if (!block.verify())
      break;

    if (!this.chain.has(block))
      this._request(this.block.type, block.hash('hex'));

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
    peer.loadHeaders(this.chain.locatorHashes(last), null);

  // Push our getdata packet
  this._scheduleRequests();

  // Reset interval to avoid calling getheaders unnecessarily
  this._startInterval();

  // Reset timeout to avoid killing the loader
  this._startTimer();
};

Pool.prototype._handleBlocks = function _handleBlocks(hashes, peer) {
  var i, hash;

  assert(!this.options.headers);

  if (hashes.length === 0)
    return;

  this.emit('debug',
    'Recieved %s block hashes from %s',
    hashes.length,
    peer.host);

  if (hashes.length > 500) {
    peer.destroy();
    return;
  }

  this.emit('blocks', hashes);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    // Resolve orphan chain
    if (this.chain.hasOrphan(hash)) {
      peer.loadBlocks(
        this.chain.locatorHashes(),
        this.chain.getOrphanRoot(hash)
      );
      continue;
    }

    // Request block if we don't have it or if
    // this is the last hash: this is done as
    // a failsafe because we _need_ to request
    // the hashContinue no matter what.
    if (!this.chain.has(hash) || i === hashes.length - 1) {
      this._request(this.block.type, hash);
      continue;
    }
  }

  // Push our getdata packet
  this._scheduleRequests();

  // Reset interval to avoid calling getblocks unnecessarily
  this._startInterval();

  // Reset timeout to avoid killing the loader
  this._startTimer();
};

Pool.prototype._handleInv = function _handleInv(hashes, peer) {
  var i, hash;

  // Ignore for now if we're still syncing
  if (!this.chain.isFull())
    return;

  for (i = 0; i < hashes.length; i++) {
    hash = utils.toHex(hashes[i]);
    if (!this.chain.has(hash)) {
      if (this.options.headers)
        this.peers.load.loadHeaders(this.chain.locatorHashes(), hash);
      else
        this._request(this.block.type, hash);
    }
  }

  if (!this.options.headers)
    this._scheduleRequests();
};

Pool.prototype._handleBlock = function _handleBlock(block, peer) {
  var self = this;

  var requested = this._response(block);

  // Emulate bip37 - emit all the "watched" txs
  if (this.options.fullNode && this.listeners('watched').length > 0) {
    block.txs.forEach(function(tx) {
      if (self.isWatched(tx))
        self.emit('watched', tx, peer);
    });
  }

  // Ignore if we already have
  if (this.chain.has(block)) {
    this.emit('debug', 'Already have block %s (%s)', block.height, peer.host);
    return false;
  }

  // Make sure the block is valid
  if (!block.verify()) {
    this.emit('debug',
      'Block verification failed for %s (%s)',
      block.rhash, peer.host);
    return false;
  }

  // Someone is sending us blocks without us requesting them.
  if (!requested) {
    this.emit('debug',
      'Recieved unrequested block: %s (%s)',
      block.rhash, peer.host);
  }

  // Resolve orphan chain
  if (!this.options.headers) {
    if (!this.chain.hasBlock(block.prevBlock)) {
      // NOTE: If we were to emit new orphans here, we
      // would not need to store full blocks as orphans.
      // However, the listener would not be able to see
      // the height until later.
      if (this._addIndex(block, peer))
        this.emit('pool block', block, peer);
      this.peers.load.loadBlocks(
        this.chain.locatorHashes(),
        this.chain.getOrphanRoot(block)
      );
      this.emit('debug', 'Handled orphan %s (%s)', block.rhash, peer.host);
      return false;
    }
  }

  // Add to index and emit/save
  if (this._addIndex(block, peer)) {
    this.emit('pool block', block, peer);
    return true;
  }
};

Pool.prototype._addIndex = function _addIndex(block, peer) {
  var added = this.chain.add(block, peer);

  this.emit('chain-progress', this.chain.fillPercent(), peer);

  return added > 0;
};

Pool.prototype.isFull = function isFull() {
  return this.chain.isFull();
};

Pool.prototype._loadRange = function _loadRange(hashes, force) {
  var now = +new Date();
  var last;

  if (this.options.fullNode)
    return;

  if (!hashes)
    return;

  if (hashes.length <= 1)
    return;

  // Limit number of requests
  if (!force && now - this.load.lastRange < this.load.rangeWindow)
    return;

  this.load.lastRange = now;

  if (!this.peers.load)
    this._addLoader();

  last = hashes[hashes.length - 1];

  hashes.slice(0, -1).forEach(function(hash) {
    this.peers.load.loadItems([hash], last);
  }, this);
};

Pool.prototype._load = function _load() {
  var self = this;
  var next;

  if (!this.syncing)
    return true;

  if (this.request.queue.length >= this.load.hwm) {
    this.load.hiReached = true;
    return false;
  }

  this.load.hiReached = false;

  if (!this.peers.load) {
    this._addLoader();
    return true;
  }

  if (this.options.headers)
    this.peers.load.loadHeaders(this.chain.locatorHashes(), null);
  else
    this.peers.load.loadBlocks(this.chain.locatorHashes(), null);

  return true;
};

Pool.prototype.loadMempool = function loadMempool() {
  this.pool.peers.block.forEach(function(peer) {
    peer.loadMempool();
  });
};

Pool.prototype._createPeer = function _createPeer(backoff) {
  var self = this;

  var peer = new bcoin.peer(this, this.createConnection, {
    backoff: backoff,
    startHeight: this.options.startHeight,
    relay: this.options.relay
  });

  peer._retry = 0;

  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.on('debug', function() {
    var args = Array.prototype.slice.call(arguments);
    self.emit.apply(self, ['debug'].concat(args));
  });

  peer.on('reject', function(payload) {
    payload.data = utils.revHex(utils.toHex(payload.data));

    self.emit('debug',
      'Reject: msg=%s ccode=%s reason=%s data=%s',
      payload.message,
      payload.ccode,
      payload.reason,
      payload.data);

    self.emit('reject', payload, peer);
  });

  peer.on('notfound', function(items) {
    items.forEach(function(item) {
      var req = self.request.map[utils.toHex(item.hash)];
      if (req && req.peer === peer)
        req.finish(null);
    });
  });

  peer.on('tx', function(tx) {
    self._response(tx);
    self.emit('tx', tx, peer);

    if (!self.options.fullNode && tx.block)
      self.emit('watched', tx, peer);
  });

  peer.on('addr', function(data) {
    if (self.seeds.length > 1000)
      self.setSeeds(self.options.seeds.concat(self.seeds.slice(-500)));

    self.addSeed(data);

    self.emit('addr', data, peer);
  });

  peer.on('txs', function(txs) {
    self.emit('txs', txs, peer);
  });

  peer.on('version', function(version) {
    if (version.height > self.block.bestHeight)
      self.block.bestHeight = version.height;
    self.emit('version', version, peer);
  });

  return peer;
};

Pool.prototype._addPeer = function _addPeer(backoff) {
  var self = this;
  var peer;

  if (this.destroyed)
    return;

  if (this.peers.block.length + this.peers.pending.length >= this.size)
    return;

  if (!this._createConnection && !this.usableSeed()) {
    setTimeout(this._addPeer.bind(this, 0), this.backoff.max);
    return;
  }

  peer = this._createPeer(backoff);

  this.peers.pending.push(peer);
  this.peers.all.push(peer);

  peer.once('close', function() {
    self._removePeer(peer);
    if (self.destroyed)
      return;
    self._addPeer(Math.min(backoff + self.backoff.delta, self.backoff.max));
  });

  peer.once('ack', function() {
    var i;

    if (self.destroyed)
      return;

    i = self.peers.pending.indexOf(peer);
    if (i !== -1) {
      self.peers.pending.splice(i, 1);
      self.peers.block.push(peer);
    }

    peer.updateWatch();

    self.inv.list.forEach(function(entry) {
      var result = peer.broadcast(entry.msg);
      if (!result)
        return;

      result[0].once('request', function() {
        entry.e.emit('ack', peer);
      });
    });

    self._scheduleRequests();
  });

  peer.on('merkleblock', function(block) {
    backoff = 0;
    self._handleBlock(block, peer);
  });

  peer.on('block', function(block) {
    backoff = 0;
    self._handleBlock(block, peer);
  });

  peer.on('blocks', function(hashes) {
    self._handleInv(hashes, peer);
  });

  utils.nextTick(function() {
    self.emit('peer', peer);
  });
};

Pool.prototype.bestPeer = function bestPeer() {
  return this.peers.block.reduce(function(best, peer) {
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

  i = this.peers.block.indexOf(peer);
  if (i !== -1)
    this.peers.block.splice(i, 1);

  i = this.peers.all.indexOf(peer);
  if (i !== -1)
    this.peers.all.splice(i, 1);

  if (this.peers.load === peer) {
    this.emit('debug', 'Removed loader peer (%s).', peer.host);
    this.peers.load = null;
  }
};

Pool.prototype.watch = function watch(id) {
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

  if (this.peers.load)
    this.peers.load.updateWatch();

  for (i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype.unwatch = function unwatch(id) {
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
  if (this.peers.load)
    this.peers.load.updateWatch();

  for (i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

// See "Filter matching algorithm":
// https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
Pool.prototype.isWatched = function(tx, bloom) {
  var i, input, output, prev;

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
    prev = input.out.hash;

    if (typeof prev === 'string')
      prev = utils.toArray(prev, 'hex');

    // Test the prev_out tx hash
    if (bloom.test(prev))
      return true;

    // Test the prev_out script
    if (input.out.tx) {
      prev = input.out.tx.outputs[input.out.index];
      if (testScript(prev.script))
        return true;
    }

    // Test the input script
    if (testScript(input.script))
      return true;
  }

  // 5. No match
  return false;
};

Pool.prototype.addWallet = function addWallet(w, defaultTs) {
  var self = this;
  var e;

  if (this.wallets.indexOf(w) !== -1)
    return false;

  this.watchWallet(w);
  this.wallets.push(w);

  e = new EventEmitter();

  function search(ts) {
    // Relay pending TXs
    // NOTE: It is important to do it after search, because search could
    // add TS to pending TXs, thus making them confirmed
    w.pending().forEach(function(tx) {
      self.sendTX(tx);
    });

    if (self.options.fullNode)
      return;

    // Search for last week by default
    if (!ts)
      ts = defaultTs || (utils.now() - 7 * 24 * 3600);

    // self.search(false, ts, e);
    self.searchWallet(ts);
  }

  if (w.loaded)
    search(w.lastTs);
  else
    w.once('load', function() { search(w.lastTs) });

  return e;
};

Pool.prototype.removeWallet = function removeWallet(w) {
  var i = this.wallets.indexOf(w);
  if (i == -1)
    return;
  this.wallets.splice(i, 1);
  this.unwatchWallet(w);
};

Pool.prototype.watchWallet = function watchWallet(w) {
  if (w.type === 'scripthash') {
    // For the redeem script hash in outputs:
    this.watch(w.getScriptHash());
    // For the redeem script in inputs:
    this.watch(w.getScript());
  }

  // For the pubkey hash in outputs:
  this.watch(w.getKeyHash());
  // For the pubkey in inputs:
  this.watch(w.getPublicKey());
};

Pool.prototype.unwatchWallet = function unwatchWallet(w) {
  if (w.type === 'scripthash') {
    // For the redeem script hash in p2sh outputs:
    this.unwatch(w.getScriptHash());
    // For the redeem script in p2sh inputs:
    this.unwatch(w.getScript());
  }

  // For the pubkey hash in p2pk/multisig outputs:
  this.unwatch(w.getKeyHash());
  // For the pubkey in p2pkh inputs:
  this.unwatch(w.getPublicKey());
};

Pool.prototype.searchWallet = function(w) {
  var self = this;
  var ts;

  if (this.options.fullNode)
    return;

  if (!w) {
    ts = this.wallets.reduce(function(ts, w) {
      if (w.lastTs < ts)
        return w.lastTs;
      return ts;
    }, Infinity);
    assert(ts !== Infinity);
  } else if (typeof w === 'number') {
    ts = w;
  } else {
    if (!w.loaded) {
      w.once('load', function() {
        self.searchWallet(w);
      });
      return;
    }
    ts = w.lastTs;
    if (!ts)
      ts = utils.now() - 7 * 24 * 3600;
  }

  utils.nextTick(function() {
    self.emit('debug', 'Wallet time: %s', new Date(ts * 1000));
    self.emit('debug',
      'Reverted chain to height=%d (%s)',
      self.chain.height(),
      new Date(self.chain.getTip().ts * 1000)
    );
  });

  this.chain.resetTime(ts);
};

Pool.prototype.search = function search(id, range, e) {
  var self = this;
  var hashes, pending, listener, timeout, done, total, cb;

  if (this.options.fullNode)
    return;

  if (typeof e === 'function') {
    cb = e;
    e = null;
  }

  e = e || new EventEmitter();

  // Optional id argument
  if ((id !== null
      && typeof id === 'object'
      && !utils.isBuffer(id))
      || typeof id === 'number') {
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

  // Last 5 days by default, this covers 1000 blocks that we have in the
  // chain by default
  if (!range.end)
    range.end = utils.now();
  if (!range.start)
    range.start = utils.now() - 432000;

  if (cb) {
    e.once('end', function(empty) {
      if (empty)
        return cb(new Error('Not found.'), false);
      return cb(null, true);
    });
  }

  if (range.start < this.chain.index.lastTs) {
    if (id)
      this.watch(id);

    done = function(empty) {
      e.emit('end', empty);
      clearInterval(timeout);
      self.removeListener('block', listener);
      if (id)
        self.unwatch(id);
    };

    this.on('block', listener = function(block) {
      if (block.ts >= range.end)
        done();
    });

    // Estimated number of blocks in time range
    total = (range.end - range.start) / network.powTargetSpacing | 0;

    if (total === 0)
      total = 1;

    // 500 blocks every 3 seconds
    total = (total / 500 | 0) * 3;

    // Add half the total time and convert to ms
    total = (total + Math.ceil(total / 2)) * 1000;

    timeout = setTimeout(done.bind(null, true), total);

    this.chain.resetTime(range.start);

    this.stopSync();

    if (this.peers.load)
      this.peers.load.destroy();

    this.startSync();

    return e;
  }

  hashes = this.chain.hashRange(range.start, range.end);
  pending = hashes.length;

  if (hashes.length === 0) {
    bcoin.utils.nextTick(function() {
      e.emit('end', true);
    });
    return e;
  }

  if (id)
    this.watch(id);

  done = function() {
    pending--;
    assert(pending >= 0);
    e.emit('progress', count - pending, count);
    if (pending === 0) {
      if (id)
        self.unwatch(id);
      e.emit('end');
    }
  };

  hashes.forEach(function(hash) {
    self._request('filtered', hash, { force: true }, done);
  });

  this._scheduleRequests();

  return e;
};

Pool.prototype._request = function _request(type, hash, options, cb) {
  var self = this;

  // Optional `force`
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  if (!options)
    options = {};

  hash = utils.toHex(hash);
  if (this.request.map[hash])
    return this.request.map[hash].addCallback(cb);

  function next(has) {
    if (has)
      return;

    if (self.destroyed)
      return;

    var req = new LoadRequest(self, type, hash, cb);
    req.add(options.noQueue);
  }

  // Block should be not in chain, or be requested
  // Do not use with headers-first
  if (!options.force && (type === 'block' || type === 'filtered'))
    return this.chain.has(hash, next);

  return next(false);
};

Pool.prototype._response = function _response(entity) {
  var req = this.request.map[entity.hash('hex')];
  if (!req)
    return false;
  req.finish(entity);
  return true;
};

Pool.prototype._scheduleRequests = function _scheduleRequests() {
  var self = this;

  if (this.destroyed)
    return;

  if (this.request.active > this.parallel / 2)
    return;

  // No need to wait - already have enough data
  if (this.request.queue.length > this.parallel) {
    if (this.load.timer !== null)
      clearTimeout(this.load.timer);
    this.load.timer = null;
    return this._doRequests();
  }

  // Already waiting
  if (this.load.timer !== null)
    return;

  this.load.timer = setTimeout(function() {
    self.load.timer = null;
    self._doRequests();
  }, this.load.window);
};

Pool.prototype._doRequests = function _doRequests() {
  var queue, above, items, below;
  var red, count, split, i, off, req, j;
  var mapReq;

  if (this.request.active >= this.parallel)
    return;

  // No peers so far
  if (this.peers.block.length === 0)
    return;

  queue = this.request.queue;
  above = queue.length >= this.load.lwm;
  items = queue.slice(0, this.parallel - this.request.active);
  this.request.queue = queue.slice(items.length);
  below = this.request.queue.length < this.load.lwm;

  // Watermark boundary crossed, load more blocks
  if (above && below && this.load.hiReached)
    this._load();

  if (items.length === 0)
    return;

  if (this.options.multiplePeers) {
    mapReq = function(item) {
      return item.start(this.peers.block[i]);
    };

    // Split list between peers
    red = this.redundancy;
    count = this.peers.block.length;
    split = Math.ceil(items.length * red / count);
    for (i = 0, off = 0; i < count; i += red, off += split) {
      req = items.slice(off, off + split).map(mapReq, this);
      for (j = 0; j < red && i + j < count; j++)
        this.peers.block[i + j].getData(req);
    }

    return;
  }

  req = items.map(function(item) {
    return item.start(this.peers.load);
  }, this);

  this.emit('debug',
    'Requesting %s/%s items from %s with getdata',
    req.length,
    this.request.queue.length,
    this.peers.load.host);

  this.peers.load.getData(req);
};

Pool.prototype.getBlock = function getBlock(hash, cb) {
  this._request('block', hash, { force: true }, function(block) {
    cb(null, block);
  });
  this._scheduleRequests();
};

Pool.prototype.sendBlock = function sendBlock(block) {
  return this.broadcast(block);
};

Pool.prototype.getTX = function getTX(hash, range, cb) {
  var self = this;
  var cbs, tx, finished, req, delta;

  if (this.options.fullNode)
    return cb(new Error('Cannot get tx with full node'));

  hash = utils.toHex(hash);

  if (typeof range === 'function') {
    cb = range;
    range = null;
  }

  // Do not perform duplicate searches
  if (this.validate.map[hash])
    return this.validate.map[hash].push(cb);

  cbs = [cb];
  this.validate.map[hash] = cbs;

  // Add request without queueing it to get notification at the time of load
  tx = null;
  finished = false;
  req = this._request('tx', hash, { noQueue: true }, function(t) {
    finished = true;
    tx = t;
  });

  // Do incremental search until the TX is found
  delta = this.validate.delta;

  // Start from the existing range if given
  if (range)
    range = { start: range.start, end: range.end };
  else
    range = { start: utils.now() - delta, end: 0 };

  function doSearch() {
    var e = self.search(hash, range);
    e.on('end', function(empty) {
      if (finished) {
        delete self.validate.map[hash];
        cbs.forEach(function(cb) {
          cb(null, tx, range);
        });
        return;
      }

      // Tried everything, but still no matches
      if (empty)
        return cb(new Error('Not found.'));

      // Not found yet, continue scanning
      range.end = range.start;
      range.start -= delta;
      if (range.start < 0)
        range.start = 0;

      doSearch();
    });
  }

  doSearch();
};

Pool.prototype.sendTX = function sendTX(tx) {
  // This is to avoid getting banned by
  // bitcoind nodes. Possibly check
  // sigops. Call isStandard and/or
  // isStandardInputs as well.
  if (tx.full()) {
    if (!tx.verify(null, true)) {
      this.emit('debug',
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

  this.peers.block.forEach(function(peer) {
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

  this.request.queue.slice().forEach(function(item) {
    item.finish(null);
  });

  this.inv.list.forEach(function(entry) {
    clearTimeout(entry.timer);
    entry.timer = null;
  });

  this.peers.pending.slice().forEach(function(peer) {
    peer.destroy();
  });

  this.peers.block.slice().forEach(function(peer) {
    peer.destroy();
  });

  if (this.load.timer)
    clearTimeout(this.load.timer);

  this.load.timer = null;
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

Pool.prototype.usableSeed = function usableSeed(addrs, force) {
  var i, addr;

  if (typeof addrs === 'boolean') {
    force = addrs;
    addrs = null;
  }

  if (!addrs)
    addrs = this.seeds;

  assert(addrs.length);

  if (this.peers.load) {
    addrs = addrs.slice().sort(function() {
      return Math.random() > 0.50 ? 1 : -1;
    });
    for (i = 0; i < addrs.length; i++) {
      if (!this.getPeer(addrs[i]))
        return addrs[i];
    }
  }

  if (addrs.length === 1)
    return addrs[0];

  if (!force)
    return;

  do {
    addr = addrs[Math.random() * (addrs.length - 1) | 0];
  } while (this.peers.load && this.getPeer(addr) === this.peers.load);

  return addr;
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

  this.hosts[seed.host] = this.seeds.length - 1;

  return true;
};

Pool.prototype.removeSeed = function removeSeed(seed) {
  seed = utils.parseHost(seed);

  if (this.hosts[seed.host] == null)
    return false;

  this.seeds.splice(this.hosts[seed.host], 1);

  delete this.hosts[seed.host];

  return true;
};

Pool.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'pool',
    chain: this.chain.toJSON(),
    requests: this.request.queue.map(function(item) {
      return {
        type: item.type,
        hash: item.hash
      };
    })
  };
};

Pool.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'pool');

  this.chain.fromJSON(json.chain);

  json.requests.forEach(function(item) {
    this._request(item.type, item.hash);
  }, this);

  return this;
};

function LoadRequest(pool, type, hash, cb) {
  var self = this;

  this.pool = pool;
  this.type = type;
  this.hash = hash;
  this.cbs = cb ? [cb] : [];
  this.timer = null;
  this.peer = null;
  this.ts = +new Date();
  this.active = false;
  this.noQueue = false;

  this.onclose = function onclose() {
    if (self.pool.destroyed)
      self.clear();
    else
      self.retry();
  };
}

LoadRequest.prototype.start = function start(peer) {
  var self = this;
  var reqType;

  assert(!this.active);
  assert(!this.timer);
  assert(!this.peer);

  this.active = true;
  this.pool.request.active++;

  // this.timer = setTimeout(function() {
  //   self.timer = null;
  //   self.retry();
  // }, this.pool.requestTimeout);

  this.peer = peer;
  this.peer.once('close', this.onclose);

  return {
    type: this.type,
    hash: this.hash
  };
};

LoadRequest.compare = function compare(a, b) {
  return a.ts - b.ts;
};

LoadRequest.prototype.add = function add(noQueue) {
  this.pool.request.map[this.hash] = this;
  if (!noQueue)
    this.pool.request.queue.push(this);
  else
    this.noQueue = true;
};

LoadRequest.prototype.clear = function clear() {
  assert(this.active);
  this.pool.request.active--;
  this.active = false;
  this.peer.removeListener('close', this.onclose);
  this.peer = null;
  clearTimeout(this.timer);
  this.timer = null;
};

LoadRequest.prototype.retry = function retry() {
  var peer = this.peer;

  // Put block into the queue, ensure that the queue is always sorted by ts
  utils.binaryInsert(this.pool.request.queue, this, LoadRequest.compare);

  this.clear();

  // Kill peer, if it misbehaves
  if (++peer._retry > this.pool.maxRetries)
    peer.destroy();

  // And schedule requesting blocks again
  this.pool._scheduleRequests();
};

LoadRequest.prototype.finish = function finish(entity) {
  var index;

  if (this.active) {
    this.clear();
  } else {
    // It could be that request was never sent to the node, remove it from
    // queue and forget about it
    index = this.pool.request.queue.indexOf(this);
    assert(index !== -1 || this.noQueue);
    if (!this.noQueue)
      this.pool.request.queue.splice(index, 1);
    assert(!this.peer);
    assert(!this.timer);
  }
  delete this.pool.request.map[this.hash];

  // We may have some free slots in queue now
  this.pool._scheduleRequests();

  this.cbs.forEach(function(cb) {
    cb(entity);
  });
};

LoadRequest.prototype.addCallback = function addCallback(cb) {
  if (cb)
    this.cbs.push(cb);
};

/**
 * Expose
 */

module.exports = Pool;
