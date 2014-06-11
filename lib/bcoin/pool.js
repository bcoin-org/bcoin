var async = require('async');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  EventEmitter.call(this);

  this.options = options || {};
  this.options.relay = this.options.relay !== false;
  this.storage = this.options.storage;
  this.destroyed = false;
  this.size = options.size || 32;
  this.parallel = options.parallel || 2000;
  this.redundancy = options.redundancy || 2;
  this.backoff = {
    delta: options.backoffDelta || 500,
    max: options.backoffMax || 5000
  };
  this.load = {
    timeout: options.loadTimeout || 3000,
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
    // Since regular blocks contain transactions and full merkle
    // trees, it's risky to cache 2000 blocks. Let's do 100.
    cacheLimit: !this.options.relay ? 100 : null
  });
  this.watchMap = {};
  this.bloom = new bcoin.bloom(8 * 1024,
                               10,
                               (Math.random() * 0xffffffff) | 0);
  this.peers = {
    // Peers that are loading blocks themselves
    block: [],
    // Peers that are still connecting
    pending: [],
    // Peers that are loading block ids
    load: null
  };
  this.block = {
    lastHash: null
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
  this.tx = {
    list: [],
    timeout: options.txTimeout || 60000
  };

  // Added and watched wallets
  this.wallets = [];

  this.createConnection = options.createConnection;
  assert(this.createConnection);

  this._init();
}
inherits(Pool, EventEmitter);
module.exports = Pool;

Pool.prototype._init = function _init() {
  this._addLoader();
  for (var i = 0; i < this.size; i++)
    this._addPeer(0);
  this._load();

  var self = this;
  this.chain.on('missing', function(hash, preload, parent) {
    self._request('block', hash, { force: true });
    self._scheduleRequests();
    self._loadRange(preload);
  });
};

Pool.prototype._addLoader = function _addLoader() {
  if (this.destroyed)
    return;
  if (this.peers.load !== null)
    return;

  var peer = new bcoin.peer(this, this.createConnection, {
    backoff: 750 * Math.random(),
    startHeight: this.options.startHeight,
    relay: this.options.relay
  });
  this.peers.load = peer;

  var self = this;
  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.once('close', onclose);
  function onclose() {
    clearTimeout(timer);
    clearInterval(interval);
    self._removePeer(peer);
    if (self.destroyed)
      return;
    self._addLoader();
  }

  var interval = setInterval(function() {
    self._load();
  }, this.load.interval);

  peer.once('ack', function() {
    peer.updateWatch();
    if (!self._load())
      clearTimeout(timer);
  });

  function destroy() {
    // Chain is full and up-to-date
    if (self.chain.isFull()) {
      clearTimeout(timer);
      self.emit('full');
      self.block.lastHash = null;
      return;
    }

    peer.destroy();
  }
  var timer = setTimeout(destroy, this.load.timeout);

  // Split blocks and request them using multiple peers
  peer.on('blocks', function(hashes) {
    if (hashes.length === 0) {
      // Reset global load
      self.block.lastHash = null;
      return;
    }

    // Request each block
    hashes.forEach(function(hash) {
      self._request('block', hash);
    });

    self._scheduleRequests();

    // The part of the response is in chain, no need to escalate requests
    async.every(hashes, function(hash, cb) {
      self.chain.has(utils.toHex(hash), function(res) {
        cb(!res);
      });
    }, function(allNew) {
      if (!allNew) {
        self.block.lastHash = null;
        return;
      }

      // Store last hash to continue global load
      self.block.lastHash = hashes[hashes.length - 1];

      clearTimeout(timer);

      // Reinstantiate timeout
      if (self._load())
        timer = setTimeout(destroy, self.load.timeout);
    });
  });
};

Pool.prototype.isFull = function isFull() {
  return this.chain.isFull();
};

Pool.prototype._loadRange = function _loadRange(hashes, force) {
  if (!hashes)
    return;

  if (hashes.length <= 1)
    return;

  // Limit number of requests
  var now = +new Date();
  if (!force && now - this.load.lastRange < this.load.rangeWindow)
    return;
  this.load.lastRange = now;

  if (!this.peers.load)
    this._addLoader();

  var last = hashes[hashes.length - 1];
  hashes.slice(0, -1).forEach(function(hash) {
    this.peers.load.loadBlocks([ hash ], last);
  }, this);
};

Pool.prototype._load = function _load() {
  if (this.request.queue.length >= this.load.hwm) {
    this.load.hiReached = true;
    return false;
  }
  this.load.hiReached = false;
  var self = this;

  // Load more blocks, starting from last hash
  if (this.block.lastHash)
    next(this.block.lastHash);
  else
    this.chain.getLast(next);

  function next(hash) {
    if (!self.peers.load)
      self._addLoader();
    else
      self.peers.load.loadBlocks([ hash ]);
  }

  return true;
};

Pool.prototype._addPeer = function _addPeer(backoff) {
  if (this.destroyed)
    return;
  if (this.peers.block.length + this.peers.pending.length >= this.size)
    return;

  var peer = new bcoin.peer(this, this.createConnection, {
    backoff: backoff,
    startHeight: this.options.startHeight,
    relay: this.options.relay
  });

  this.peers.pending.push(peer);

  peer._retry = 0;

  // Create new peer on failure
  var self = this;
  peer.on('error', function(err) {
    self.emit('error', err, peer);
  });

  peer.once('close', function() {
    self._removePeer(peer);
    if (self.destroyed)
      return;
    self._addPeer(Math.max(backoff + self.backoff.delta, self.backoff.max));
  });

  peer.once('ack', function() {
    if (self.destroyed)
      return;

    var i = self.peers.pending.indexOf(peer);
    if (i !== -1) {
      self.peers.pending.splice(i, 1);
      self.peers.block.push(peer);
    }

    peer.updateWatch();

    self.tx.list.forEach(function(entry) {
      var result = peer.broadcast(entry.tx);
      if (!result) return;
      result[0].once('request', function() {
        entry.e.emit('ack');
      });
    });

    self._scheduleRequests();
  });

  peer.on('merkleblock', function(block) {
    // Reset backoff, peer seems to be responsive
    backoff = 0;

    self._response(block);
    self.chain.add(block);
    self.emit('chain-progress', self.chain.fillPercent(), peer);
    self.emit('block', block, peer);
  });

  if (!this.options.relay) {
    peer.on('block', function(block) {
      peer.emit('merkleblock', block);
    });
  }

  // Just FYI
  peer.on('reject', function(payload) {
    self.emit('reject', payload, peer);
  });

  peer.on('notfound', function(items) {
    items.forEach(function(item) {
      var req = self.request.map[utils.toHex(item.hash)];
      if (req)
        req.finish(null);
    });
  });

  peer.on('tx', function(tx) {
    self._response(tx);
    self.emit('tx', tx, peer);
  });

  peer.on('addr', function(addr) {
    self.emit('addr', addr, peer);
  });

  peer.on('blocks', function(blocks) {
    self.emit('blocks', blocks, peer);
  });

  peer.on('txs', function(txs) {
    self.emit('txs', txs, peer);
  });

  peer.on('version', function(version) {
    self.emit('version', version, peer);
  });

  utils.nextTick(function() {
    self.emit('peer', peer);
  });
};

Pool.prototype._removePeer = function _removePeer(peer) {
  var i = this.peers.pending.indexOf(peer);
  if (i !== -1)
    this.peers.pending.splice(i, 1);

  i = this.peers.block.indexOf(peer);
  if (i !== -1)
    this.peers.block.splice(i, 1);

  if (this.peers.load === peer)
    this.peers.load = null;
};

Pool.prototype.watch = function watch(id) {
  if (id instanceof bcoin.wallet) {
    this.watch(id.getAddress());
    this.watch(id.getPublicKey());
    return;
  }

  if (id) {
    var hid = utils.toHex(id);
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
  for (var i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype.unwatch = function unwatch(id) {
  if (!this.bloom.test(id, 'hex'))
    return;

  id = utils.toHex(id);
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
  for (var i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype.addWallet = function addWallet(w, defaultTs) {
  if (this.wallets.indexOf(w) !== -1)
    return false;
  this.watch(w.getHash());
  this.watch(w.getPublicKey());

  var self = this;
  var e = new EventEmitter();
  if (w.loaded)
    search(w.lastTs);
  else
    w.once('load', function(lastTs) { search(w.lastTs) });

  function search(ts) {
    // Relay pending TXs
    // NOTE: It is important to do it after search, because search could
    // add TS to pending TXs, thus making them confirmed
    w.pending().forEach(function(tx) {
      self.sendTX(tx);
    });

    // Search for last week by default
    if (!ts)
      ts = defaultTs || ((+new Date / 1000) - 7 * 24 * 3600);
    self.search(false, ts, e);
  }

  return e;
}

Pool.prototype.removeWallet = function removeWallet(w) {
  var i = this.wallets.indexOf(w);
  if (i == -1)
    return;
  this.wallets.splice(i, 1);
  this.unwatch(w.getHash());
  this.unwatch(w.getPublicKey());
}

Pool.prototype.search = function search(id, range, e) {
  e = e || new EventEmitter();

  // Optional id argument
  if (id !== null &&
        typeof id === 'object' &&
        !Array.isArray(id) ||
      typeof id === 'number') {
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
    range.end = +new Date() / 1000;
  if (!range.start)
    range.start = +new Date() / 1000 - 432000;

  var self = this;
  this.chain.hashesInRange(range.start, range.end, function(hashes, count) {
    var waiting = count;

    if (id)
      self.watch(id);

    self._loadRange(hashes, true);
    hashes = hashes.slice().reverse();
    hashes.forEach(function(hash, i) {
      // Get the block that is in index
      self.chain.get(hash, true, function(block) {
        loadBlock(block, hashes[i + 1]);
      });
    });

    function loadBlock(block, stop) {
      // Stop block reached
      if (block.hash('hex') === stop)
        return;

      // Get block's prev and request it and all of it's parents up to
      // the next known block hash
      self.chain.get(block.prevBlock, block.prevBlock !== stop, function(prev) {
        done();

        // First hash loaded
        if (!stop)
          return;

        // Continue loading blocks
        loadBlock(prev, stop);
      });
    }

    function done() {
      waiting--;
      assert(waiting >= 0);
      e.emit('progress', count - waiting, count);
      if (waiting === 0) {
        if (id)
          self.unwatch(id);
        e.emit('end');
      }
    }

    // Empty search
    if (hashes.length === 0) {
      bcoin.utils.nextTick(function() {
        e.emit('end', true);
      });
    }
  });

  return e;
};

Pool.prototype._request = function _request(type, hash, options, cb) {
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

  var self = this;

  // Block should be not in chain, or be requested
  if (!options.force && type === 'block')
    return this.chain.has(hash, true, next);
  else
    return next(false);

  function next(has) {
    if (has)
      return;

    if (self.destroyed)
      return;

    var req = new LoadRequest(self, type, hash, cb);
    req.add(options.noQueue);
  }
};

Pool.prototype._response = function _response(entity) {
  var req = this.request.map[entity.hash('hex')];
  if (!req)
    return false;
  req.finish(entity);
  return true;
};

Pool.prototype._scheduleRequests = function _scheduleRequests() {
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

  var self = this;
  this.load.timer = setTimeout(function() {
    self.load.timer = null;
    self._doRequests();
  }, this.load.window);
};

Pool.prototype._doRequests = function _doRequests() {
  if (this.request.active >= this.parallel)
    return;

  // No peers so far
  if (this.peers.block.length === 0)
    return;

  var queue = this.request.queue;
  var above = queue.length >= this.load.lwm;
  var items = queue.slice(0, this.parallel - this.request.active);
  this.request.queue = queue.slice(items.length);
  var below = this.request.queue.length < this.load.lwm;

  // Watermark boundary crossed, load more blocks
  if (above && below && this.load.hiReached)
    this._load();

  function mapReq(item) {
    return item.start(this.peers.block[i]);
  }

  // Split list between peers
  var red = this.redundancy;
  var count = this.peers.block.length;
  var split = Math.ceil(items.length * red / count);
  for (var i = 0, off = 0; i < count; i += red, off += split) {
    var req = items.slice(off, off + split).map(mapReq, this);

    for (var j = 0; j < red && i + j < count; j++) {
      this.peers.block[i + j].getData(req);
    }
  }
};

Pool.prototype.getTX = function getTX(hash, range, cb) {
  hash = utils.toHex(hash);

  if (typeof range === 'function') {
    cb = range;
    range = null;
  }

  // Do not perform duplicate searches
  if (this.validate.map[hash])
    return this.validate.map[hash].push(cb);
  var cbs = [ cb ];
  this.validate.map[hash] = cbs;

  // Add request without queueing it to get notification at the time of load
  var tx = null;
  var finished = false;
  var req = this._request('tx', hash, { noQueue: true }, function(t) {
    finished = true;
    tx = t;
  });

  // Do incremental search until the TX is found
  var delta = this.validate.delta;

  // Start from the existing range if given
  if (range)
    range = { start: range.start, end: range.end };
  else
    range = { start: (+new Date() / 1000) - delta, end: 0 };

  var self = this;
  doSearch();

  function doSearch() {
    var e = self.search(hash, range);
    e.on('end', function(empty) {
      if (finished) {
        delete self.validate.map[hash];
        cbs.forEach(function(cb) {
          cb(tx, range);
        });
        return;
      }

      // Tried everything, but still no matches
      if (empty)
        return cb(null);

      // Not found yet, continue scanning
      range.end = range.start;
      range.start -= delta;
      if (range.start < 0)
        range.start = 0;

      doSearch();
    });
  }
};

Pool.prototype.sendTX = function sendTX(tx) {
  var e = new EventEmitter();

  var self = this;
  var entry = {
    tx: tx,
    e: e,
    timer: setTimeout(function() {
      var i = self.tx.list.indexOf(entry);
      if (i !== -1)
        self.tx.list.splice(i, 1);
    }, this.tx.timeout)
  };
  this.tx.list.push(entry);

  this.peers.block.forEach(function(peer) {
    var result = peer.broadcast(tx);
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
  this.tx.list.forEach(function(tx) {
    clearTimeout(tx.timer);
    tx.timer = null;
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

Pool.prototype.toJSON = function toJSON() {
  return {
    v: 1,
    type: 'pool',
    chain: this.chain.toJSON()
  };
};

Pool.prototype.fromJSON = function fromJSON(json) {
  assert.equal(json.v, 1);
  assert.equal(json.type, 'pool');
  this.chain.fromJSON(json.chain);

  return this;
};

function LoadRequest(pool, type, hash, cb) {
  this.pool = pool;
  this.type = type;
  this.hash = hash;
  this.cbs = cb ? [ cb ] : [];
  this.timer = null;
  this.peer = null;
  this.ts = +new Date();
  this.active = false;
  this.noQueue = false;

  var self = this;
  this.onclose = function onclose() {
    if (self.pool.destroyed)
      self.clear();
    else
      self.retry();
  };
}

LoadRequest.prototype.start = function start(peer) {
  var self = this;
  assert(!this.active);

  this.active = true;
  this.pool.request.active++;

  assert(!this.timer);
  this.timer = setTimeout(function() {
    self.timer = null;
    self.retry();
  }, this.pool.requestTimeout);

  assert(!this.peer);
  this.peer = peer;
  this.peer.once('close', this.onclose);

  var reqType;
  if (this.type === 'block')
    reqType = 'filtered';
  else if (this.type === 'tx')
    reqType = 'tx';

  return {
    type: reqType,
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
  // Put block into the queue, ensure that the queue is always sorted by ts
  utils.binaryInsert(this.pool.request.queue, this, LoadRequest.compare);
  var peer = this.peer;
  this.clear();

  // Kill peer, if it misbehaves
  if (++peer._retry > this.pool.maxRetries)
    peer.destroy();

  // And schedule requesting blocks again
  this.pool._scheduleRequests();
};

LoadRequest.prototype.finish = function finish(entity) {
  if (this.active) {
    this.clear();
  } else {
    // It could be that request was never sent to the node, remove it from
    // queue and forget about it
    var index = this.pool.request.queue.indexOf(this);
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
