var assert = require('assert');
var async = require('async');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  EventEmitter.call(this);

  this.options = options || {};
  this.size = options.size || 3;
  this.parallel = options.parallel || 2000;
  this.load = {
    timeout: options.loadTimeout || 10000,
    window: options.loadWindow || 250,
    timer: null,
    lwm: options.lwm || this.parallel * 2,
    hwm: options.hwm || this.parallel * 8,
    hiReached: false
  };
  this.maxRetries = options.maxRetries || 300;
  this.requestTimeout = options.requestTimeout || 10000;
  this.chain = new bcoin.chain();
  this.watchList = [];
  this.bloom = new bcoin.bloom(8 * 10 * 1024,
                               10,
                               (Math.random() * 0xffffffff) | 0),
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
    minDepth: options.minValidateDepth || 1,

    // getTx map
    map: {},

    // Validation cache
    cache: [],
    cacheSize: 1000
  };

  this.createConnection = options.createConnection;
  assert(this.createConnection);

  this._init();
}
util.inherits(Pool, EventEmitter);
module.exports = Pool;

Pool.prototype._init = function _init() {
  this._addLoader();
  for (var i = 0; i < this.size; i++)
    this._addPeer();

  var self = this;
  this.chain.on('missing', function(hash, range) {
    self._request('block', hash, { force: true });
    self._scheduleRequests();
    self._loadRange(range);
  });

  setInterval(function() {
    console.log('a %d q %d o %d r %d',
                self.request.active, self.request.queue.length,
                self.chain.orphan.count,
                self.chain.request.count);
    if (self.chain.request.count === 1)
      console.log(Object.keys(self.chain.request.map));
  }, 1000);
};

Pool.prototype._addLoader = function _addLoader() {
  if (this.peers.load !== null)
    return;

  var socket = this.createConnection();
  var peer = bcoin.peer(this, socket, this.options.peer);
  this.peers.load = peer;

  var self = this;
  peer.once('error', function() {
    // Just ignore, it will result in `close` anyway
  });

  peer.once('close', onclose);
  function onclose() {
    clearTimeout(timer);
    self._removePeer(peer);
    self._addLoader();
  };

  peer.once('ack', function() {
    peer.updateWatch();
    if (!self._load())
      clearTimeout(timer);
  });

  function destroy() {
    // Chain is full and up-to-date
    if (self.block.lastHash === null && self.chain.isFull()) {
      clearTimeout(timer);
      peer.removeListener('close', onclose);
      self._removePeer(peer);
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

    // Store last hash to continue global load
    self._lastHash = hashes[hashes.length - 1];

    clearTimeout(timer);

    // Reinstantiate timeout
    if (self._load())
      timer = setTimeout(destroy, self.load.timeout);
  });
};

Pool.prototype._loadRange = function _loadRange(range) {
  if (!range)
    return;

  // We will be requesting block anyway
  if (range.start === range.end)
    return;

  if (!this.peers.load)
    this._addLoader();
  this.peers.load.loadBlocks(range.start, range.end);
};

Pool.prototype._load = function _load() {
  if (this.request.queue.length >= this.load.hwm) {
    this.load.hiReached = true;
    return false;
  }
  this.load.hiReached = false;

  // Load more blocks, starting from last hash
  var hash;
  if (this.block.lastHash)
    hash = this.block.lastHash;
  else
    hash = this.chain.getLast();

  if (!this.peers.load)
    this._addLoader();
  else
    this.peers.load.loadBlocks(hash);

  return true;
};

Pool.prototype._addPeer = function _addPeer() {
  if (this.peers.block.length + this.peers.pending.length >= this.size)
    return;

  var socket = this.createConnection();
  var peer = bcoin.peer(this, socket, this.options.peer);
  this.peers.pending.push(peer);

  peer._retry = 0;

  // Create new peer on failure
  var self = this;
  peer.once('error', function(err) {
    // Just ignore, it will result in `close` anyway
  });

  peer.once('close', function() {
    self._removePeer(peer);
    self._addPeer();
  });

  peer.once('ack', function() {
    var i = self.peers.pending.indexOf(peer);
    if (i !== -1) {
      self.peers.pending.splice(i, 1);
      self.peers.block.push(peer);
    }

    peer.updateWatch();
  });

  peer.on('merkleblock', function(block) {
    self.chain.add(block);
    self._response(block);
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
    self.emit('tx', tx);
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
  if (this.bloom.test(id, 'hex'))
    return;

  this.watchList.push(utils.toHex(id));
  if (id)
    this.bloom.add(id, 'hex');
  if (this.peers.load)
    this.peers.load.updateWatch();
  for (var i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype.unwatch = function unwatch(id) {
  if (!this.bloom.test(id, 'hex'))
    return;

  id = utils.toHex(id);
  var index = this.watchList.indexOf(id);
  if (index === -1)
    return;
  this.watchList.splice(index, 1);

  // Reset bloom filter
  this.bloom.reset();
  for (var i = 0; i < this.watchList.length; i++)
    this.bloom.add(this.watchList[i], 'hex');

  // Resend it to peers
  if (this.peers.load)
    this.peers.load.updateWatch();
  for (var i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype.search = function search(id, range) {
  if (typeof id === 'string')
    id = utils.toArray(id, 'hex');

  if (range)
    range = { start: range.start, end: range.end };
  else
    range = { start: 0, end: 0 };

  // Last 5 days by default, this covers 1000 blocks that we have in the
  // chain by default
  if (!range.end)
    range.end = +new Date / 1000;
  if (!range.start)
    range.start = +new Date / 1000 - 432000;

  var self = this;
  var e = new EventEmitter();
  var hashes = this.chain.hashesInRange(range.start, range.end);
  var waiting = hashes.length;

  this.watch(id);

  hashes.slice().reverse().forEach(function(hash) {
    // Get the block that is in index
    this.chain.get(hash, function(block) {
      // Get block's prev and request it and all of it's parents up to
      // the next known block hash
      self.chain.get(block.prevBlock, function() {
        waiting--;
        e.emit('progress', hashes.length - waiting, hashes.length);
        if (waiting === 0) {
          self.unwatch(id);
          e.emit('end');
        }
      });
    });
  }, this);

  // Empty search
  if (hashes.length === 0) {
    process.nextTick(function() {
      e.emit('end', true);
    });
  }

  return e;
};

Pool.prototype._request = function _request(type, hash, options, cb) {
  if (typeof hash === 'string')
    hash = utils.toArray(hash, 'hex');

  // Optional `force`
  if (typeof options === 'function') {
    cb = options;
    options = {};
  }
  if (!options)
    options = {};

  var hex = utils.toHex(hash);
  if (this.request.map[hex])
    return this.request.map[hex].addCallback(cb);

  // Block should be not in chain, or be requested
  if (!options.force && type === 'block' && this.chain.has(hash))
    return;

  var req = new LoadRequest(this, type, hex, cb);
  req.add(options.noQueue);
};

Pool.prototype._response = function _response(entity) {
  var req = this.request.map[entity.hash('hex')];
  if (!req)
    return;
  req.finish(entity);
};

Pool.prototype._scheduleRequests = function _scheduleRequests() {
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

  // Split list between nodes
  var count = this.peers.block.length;
  var split = Math.ceil(items.length / count);
  for (var i = 0, off = 0; i < count; i++, off += split) {
    var peer = this.peers.block[i];
    peer.getData(items.slice(off, off + split).map(function(item) {
      return item.start(peer);
    }));
  }
};

Pool.prototype.getTx = function getTx(hash, range, cb) {
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
    range = { start: (+new Date / 1000) - delta, end: 0 };

  var self = this;
  doSearch();

  function doSearch() {
    console.log('Searching for ' + hash, range);
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

Pool.prototype._addValidateCache = function addValidateCache(tx, result) {
  this.validate.cache.push({
    hash: tx.hash('hex'),
    result: result
  });
  if (this.validate.cache.length > this.validate.cacheSize)
    this.validate.cache = this.validate.cache.slice(-this.validate.cacheSize);
};

Pool.prototype._probeValidateCache = function probeValidateCache(tx) {
  for (var i = 0; i < this.validate.cache.length; i++) {
    var entry = this.validate.cache[i];
    if (entry.hash === tx.hash('hex'))
      return entry.result;
  }
};

Pool.prototype.validateTx = function validateTx(tx, cb, _params) {
  // Probe cache first
  var result = this._probeValidateCache(tx);
  if (result) {
    process.nextTick(function() {
      cb(null, result);
    });
    return;
  }

  if (!_params)
    _params = { depth: 0, range: null };

  // Propagate range to improve speed of search
  var depth = _params.depth;
  var range = _params.range;

  var result = {
    included: this.chain.hasMerkle(tx.hash()),
    valid: false
  };

  console.log('validateTx: ', tx.hash('hex'), depth);
  if (depth > this.validate.minDepth && result.included) {
    result.valid = true;
    process.nextTick(function() {
      cb(null, result);
    });
    return;
  }

  // Load all inputs and validate them
  var self = this;
  async.map(tx.inputs, function(input, cb) {
    var out = null;
    console.log('load input: ', input.out.hash);
    self.getTx(input.out.hash, range, function(t, range) {
      console.log('got input for: ', tx.hash('hex'), !!t);
      out = t;
      self.validateTx(out, onSubvalidate, {
        depth: depth + 1,
        range: range
      });
    });

    function onSubvalidate(err, subres) {
      if (err)
        return cb(err);

      cb(null, {
        input: input,
        tx: out,
        valid: subres.valid
      });
    }
  }, function(err, inputs) {
    if (err) {
      result.valid = false;
      return cb(err, result);
    }

    self._addValidateCache(tx, result);
    console.log(inputs);
  });
};

function LoadRequest(pool, type, hash, cb) {
  this.pool = pool
  this.type = type;
  this.hash = hash;
  this.cbs = cb ? [ cb ] : [];
  this.timer = null;
  this.peer = null;
  this.ts = +new Date;
  this.active = false;

  var self = this;
  this.onclose = function onclose() {
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
    if (index !== -1)
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
