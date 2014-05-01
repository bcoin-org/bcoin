var assert = require('assert');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  this.options = options || {};
  this.size = options.size || 16;
  this.parallel = options.parallel || 8000;
  this.loadTimeout = options.loadTimeout || 10000;
  this.loadWindow = options.loadWindow || 2500;
  this.loadTimer = null;
  this.loadWatermark = {
    lo: options.lwm || 1000,
    hi: options.hwm || 32000
  };
  this.maxRetries = options.maxRetries || 1000;
  this.requestTimeout = options.requestTimeout || 15000;
  this.chain = new bcoin.chain();
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
    lastSeen: null,
    queue: [],
    active: 0,
    requests: {}
  };

  this.createConnection = options.createConnection;
  assert(this.createConnection);

  this._init();

  var self = this;
  setInterval(function() {
    console.log('clen %d ocnt %d active %d queue %d reqs %d mem %d',
                self.chain.chain.length, self.chain.orphan.count,
                self.block.active,
                self.block.queue.length,
                Object.keys(self.block.requests).length,
                process.memoryUsage().heapUsed);
  }, 5000);
}
module.exports = Pool;

Pool.prototype._init = function _init() {
  this._addLoader();
  for (var i = 0; i < this.size; i++)
    this._addPeer();
};

Pool.prototype._addLoader = function _addLoader() {
  assert(this.peers.load === null);
  var socket = this.createConnection();
  var peer = bcoin.peer(this, socket, this.options.peer);
  this.peers.load = peer;

  var self = this;
  peer.once('error', function() {
    // Just ignore, it will result in `close` anyway
  });

  peer.once('close', function() {
    clearTimeout(timer);
    self._removePeer(peer);
    self._addLoader();
  });

  peer.once('ack', function() {
    peer.updateWatch();
    if (!self._load())
      clearTimeout(timer);
  });

  function destroy() {
    peer.destroy();
  }
  var timer = setTimeout(destroy, this.loadTimeout);

  // Split blocks and request them using multiple peers
  peer.on('blocks', function(hashes) {
    if (hashes.length === 0) {
      self.block.lastSeen = null;
      return;
    }

    // Request each block
    hashes.forEach(function(hash) {
      self._requestBlock(hash);
    });

    self._scheduleRequests();

    self.block.lastSeen = hashes[hashes.length - 1];

    clearTimeout(timer);
    // Reinstantiate timeout
    if (self._load())
      timer = setTimeout(destroy, self.loadTimeout);
  });
};

Pool.prototype._load = function load() {
  if (this.block.queue.length >= this.loadWatermark.hi)
    return false;

  // Load more blocks, starting from last hash
  var hash;
  if (this.block.lastSeen) {
    hash = this.block.lastSeen;
    console.log('Loading from (last): '  + utils.toHex(hash.slice().reverse()));
  } else {
    hash = this.chain.getLast().hash();
    console.log('Loading from (chain): '  + utils.toHex(hash.slice().reverse()));
  }

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
    var req = self.block.requests[block.hash('hex')];
    if (!req)
      return;
    req.finish(block);
  });

  peer.on('notfound', function(items) {
    items.forEach(function(item) {
      if (item.type !== 'filtered')
        return;

      var req = self.block.requests[utils.toHex(item.hash)];
      console.log('notfound', !!req);
      if (req)
        req.finish(null);
    });
  });

  peer.on('tx', function(tx) {
    console.log('got tx', tx.hash('hex'));
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
  if (id)
    this.bloom.add(id);
  for (var i = 0; i < this.peers.block.length; i++)
    this.peers.block[i].updateWatch();
};

Pool.prototype._requestBlock = function _requestBlock(hash) {
  // Block is already in chain, or being requested
  if (this.chain.has(hash) || this.block.requests[utils.toHex(hash)])
    return;

  var req = new BlockRequest(this, hash);
  this.block.requests[utils.toHex(hash)] = req;
  this.block.queue.push(req);
};

Pool.prototype._scheduleRequests = function _scheduleRequests() {
  if (this.block.active > 100)
    return;

  // No need to wait - already have enough data
  if (this.block.queue.length > this.parallel) {
    if (this.loadTimer !== null)
      clearTimeout(this.loadTimer);
    this.loadTimer = null;
    return this._doRequests();
  }

  // Already waiting
  if (this.loadTimer !== null)
    return;

  var self = this;
  this.loadTimer = setTimeout(function() {
    self.loadTimer = null;
    self._doRequests();
  }, this.loadWindow);
};

Pool.prototype._doRequests = function _doRequests() {
  if (this.block.active >= this.parallel)
    return;

  var above = this.block.queue.length >= this.loadWatermark.lo;
  var items = this.block.queue.slice(0, this.parallel - this.block.active);
  this.block.queue = this.block.queue.slice(items.length);
  var below = this.block.queue.length < this.loadWatermark.lo;

  // Watermark boundary crossed, load more blocks
  if (above && below)
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

function BlockRequest(pool, hash) {
  this.pool = pool
  this.hash = hash;
  this.timer = null;
  this.peer = null;
  this.ts = +new Date;
  this.active = false;
}

function binaryInsert(list, item, compare) {
  var start = 0,
      end = list.length;

  while (start < end) {
    var pos = (start + end) >> 1;
    var cmp = compare(item, list[pos]);

    if (cmp === 0) {
      start = pos;
      end = pos;
      break;
    } else if (cmp < 0) {
      end = pos;
    } else {
      start = pos + 1;
    }
  }

  list.splice(start, 0, item);
}

BlockRequest.prototype.start = function start(peer) {
  var self = this;

  this.peer = peer;
  if (this.timer)
    clearTimeout(this.timer);
  this.timer = setTimeout(function() {
    self.timer = null;
    self.retry();
  }, this.pool.requestTimeout);

  if (!this.active)
    this.pool.block.active++;
  this.active = true;

  return {
    type: 'filtered',
    hash: this.hash
  };
};

BlockRequest.compare = function compare(a, b) {
  return a.ts - b.ts;
};

BlockRequest.prototype.retry = function retry() {
  assert(this.active);
  this.pool.block.active--;

  // Put block into the queue, ensure that the queue is always sorted by ts
  binaryInsert(this.pool.block.queue, this, BlockRequest.compare);
  this.active = false;

  // And schedule requesting blocks again
  this.pool._scheduleRequests();

  // Kill peer, if it misbehaves
  if (++this.peer._retry > this.pool._maxRetries)
    this.peer.destroy();
};

BlockRequest.prototype.finish = function finish() {
  if (this.active) {
    this.pool.block.active--;
    this.active = false;
  } else {
    // It could be that request was never sent to the node, remove it from
    // queue and forget about it
    var index = this.pool.block.queue.indexOf(this);
    if (index !== -1)
      this.pool.block.queue.splice(index, 1);
  }
  delete this.pool.block.requests[utils.toHex(this.hash)];
  if (this.timer)
    clearTimeout(this.timer);
  this.timer = null;

  // We may have some free slots in queue now
  this.pool._scheduleRequests();
};
