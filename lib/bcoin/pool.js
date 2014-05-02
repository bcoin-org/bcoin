var assert = require('assert');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  this.options = options || {};
  this.size = options.size || 64;
  this.parallel = options.parallel || 8000;
  this.load = {
    timeout: options.loadTimeout || 5000,
    window: options.loadWindow || 2500,
    timer: null,
    lwm: options.lwm || this.parallel * 2,
    hwm: options.hwm || this.parallel * 8,
    hiReached: false
  };
  this.maxRetries = options.maxRetries || 50;
  this.requestTimeout = options.requestTimeout || 10000;
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
  this.finished = 0;

  this.createConnection = options.createConnection;
  assert(this.createConnection);

  this._init();

  var self = this;
  setInterval(function() {
    console.log('clen %d ocnt %d active %d queue %d reqs %d mem %d d %d',
                self.chain.ts.length, self.chain.orphan.count,
                self.block.active,
                self.block.queue.length,
                Object.keys(self.block.requests).length,
                process.memoryUsage().heapUsed,
                self.finished - self.chain.ts.length - self.chain.orphan.count);
  }, 5000);

  process.on('SIGUSR2', function() {
    require('fs').writeFileSync('/tmp/1.json', JSON.stringify({
      hashes: self.chain.hashes,
      ts: self.chain.ts
    }));
  });
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
    self.block.lastSeen = null;
    peer.destroy();
  }
  var timer = setTimeout(destroy, this.load.timeout);

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
      timer = setTimeout(destroy, self.load.timeout);
  });
};

Pool.prototype._load = function load() {
  if (this.block.queue.length >= this.load.hwm) {
    this.load.hiReached = true;
    return false;
  }
  this.load.hiReached = false;

  // Load more blocks, starting from last hash
  var hash;
  if (this.block.lastSeen)
    hash = this.block.lastSeen;
  else
    hash = this.chain.getLast().hash();

  console.log('Loading from: ' + utils.toHex(hash.slice().reverse()));
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
    var has = self.chain.has(block);
    self.chain.add(block);
    var req = self.block.requests[block.hash('hex')];
    if (!req)
      return;
    assert(!has);
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
  if (this.chain.has(hash))
    return;

  var hex = utils.toHex(hash);
  if (this.block.requests[hex])
    return;

  var req = new BlockRequest(this, hex);
  this.block.requests[hex] = req;
  this.block.queue.push(req);
};

Pool.prototype._scheduleRequests = function _scheduleRequests() {
  if (this.block.active > this.parallel / 2)
    return;

  // No need to wait - already have enough data
  if (this.block.queue.length > this.parallel) {
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
  if (this.block.active >= this.parallel)
    return;

  var above = this.block.queue.length >= this.load.lwm;
  var items = this.block.queue.slice(0, this.parallel - this.block.active);
  this.block.queue = this.block.queue.slice(items.length);
  var below = this.block.queue.length < this.load.lwm;

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

function BlockRequest(pool, hash) {
  this.pool = pool
  this.hash = hash;
  this.timer = null;
  this.peer = null;
  this.ts = +new Date;
  this.active = false;

  var self = this;
  this.onclose = function onclose() {
    self.retry();
  };
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
  assert(!this.active);

  this.active = true;
  this.pool.block.active++;

  assert(!this.timer);
  this.timer = setTimeout(function() {
    self.timer = null;
    self.retry();
  }, this.pool.requestTimeout);

  assert(!this.peer);
  this.peer = peer;
  this.peer.once('close', this.onclose);

  return {
    type: 'filtered',
    hash: this.hash
  };
};

BlockRequest.compare = function compare(a, b) {
  return a.ts - b.ts;
};

BlockRequest.prototype.clear = function clear() {
  assert(this.active);
  this.pool.block.active--;
  this.active = false;
  this.peer.removeListener('close', this.onclose);
  this.peer = null;
  clearTimeout(this.timer);
  this.timer = null;
};

BlockRequest.prototype.retry = function retry() {
  // Put block into the queue, ensure that the queue is always sorted by ts
  binaryInsert(this.pool.block.queue, this, BlockRequest.compare);
  var peer = this.peer;
  this.clear();

  // Kill peer, if it misbehaves
  if (++peer._retry > this.pool.maxRetries)
    peer.destroy();

  // And schedule requesting blocks again
  this.pool._scheduleRequests();
};

BlockRequest.prototype.finish = function finish() {
  if (this.active) {
    this.clear();
  } else {
    // It could be that request was never sent to the node, remove it from
    // queue and forget about it
    var index = this.pool.block.queue.indexOf(this);
    if (index !== -1)
      this.pool.block.queue.splice(index, 1);
    assert(!this.peer);
    assert(!this.timer);
  }
  delete this.pool.block.requests[this.hash];

  // We may have some free slots in queue now
  this.pool._scheduleRequests();
  this.pool.finished++;
};
