var assert = require('assert');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

function Pool(options) {
  if (!(this instanceof Pool))
    return new Pool(options);

  this.options = options || {};
  this.size = options.size || 16;
  this.redundancy = options.redundancy || 3;
  this.parallel = options.parallel || this.size;
  this.pendingBlocks = {};
  this.chain = new bcoin.chain();
  this.bloom = new bcoin.bloom(8 * 10 * 1024,
                               10,
                               (Math.random() * 0xffffffff) | 0),
  this.peers = [];
  this.pending = [];

  // Peers that are loading block ids
  this.loadPeers = [];
  this.createConnection = options.createConnection;
  assert(this.createConnection);

  this._init();
}
module.exports = Pool;

Pool.prototype._init = function _init() {
  for (var i = 0; i < this.size; i++)
    this._addPeer();
};

Pool.prototype._addPeer = function _addPeer() {
  if (this.peers.length + this.pending.length >= this.size)
    return;

  var socket = this.createConnection();
  var peer = bcoin.peer(this, socket, this.options.peer);
  this.pending.push(peer);

  var load = false;
  if (this.loadPeers.length < this.redundancy) {
    this.loadPeers.push(peer);
    load = true;
  }

  // Create new peer on failure
  var self = this;
  peer.once('error', function(err) {
    self._removePeer(peer);
    self._addPeer();
  });

  peer.once('ack', function() {
    var i = self.pending.indexOf(peer);
    if (i !== -1) {
      self.pending.splice(i, 1);
      self.peers.push(peer);
    }

    peer.updateWatch();
    if (load)
      peer.loadBlocks(self.chain.getLast().hash());
  });

  // Split blocks and request them using multiple peers
  peer.on('blocks', function(hashes) {
    if (hashes.length === 0)
      return;
    self._requestBlocks(hashes);
    if (load)
      peer.loadBlocks(hashes[hashes.length - 1]);
  });
};

Pool.prototype._removePeer = function _removePeer(peer) {
  var i = this.pending.indexOf(peer);
  if (i !== -1)
    this.pending.splice(i, 1);

  i = this.peers.indexOf(peer);
  if (i !== -1)
    this.peers.splice(i, 1);

  i = this.loadPeers.indexOf(peer);
  if (i !== -1)
    this.loadPeers.splice(i, 1);
};

Pool.prototype.watch = function watch(id) {
  if (id)
    this.bloom.add(id);
  for (var i = 0; i < this.peers.length; i++)
    this.peers[i].updateWatch();
};

Pool.prototype._getPeers = function _getPeers() {
  var res = [];

  if (this.peers.length <= this.redundancy)
    return this.peers.slice();

  for (var i = 0; i < this.redundancy; i++) {
    var peer = this.peers[(Math.random() * this.peers.length) | 0];
    if (res.indexOf(peer) !== -1)
      continue;

    res.push(peer);
  }

  return res;
};

Pool.prototype._requestBlocks = function _requestBlocks(hashes, force) {
  // Do not request blocks that either already in chain, or are
  // already requested from some of the peers
  hashes = hashes.filter(function(hash) {
    return !this.chain.has(hash) &&
           (force || !this.pendingBlocks[utils.toHex(hash)]);
  }, this).map(function(hash) {
    this.pendingBlocks[utils.toHex(hash)] = true;
    return { type: 'filtered', hash: hash };
  }, this);

  // Split blocks into chunks and send each chunk to some peers
  var chunks = [];
  var count = Math.ceil(hashes.length / this.parallel);
  for (var i = 0; i < hashes.length; i += count)
    chunks.push(hashes.slice(i, i + count));

  var self = this;
  chunks.forEach(function(chunk) {
    var peers = self._getPeers();
    peers.forEach(function(peer) {
      peer.getData(chunk, function(err, blocks) {
        // Re-request blocks on failure
        if (err) {
          return self._requestBlocks(chunk.map(function(item) {
            return item.hash;
          }), true);
        }

        // Add blocks to chain on success
        blocks.forEach(function(block) {
          delete self.pendingBlocks[block.hash('hex')];
          self.chain.add(block);
        });
      });
    });
  });
};
