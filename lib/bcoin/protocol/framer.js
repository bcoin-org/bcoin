/**
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../../bcoin');
var network = require('./network');
var constants = require('./constants');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Framer
 */

function Framer(options) {
  if (!(this instanceof Framer))
    return new Framer(options);

  options = options || {};

  this.options = options;

  this.agent = new Buffer(options.userAgent || constants.userAgent, 'ascii');
  this.agent = this.agent.slice(0, 0xfc);
}

Framer.prototype.header = function header(cmd, payload) {
  var h = new Buffer(24);
  var len, i;

  cmd = new Buffer(cmd, 'ascii');

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  // Magic value
  utils.writeU32(h, network.magic, 0);

  // Command
  len = utils.copy(cmd, h, 4);
  for (i = 4 + len; i < 4 + 12; i++)
    h[i] = 0;

  // Payload length
  utils.writeU32(h, payload.length, 16);

  // Checksum
  utils.copy(utils.checksum(payload), h, 20);

  return h;
};

Framer.prototype.packet = function packet(cmd, payload) {
  var h = this.header(cmd, payload);
  return Buffer.concat([h, payload]);
};

Framer.prototype._addr = function addr(data, full) {
  var p = new Buffer(26 + (full ? 4 : 0));
  var off = 0;

  if (!data)
    data = {};

  if (!data.ts)
    data.ts = utils.now() - (process.uptime() | 0);

  if (!data.services)
    data.services = constants.services.network;

  if (!data.ipv4)
    data.ipv4 = new Buffer([]);

  if (!data.port)
    data.port = network.port;

  // timestamp
  if (full)
    off += utils.writeU32(p, data.ts, off);

  // NODE_NETWORK services
  off += utils.writeU64(p, data.services, off);

  // ipv6
  if (data.ipv6) {
    data.ipv6 = utils.ip2array(data.ipv6, 6);
    off += utils.writeU64BE(p, utils.readU64BE(data.ipv6, 0), off);
    off += utils.writeU64BE(p, utils.readU64BE(data.ipv6, 8), off);
  } else {
    data.ipv4 = utils.ip2array(data.ipv4, 4);
    // We don't have an ipv6, convert ipv4 to ipv4-mapped ipv6 address
    off += utils.writeU32BE(p, 0x00000000, off);
    off += utils.writeU32BE(p, 0x00000000, off);
    off += utils.writeU32BE(p, 0x0000ffff, off);
    off += utils.writeU32BE(p, utils.readU32BE(data.ipv4, 0), off);
  }

  // port
  off += utils.writeU16BE(p, data.port, off);

  return p;
};

Framer.prototype.version = function version(packet) {
  var p = new Buffer(86 + this.agent.length);
  var off = 0;
  var i, remote, local;

  if (!packet)
    packet = {};

  // Version
  off += utils.writeU32(p, constants.version, off);

  // Services
  off += utils.writeU64(p, constants.services.network, off);

  // Timestamp
  off += utils.write64(p, utils.now(), off);

  // Their address (recv)
  remote = this._addr(packet.remote || {});
  off += utils.copy(remote, p, off);

  // Our address (from)
  local = this._addr(packet.local || {});
  off += utils.copy(local, p, off);

  // Nonce, very dramatic
  off += utils.writeU64(p, utils.nonce(), off);

  // User-agent
  assert.equal(off, 80);
  if (!this.agent) {
    p[off++] = 0;
  } else {
    off += utils.writeIntv(p, this.agent.length, off);
    for (i = 0; i < this.agent.length; i++)
      p[off++] = this.agent[i];
  }

  // Start height
  off += utils.writeU32(p, packet.height || 0, off);

  // Relay
  p[off++] = packet.relay ? 1 : 0;

  assert(off === p.length);

  return this.packet('version', p);
};

Framer.prototype.verack = function verack() {
  return this.packet('verack', new Buffer([]));
};

Framer.prototype._inv = function _inv(command, items) {
  var res, off, i, hash;

  assert(items.length <= 50000);

  res = new Buffer(utils.sizeIntv(items.length) + items.length * 36);

  off = utils.writeIntv(res, items.length, 0);

  for (i = 0; i < items.length; i++) {
    // Type
    off += utils.writeU32(res, constants.inv[items[i].type], off);

    // Hash
    hash = items[i].hash;
    if (typeof hash === 'string')
      hash = new Buffer(hash, 'hex');
    assert.equal(hash.length, 32);
    off += utils.copy(hash, res, off);
  }

  return this.packet(command, res);
};

Framer.prototype.inv = function inv(items) {
  return this._inv('inv', items);
};

Framer.prototype.getData = function getData(items) {
  return this._inv('getdata', items);
};

Framer.prototype.notFound = function notFound(items) {
  return this._inv('notfound', items);
};

Framer.prototype.ping = function ping(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return this.packet('ping', p);
};

Framer.prototype.pong = function pong(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return this.packet('pong', p);
};

Framer.prototype.filterLoad = function filterLoad(bloom, update) {
  var filter = bloom.toBuffer();
  var before = new Buffer(utils.sizeIntv(filter.length));
  var after = new Buffer(9);

  utils.writeIntv(before, filter.length, 0);

  // Number of hash functions
  utils.writeU32(after, bloom.n, 0);

  // nTweak
  utils.writeU32(after, bloom.tweak, 4);

  // nFlags
  after[8] = constants.filterFlags[update];

  return this.packet('filterload', Buffer.concat([before, filter, after]));
};

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', new Buffer([]));
};

Framer.prototype.getHeaders = function getHeaders(hashes, stop) {
  return this._getBlocks('getheaders', hashes, stop);
};

Framer.prototype.getBlocks = function getBlocks(hashes, stop) {
  return this._getBlocks('getblocks', hashes, stop);
};

Framer.prototype._getBlocks = function _getBlocks(cmd, hashes, stop) {
  var p = new Buffer(4 + utils.sizeIntv(hashes.length) + 32 * (hashes.length + 1));
  var i, hash, len;
  var off = 0;

  // getheaders can have a null hash
  if (cmd === 'getheaders' && !hashes)
    hashes = [];

  off += utils.writeU32(p, constants.version, 0);
  off += utils.writeIntv(p, hashes.length, 4);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (typeof hash === 'string')
      hash = new Buffer(hash, 'hex');

    len = utils.copy(hash, p, off);

    for (; len < 32; len++)
      p[off + len] = 0;

    off += len;
  }

  if (stop) {
    if (typeof stop === 'string')
      stop = new Buffer(stop, 'hex');
    len = utils.copy(stop, p, off);
  } else {
    len = 0;
  }

  for (; len < 32; len++)
    p[off + len] = 0;

  assert.equal(off + len, p.length);

  return this.packet(cmd, p);
};

Framer.input = function _input(input) {
  var off = 0;
  var s, p;

  s = bcoin.script.encode(input.script);
  p = new Buffer(32 + 4 + utils.sizeIntv(s.length) + s.length + 4);

  off += utils.copy(new Buffer(input.prevout.hash, 'hex'), p, off);
  off += utils.writeU32(p, input.prevout.index, off);

  off += utils.writeIntv(p, s.length, off);
  off += utils.copy(s, p, off);

  off += utils.writeU32(p, input.sequence, off);

  return p;
};

Framer.output = function _output(output) {
  var off = 0;
  var s, p;

  s = bcoin.script.encode(output.script);
  p = new Buffer(8 + utils.sizeIntv(s.length) + s.length);

  off += utils.write64(p, output.value, off);
  assert(output.value.byteLength() <= 8);

  off += utils.writeIntv(p, s.length, off);
  off += utils.copy(s, p, off);

  return p;
};

Framer.coin = function _coin(coin, extended) {
  var script = bcoin.script.encode(coin.script);
  var intSize = utils.sizeIntv(script.length);
  var height = coin.height;
  var off = 0;
  var data;

  data = new Buffer(16 + intSize + script.length + (extended ? 37 : 0));

  if (height === -1)
    height = 0x7fffffff;

  off += utils.writeU32(data, coin.version, off);
  off += utils.writeU32(data, height, off);
  off += utils.write64(data, coin.value, off);
  assert(coin.value.byteLength() <= 8);
  off += utils.writeIntv(data, script.length, off);
  off += utils.copy(script, data, off);

  if (extended) {
    off += utils.copy(new Buffer(coin.hash, 'hex'), data, off);
    off += utils.writeU32(data, coin.index, off);
    off += utils.writeU8(data, coin.spent ? 1 : 0, off);
  }

  return data;
};

Framer.tx = function _tx(tx) {
  var inputs = [];
  var outputs = [];
  var inputSize = 0;
  var outputSize = 0;
  var off = 0;
  var p, i, input, output;

  for (i = 0; i < tx.inputs.length; i++) {
    input = Framer.input(tx.inputs[i]);
    inputs.push(input);
    inputSize += input.length;
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = Framer.output(tx.outputs[i]);
    outputs.push(output);
    outputSize += output.length;
  }

  p = new Buffer(4
    + utils.sizeIntv(tx.inputs.length) + inputSize
    + utils.sizeIntv(tx.outputs.length) + outputSize
    + 4);

  off += utils.write32(p, tx.version, off);

  off += utils.writeIntv(p, tx.inputs.length, off);
  for (i = 0; i < inputs.length; i++) {
    input = inputs[i];
    off += utils.copy(input, p, off);
  }

  off += utils.writeIntv(p, tx.outputs.length, off);
  for (i = 0; i < outputs.length; i++) {
    output = outputs[i];
    off += utils.copy(output, p, off);
  }

  off += utils.writeU32(p, tx.locktime, off);

  return p;
};

Framer.prototype.tx = function tx(tx) {
  return this.packet('tx', Framer.tx(tx));
};

Framer.block = function _block(block, type) {
  var off = 0;
  var txSize = 0;
  var txs = [];
  var i, tx, p;

  if (!type)
    type = block.subtype;

  if (type === 'merkleblock') {
    p = new Buffer(80 + 4
      + utils.sizeIntv(block.hashes.length) + (block.hashes.length * 32)
      + utils.sizeIntv(block.flags.length) + block.flags.length);
  } else if (type === 'header') {
    p = new Buffer(80 + utils.sizeIntv(block.txs.length));
  } else {
    for (i = 0; i < block.txs.length; i++) {
      tx = block.txs[i].render();
      txs.push(tx);
      txSize += tx.length;
    }
    p = new Buffer(80 + utils.sizeIntv(block.txs.length) + txSize);
  }

  // version
  off += utils.write32(p, block.version, off);

  // prev_block
  off += utils.copy(new Buffer(block.prevBlock, 'hex'), p, off);

  // merkle_root
  off += utils.copy(new Buffer(block.merkleRoot, 'hex'), p, off);

  // timestamp
  off += utils.writeU32(p, block.ts, off);

  // bits
  off += utils.writeU32(p, block.bits, off);

  // nonce
  off += utils.writeU32(p, block.nonce, off);

  assert.equal(off, 80);

  if (type === 'merkleblock') {
    // txn_count
    off += utils.writeU32(p, block.totalTX, off);

    // hash count
    off += utils.writeIntv(p, block.hashes.length, off);

    // hashes
    for (i = 0; i < block.hashes.length; i++)
      off += utils.copy(new Buffer(block.hashes[i], 'hex'), p, off);

    // flag count
    off += utils.writeIntv(p, block.flags.length, off);

    // flags
    for (i = 0; i < block.flags.length; i++)
      p[off++] = block.flags[i];
  } else if (type === 'header') {
    // txn_count
    off += utils.writeIntv(p, block.txs.length, off);
  } else {
    // txn_count
    off += utils.writeIntv(p, block.txs.length, off);

    // txs
    for (i = 0; i < txs.length; i++)
      off += utils.copy(txs[i], p, off);
  }

  return p;
};

Framer.prototype.block = function _block(block) {
  return this.packet('block', Framer.block(block, 'block'));
};

Framer.prototype.merkleBlock = function merkleBlock(block) {
  return this.packet('merkleblock', Framer.block(block, 'merkleblock'));
};

Framer.prototype.reject = function reject(details) {
  var message = new Buffer(details.message || '', 'ascii');
  var ccode = constants.reject[details.ccode] || constants.reject.malformed;
  var reason = new Buffer(details.reason || '', 'ascii');
  var data = details.data || new Buffer([]);
  var p = new Buffer(
    utils.sizeIntv(message.length) + message.length
    + 1
    + utils.sizeIntv(reason.length) + reason.length
    + data.length);
  var off = 0;

  off += utils.writeIntv(p, message.length, off);
  off += utils.copy(message, p, off);

  off += utils.writeU8(p, ccode, off);

  off += utils.writeIntv(p, reason.length, off);
  off += utils.copy(reason, p, off);

  off += utils.copy(data, p, off);

  return this.packet('reject', p);
};

Framer.prototype.addr = function addr(peers) {
  var p = new Buffer(utils.sizeIntv(peers.length) + peers.length * 30);
  var off = 0;
  var addrs = [];
  var addr;
  var i, peer;

  off += utils.writeIntv(p, peers.length, off);

  for (i = 0; i < peers.length; i++) {
    peer = peers[i];

    addr = this._addr({
      ts: peer.ts,
      services: peer.services,
      ipv6: peer.ipv6,
      ipv4: peer.ipv4,
      port: peer.port
    }, true);

    off += addr.copy(p, off, 0, addr.length);
  }

  return this.packet('addr', p);
};

Framer.prototype.mempool = function mempool() {
  return this.packet('mempool', new Buffer([]));
};

/**
 * Expose
 */

module.exports = Framer;
