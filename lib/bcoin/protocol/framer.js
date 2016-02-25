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

Framer.prototype.version = function version(options) {
  if (!options)
    options = {};

  options.agent = this.agent;

  return this.packet('version', Framer.version(options));
};

Framer.prototype.verack = function verack() {
  return this.packet('verack', Framer.verack());
};

Framer.prototype.inv = function inv(items) {
  return this.packet('inv', Framer.inv(items));
};

Framer.prototype.getData = function getData(items) {
  return this.packet('getdata', Framer.getData(items));
};

Framer.prototype.notFound = function notFound(items) {
  return this.packet('notfound', Framer.notFound(items));
};

Framer.prototype.ping = function ping(data) {
  return this.packet('ping', Framer.ping(data));
};

Framer.prototype.pong = function pong(data) {
  return this.packet('pong', Framer.pong(data));
};

Framer.prototype.filterLoad = function filterLoad(bloom, update) {
  return this.packet('filterload', Framer.filterLoad(bloom, update));
};

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', Framer.filterClear());
};

Framer.prototype.getHeaders = function getHeaders(hashes, stop) {
  return this.packet('getheaders', Framer.getHeaders(hashes, stop));
};

Framer.prototype.getBlocks = function getBlocks(hashes, stop) {
  return this.packet('getblocks', Framer.getBlocks(hashes, stop));
};

Framer.prototype.utxo =
Framer.prototype.coin = function _coin(coin) {
  return this.packet('utxo', Framer.coin(coin, false));
};

Framer.prototype.tx = function tx(tx) {
  return this.packet('tx', Framer.tx(block));
};

Framer.prototype.block = function _block(block) {
  return this.packet('block', Framer.block(block));
};

Framer.prototype.merkleBlock = function merkleBlock(block) {
  return this.packet('merkleblock', Framer.merkleBlock(block));
};

Framer.prototype.headers = function headers(block) {
  return this.packet('headers', Framer.headers(block));
};

Framer.prototype.reject = function reject(details) {
  return this.packet('reject', Framer.reject(details));
};

Framer.prototype.addr = function addr(peers) {
  return this.packet('addr', Framer.addr(peers));
};

Framer.prototype.mempool = function mempool() {
  return this.packet('mempool', Framer.mempool());
};

Framer.address = function addr(data, full) {
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

Framer.version = function version(options) {
  var off = 0;
  var p, i, remote, local;

  if (!options.agent)
    options.agent = new Buffer(constants.userAgent, 'ascii');

  p = new Buffer(85
    + utils.sizeIntv(options.agent.length)
    + options.agent.length);

  if (!options)
    options = {};

  // Version
  off += utils.writeU32(p, constants.version, off);

  // Services
  off += utils.writeU64(p, constants.services.network, off);

  // Timestamp
  off += utils.write64(p, utils.now(), off);

  // Their address (recv)
  remote = Framer.address(options.remote || {});
  off += utils.copy(remote, p, off);

  // Our address (from)
  local = Framer.address(options.local || {});
  off += utils.copy(local, p, off);

  // Nonce, very dramatic
  off += utils.writeU64(p, utils.nonce(), off);

  assert.equal(off, 80);

  // User-agent
  off += utils.writeIntv(p, agent.length, off);
  off += utils.copy(agent, p, off);

  // Start height
  off += utils.writeU32(p, options.height || 0, off);

  // Relay
  p[off++] = options.relay ? 1 : 0;

  assert(off === p.length);

  return p;
};

Framer.verack = function verack() {
  return new Buffer([]);
};

Framer._inv = function _inv(items) {
  var p, i, hash;
  var off = 0;

  assert(items.length <= 50000);

  p = new Buffer(utils.sizeIntv(items.length) + items.length * 36);

  off += utils.writeIntv(p, items.length, off);

  for (i = 0; i < items.length; i++) {
    // Type
    off += utils.writeU32(p, constants.inv[items[i].type], off);

    // Hash
    hash = items[i].hash;
    if (typeof hash === 'string')
      hash = new Buffer(hash, 'hex');
    assert.equal(hash.length, 32);
    off += utils.copy(hash, p, off);
  }

  return p;
};

Framer.inv = function inv(items) {
  return Framer._inv(items);
};

Framer.getData = function getData(items) {
  return Framer._inv(items);
};

Framer.notFound = function notFound(items) {
  return Framer._inv(items);
};

Framer.ping = function ping(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return p;
};

Framer.pong = function pong(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return p;
};

Framer.filterLoad = function filterLoad(bloom, update) {
  var filter = bloom.toBuffer();
  var p = new Buffer(utils.sizeIntv(filter.length) + filter.length + 9);
  var off = 0;

  off += utils.writeIntv(p, filter.length, off);
  off += utils.copy(filter, p, off);

  // Number of hash functions
  off += utils.writeU32(p, bloom.n, off);

  // nTweak
  off += utils.writeU32(p, bloom.tweak, off);

  // nFlags
  p[off++] = constants.filterFlags[update];

  return p;
};

Framer.filterClear = function filterClear() {
  return new Buffer([]);
};

Framer.getHeaders = function getHeaders(hashes, stop) {
  // NOTE: getheaders can have a null hash
  if (!hashes)
    hashes = [];

  return Framer._getBlocks(hashes, stop);
};

Framer.getBlocks = function getBlocks(hashes, stop) {
  return Framer._getBlocks(hashes, stop);
};

Framer._getBlocks = function _getBlocks(hashes, stop) {
  var p, i, hash, len;
  var off = 0;

  p = new Buffer(4 + utils.sizeIntv(hashes.length) + 32 * (hashes.length + 1));

  off += utils.writeU32(p, constants.version, off);
  off += utils.writeIntv(p, hashes.length, off);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (typeof hash === 'string')
      hash = new Buffer(hash, 'hex');

    len = utils.copy(hash, p, off);
    assert(len === 32);

    off += len;
  }

  if (stop) {
    if (typeof stop === 'string')
      stop = new Buffer(stop, 'hex');
    len = utils.copy(stop, p, off);
    assert(len === 32);
  } else {
    len = 0;
    for (; len < 32; len++)
      p[off + len] = 0;
  }

  assert.equal(off + len, p.length);

  return p;
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

Framer.utxo =
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

Framer.block = function _block(block) {
  var off = 0;
  var txSize = 0;
  var txs = [];
  var i, tx, p;

  for (i = 0; i < block.txs.length; i++) {
    tx = block.txs[i].render
      ? block.txs[i].render()
      : Framer.tx(block.txs[i]);
    txs.push(tx);
    txSize += tx.length;
  }

  p = new Buffer(80 + utils.sizeIntv(block.txs.length) + txSize);

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

  // txn_count
  off += utils.writeIntv(p, block.txs.length, off);

  // txs
  for (i = 0; i < txs.length; i++)
    off += utils.copy(txs[i], p, off);

  return p;
};

Framer.merkleBlock = function _merkleBlock(block) {
  var off = 0;
  var p, i;

  p = new Buffer(80 + 4
    + utils.sizeIntv(block.hashes.length) + (block.hashes.length * 32)
    + utils.sizeIntv(block.flags.length) + block.flags.length);

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

  return p;
};

Framer.headers = function _headers(block) {
  var off = 0;
  var p, i;

  p = new Buffer(80 + utils.sizeIntv(data.totalTX));

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

  // txn_count
  off += utils.writeIntv(p, data.totalTX, off);

  return p;
};

Framer.reject = function reject(details) {
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

  return p;
};

Framer.addr = function addr(peers) {
  var p = new Buffer(utils.sizeIntv(peers.length) + peers.length * 30);
  var off = 0;
  var addrs = [];
  var addr;
  var i, peer;

  off += utils.writeIntv(p, peers.length, off);

  for (i = 0; i < peers.length; i++) {
    peer = peers[i];

    addr = Framer.address({
      ts: peer.ts,
      services: peer.services,
      ipv6: peer.ipv6,
      ipv4: peer.ipv4,
      port: peer.port
    }, true);

    off += addr.copy(p, off, 0, addr.length);
  }

  return p;
};

Framer.mempool = function mempool() {
  return new Buffer([]);
};

/**
 * Expose
 */

module.exports = Framer;
