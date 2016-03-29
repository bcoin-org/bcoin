/**
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../../bcoin');
var network = require('./network');
var constants = require('./constants');
var utils = require('../utils');
var assert = utils.assert;
var BufferWriter = require('../writer');

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

Framer.prototype.utxo = function _coin(coin) {
  return this.packet('utxo', Framer.coin(coin, false));
};

Framer.prototype.tx = function tx(tx) {
  return this.packet('tx', Framer.tx(tx));
};

Framer.prototype.witnessTX = function witnessTX(tx) {
  return this.packet('tx', Framer.witnessTX(tx));
};

Framer.prototype.block = function _block(block) {
  return this.packet('block', Framer.block(block));
};

Framer.prototype.witnessBlock = function witnessBlock(block) {
  return this.packet('block', Framer.witnessBlock(block));
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

Framer.address = function address(data, full, writer) {
  var p = new BufferWriter(writer);

  if (!data)
    data = {};

  if (!data.ts)
    data.ts = utils.now() - (process.uptime() | 0);

  if (!data.services)
    data.services = 0;

  if (!data.ipv4)
    data.ipv4 = new Buffer([]);

  if (!data.port)
    data.port = network.port;

  if (full)
    p.writeU32(data.ts);

  p.writeU64(data.services);

  if (data.ipv6) {
    data.ipv6 = utils.ip2array(data.ipv6, 6);
    p.writeBytes(data.ipv6);
  } else {
    data.ipv4 = utils.ip2array(data.ipv4, 4);
    // We don't have an ipv6, convert ipv4 to ipv4-mapped ipv6 address
    p.writeU32BE(0x00000000);
    p.writeU32BE(0x00000000);
    p.writeU32BE(0x0000ffff);
    p.writeBytes(data.ipv4);
  }

  p.writeU16BE(data.port);

  if (!writer)
    p = p.render();

  return p;
};

Framer.version = function version(options, writer) {
  var p = new BufferWriter(writer);

  if (!options.agent)
    options.agent = new Buffer(constants.userAgent, 'ascii');

  if (!options)
    options = {};

  if (!options.remote)
    options.remote = {};

  if (!options.local)
    options.local = {};

  if (options.local.services == null)
    options.local.services = constants.bcoinServices;

  p.write32(constants.version);
  p.writeU64(constants.bcoinServices);
  p.write64(utils.now());
  Framer.address(options.remote, false, p);
  Framer.address(options.local, false, p);
  p.writeU64(utils.nonce());
  p.writeVarString(options.agent);
  p.write32(options.height || 0);
  p.writeU8(options.relay ? 1 : 0);

  if (!writer)
    p = p.render();

  return p;
};

Framer.verack = function verack() {
  return new Buffer([]);
};

Framer._inv = function _inv(items, writer) {
  var p = new BufferWriter(writer);
  var type;
  var i;

  assert(items.length <= 50000);

  p.writeVarint(items.length);

  for (i = 0; i < items.length; i++) {
    type = items[i].type;
    if (typeof type === 'string')
      type = constants.inv[items[i].type];
    assert(constants.invByVal[type] != null);
    p.writeU32(type);
    p.writeHash(items[i].hash);
  }

  if (!writer)
    p = p.render();

  return p;
};

Framer.inv = function inv(items, writer) {
  return Framer._inv(items, writer);
};

Framer.getData = function getData(items, writer) {
  return Framer._inv(items, writer);
};

Framer.notFound = function notFound(items, writer) {
  return Framer._inv(items, writer);
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

Framer.filterLoad = function filterLoad(bloom, update, writer) {
  var p = new BufferWriter(writer);

  p.writeVarBytes(bloom.toBuffer());
  p.writeU32(bloom.n);
  p.writeU32(bloom.tweak);
  p.writeU8(constants.filterFlags[update]);

  if (!writer)
    p = p.render();

  return p;
};

Framer.filterClear = function filterClear() {
  return new Buffer([]);
};

Framer.getHeaders = function getHeaders(hashes, stop, writer) {
  // NOTE: getheaders can have a null hash
  if (!hashes)
    hashes = [];

  return Framer._getBlocks(hashes, stop, writer);
};

Framer.getBlocks = function getBlocks(hashes, stop, writer) {
  return Framer._getBlocks(hashes, stop, writer);
};

Framer._getBlocks = function _getBlocks(hashes, stop, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeU32(constants.version);
  p.writeVarint(hashes.length);

  for (i = 0; i < hashes.length; i++)
    p.writeHash(hashes[i]);

  p.writeHash(stop || constants.zeroHash);

  if (!writer)
    p = p.render();

  return p;
};

Framer.utxo = function _utxo(coin, writer) {
  var p = new BufferWriter(writer);
  var height = coin.height;

  if (height === -1)
    height = 0x7fffffff;

  assert(coin.value.byteLength() <= 8);

  p.writeU32(coin.version);
  p.writeU32(height);
  p.write64(coin.value);
  p.writeVarBytes(coin.script.encode());

  if (!writer)
    p = p.render();

  return p;
};

Framer.coin = function _coin(coin, extended, writer) {
  var p = new BufferWriter(writer);
  var height = coin.height;

  if (height === -1)
    height = 0x7fffffff;

  assert(coin.value.byteLength() <= 8);

  p.writeU32(coin.version);
  p.writeU32(height);
  p.write64(coin.value);
  p.writeVarBytes(coin.script.encode());
  p.writeU8(coin.coinbase ? 1 : 0);

  if (extended) {
    p.writeHash(coin.hash);
    p.writeU32(coin.index);
  }

  if (!writer)
    p = p.render();

  return p;
};

Framer.tx = function _tx(tx, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.write32(tx.version);

  p.writeVarint(tx.inputs.length);
  for (i = 0; i < tx.inputs.length; i++)
    Framer.input(tx.inputs[i], p);

  p.writeVarint(tx.outputs.length);
  for (i = 0; i < tx.outputs.length; i++)
    Framer.output(tx.outputs[i], p);

  p.writeU32(tx.locktime);

  if (!writer)
    p = p.render();

  p._witnessSize = 0;

  return p;
};

Framer.input = function _input(input, writer) {
  var p = new BufferWriter(writer);

  p.writeHash(input.prevout.hash);
  p.writeU32(input.prevout.index);
  p.writeVarBytes(input.script.encode());
  p.writeU32(input.sequence);

  if (!writer)
    p = p.render();

  return p;
};

Framer.output = function _output(output, writer) {
  var p = new BufferWriter(writer);

  assert(output.value.byteLength() <= 8);

  p.write64(output.value);
  p.writeVarBytes(output.script.encode());

  if (!writer)
    p = p.render();

  return p;
};

Framer.witnessTX = function _witnessTX(tx, writer) {
  var p = new BufferWriter(writer);
  var witnessSize = 0;
  var i;

  p.write32(tx.version);
  p.writeU8(0);
  p.writeU8(tx.flag || 1);

  p.writeVarint(tx.inputs.length);

  for (i = 0; i < tx.inputs.length; i++)
    Framer.input(tx.inputs[i], p);

  p.writeVarint(tx.outputs.length);

  for (i = 0; i < tx.outputs.length; i++)
    Framer.output(tx.outputs[i], p);

  for (i = 0; i < tx.inputs.length; i++) {
    var start = p.written;
    Framer.witness(tx.inputs[i].witness, p);
    witnessSize += p.written - start;
  }

  p.writeU32(tx.locktime);

  if (!writer)
    p = p.render();

  p._witnessSize = witnessSize + 2;

  return p;
};

Framer.witnessBlockSize = function witnessBlockSize(block) {
  return Framer.witnessBlock(block, new BufferWriter())._witnessSize;
};

Framer.witnessTXSize = function witnessTXSize(tx) {
  return Framer.witnessTXSize(tx, new BufferWriter())._witnessSize;
};

Framer.witness = function _witness(witness, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeVarint(witness.items.length);

  for (i = 0; i < witness.items.length; i++)
    p.writeVarBytes(witness.items[i]);

  if (!writer)
    p = p.render();

  return p;
};

Framer.block = function _block(block, writer) {
  return Framer._block(block, false, writer);
};

Framer.witnessBlock = function _witnessBlock(block, writer) {
  return Framer._block(block, true, writer);
};

Framer.renderTX = function renderTX(tx, useWitness, writer) {
  var p = new BufferWriter(writer);
  var witnessSize;

  if (tx._raw) {
    if (!useWitness && bcoin.protocol.parser.isWitnessTX(tx._raw)) {
      Framer.tx(tx, p);
      witnessSize = p._witnessSize;
    } else {
      p.writeBytes(tx._raw);
      witnessSize = tx._witnessSize;
    }
  } else {
    if (useWitness && bcoin.tx.prototype.hasWitness.call(tx))
      Framer.witnessTX(tx, p);
    else
      Framer.tx(tx, p);
    witnessSize = p._witnessSize;
  }

  if (!writer)
    p = p.render();

  p._witnessSize = witnessSize;

  return p;
};

Framer._block = function _block(block, useWitness, writer) {
  var p = new BufferWriter(writer);
  var witnessSize = 0;
  var i;

  p.write32(block.version);
  p.writeHash(block.prevBlock);
  p.writeHash(block.merkleRoot);
  p.writeU32(block.ts);
  p.writeU32(block.bits);
  p.writeU32(block.nonce);
  p.writeVarint(block.txs.length);

  for (i = 0; i < block.txs.length; i++) {
    Framer.renderTX(block.txs[i], useWitness, p);
    witnessSize += p._witnessSize;
  }

  if (!writer)
    p = p.render();

  p._witnessSize = witnessSize;

  return p;
};

Framer.merkleBlock = function _merkleBlock(block, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.write32(block.version);
  p.writeHash(block.prevBlock);
  p.writeHash(block.merkleRoot);
  p.writeU32(block.ts);
  p.writeU32(block.bits);
  p.writeU32(block.nonce);
  p.writeU32(block.totalTX);

  p.writeVarint(block.hashes.length);

  for (i = 0; i < block.hashes.length; i++)
    p.writeHash(block.hashes[i]);

  p.writeVarBytes(block.flags);

  if (!writer)
    p = p.render();

  return p;
};

Framer.headers = function _headers(block, writer) {
  var p = new BufferWriter(writer);

  p.write32(block.version);
  p.writeHash(block.prevBlock);
  p.writeHash(block.merkleRoot);
  p.writeU32(block.ts);
  p.writeU32(block.bits);
  p.writeU32(block.nonce);
  p.writeVarint(block.totalTX);

  if (!writer)
    p = p.render();

  return p;
};

Framer.reject = function reject(details, writer) {
  var p = new BufferWriter(writer);
  var ccode = details.ccode;

  if (ccode >= constants.reject.internal)
    ccode = constants.reject.invalid;

  p.writeVarString(details.message || '', 'ascii');
  p.writeU8(constants.reject[ccode] || constants.reject.invalid);
  p.writeVarString(details.reason || '', 'ascii');
  if (details.data)
    p.writeHash(details.data);

  if (!writer)
    p = p.render();

  return p;
};

Framer.addr = function addr(peers, writer) {
  var p = new BufferWriter(writer);
  var i, peer;

  p.writeVarint(peers.length);

  for (i = 0; i < peers.length; i++) {
    peer = peers[i];
    Framer.address({
      ts: peer.ts,
      services: peer.services,
      ipv6: peer.ipv6,
      ipv4: peer.ipv4,
      port: peer.port
    }, true, p);
  }

  if (!writer)
    p = p.render();

  return p;
};

Framer.mempool = function mempool() {
  return new Buffer([]);
};

Framer.alert = function alert(data, writer) {
  var p, i, payload;

  if (!data.payload) {
    p = new BufferWriter();
    p.write32(data.version);
    p.write64(data.relayUntil);
    p.write64(data.expiration);
    p.write32(data.id);
    p.write32(data.cancel);
    p.writeVarint(data.cancels.length);
    for (i = 0; i < data.cancels.length; i++)
      p.write32(data.cancels[i]);
    p.write32(data.minVer);
    p.write32(data.maxVer);
    p.writeVarint(data.subVers.length);
    for (i = 0; i < data.subVers.length; i++)
      p.writeVarString(data.subVers[i], 'ascii');
    p.write32(data.priority);
    p.writeVarString(data.comment, 'ascii');
    p.writeVarString(data.statusBar, 'ascii');
    p.writeVarString('', 'ascii');
    payload = p.render();
  } else {
    payload = data.payload;
  }

  p = new BufferWriter(writer);
  p.writeVarBytes(payload);

  if (data.signature)
    p.writeVarBytes(data.signature);
  else if (data.key)
    p.writeVarBytes(bcoin.ec.sign(utils.dsha256(payload), data.key));
  else
    assert(false, 'No key or signature.');

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Expose
 */

module.exports = Framer;
