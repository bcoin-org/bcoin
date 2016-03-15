/**
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');

var bcoin = require('../../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = require('./constants');
var network = require('./network');

/**
 * Parser
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 24;
  this.packet = null;
}

utils.inherits(Parser, EventEmitter);

Parser.prototype._error = function _error(str) {
  this.emit('error', new Error(str));
};

Parser.prototype.feed = function feed(data) {
  var chunk, off, len;

  this.pendingTotal += data.length;
  this.pending.push(data);

  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    chunk = new Buffer(this.waiting);

    off = 0;
    len = 0;

    while (off < chunk.length) {
      len = utils.copy(this.pending[0], chunk, off);
      if (len === this.pending[0].length)
        this.pending.shift();
      else
        this.pending[0] = this.pending[0].slice(len);
      off += len;
    }

    assert.equal(off, chunk.length);

    // Slice buffers
    this.pendingTotal -= chunk.length;
    this.parse(chunk);
  }
};

Parser.prototype.parse = function parse(chunk) {
  if (chunk.length > constants.maxMessage)
    return this._error('Packet too large: %dmb.', utils.mb(chunk.length));

  if (this.packet === null) {
    this.packet = this.parseHeader(chunk) || {};
    return;
  }

  this.packet.payload = chunk;

  if (utils.readU32(utils.checksum(this.packet.payload)) !== this.packet.checksum)
    return this._error('Invalid checksum');

  try {
    this.packet.payload = this.parsePayload(this.packet.cmd, this.packet.payload);
  } catch (e) {
    this.emit('error', e);
  }

  if (this.packet.payload)
    this.emit('packet', this.packet);

  this.waiting = 24;
  this.packet = null;
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var i, magic, cmd;

  magic = utils.readU32(h, 0);

  if (magic !== network.magic)
    return this._error('Invalid magic value: ' + magic.toString(16));

  // Count length of the cmd
  for (i = 0; h[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  cmd = h.toString('ascii', 4, 4 + i);
  this.waiting = utils.readU32(h, 16);

  if (this.waiting > constants.maxMessage)
    return this._error('Packet length too large: %dmb', utils.mb(this.waiting));

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: utils.readU32(h, 20)
  };
};

Parser.prototype.parsePayload = function parsePayload(cmd, p) {
  if (cmd === 'version')
    return Parser.parseVersion(p);

  if (cmd === 'getdata' || cmd === 'inv' || cmd === 'notfound')
    return Parser.parseInvList(p);

  if (cmd === 'merkleblock')
    return Parser.parseMerkleBlock(p);

  if (cmd === 'headers')
    return Parser.parseHeaders(p);

  if (cmd === 'block')
    return Parser.parseBlockCompact(p);

  if (cmd === 'tx')
    return Parser.parseTX(p);

  if (cmd === 'reject')
    return Parser.parseReject(p);

  if (cmd === 'addr')
    return Parser.parseAddr(p);

  if (cmd === 'ping')
    return Parser.parsePing(p);

  if (cmd === 'pong')
    return Parser.parsePong(p);

  return p;
};

Parser.parsePing = function parsePing(p) {
  p = new BufferReader(p);

  if (p.left() < 8)
    throw new Error('pong packet is too small');

  return {
    nonce: p.readU64()
  };
};

Parser.parsePong = function parsePong(p) {
  p = new BufferReader(p);

  if (p.left() < 8)
    throw new Error('ping packet is too small');

  return {
    nonce: p.readU64()
  };
};

Parser.parseVersion = function parseVersion(p) {
  var v, services, ts, recv, from, nonce, agent, height, relay;

  p = new BufferReader(p);

  v = p.readU32();
  services = p.readU64();

  // Timestamp
  ts = p.read64();

  // Our address (recv)
  recv = Parser.parseAddress(p);

  // Their Address (from)
  from = Parser.parseAddress(p);

  // Nonce, very dramatic
  nonce = p.readU64();

  // User agent length
  agent = p.readVarString('ascii');

  // Start height
  height = p.readU32();

  // Relay
  try {
    relay = p.readU8() === 1;
  } catch (e) {
    relay = true;
  }

  try {
    ts = ts.toNumber();
  } catch (e) {
    ts = 0;
  }

  try {
    services = services.toNumber();
  } catch (e) {
    services = 1;
  }

  return {
    v: v,
    services: services,
    network: (services & constants.services.network) !== 0,
    getutxo: (services & constants.services.getutxo) !== 0,
    bloom: (services & constants.services.bloom) !== 0,
    witness: (services & constants.services.witness) !== 0,
    ts: ts,
    local: recv,
    remote: from,
    nonce: nonce,
    agent: agent,
    height: height,
    relay: relay
  };
};

Parser.parseInvList = function parseInvList(p) {
  var items = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readUIntv();

  for (i = 0; i < count; i++) {
    items.push({
      type: constants.invByVal[p.readU32()],
      hash: p.readHash()
    });
  }

  return items;
};

Parser.parseMerkleBlock = function parseMerkleBlock(p) {
  var version, prevBlock, merkleRoot, ts, bits, nonce, totalTX;
  var i, hashCount, hashes, flags;

  p = new BufferReader(p);
  p.start();

  version = p.read32();
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readU32();

  hashCount = p.readUIntv();

  hashes = new Array(hashCount);

  for (i = 0; i < hashCount; i++)
    hashes[i] = p.readHash();

  flags = p.readVarBytes();

  return {
    version: version,
    prevBlock: prevBlock,
    merkleRoot: merkleRoot,
    ts: ts,
    bits: bits,
    nonce: nonce,
    totalTX: totalTX,
    hashes: hashes,
    flags: flags,
    _size: p.end()
  };
};

Parser.parseHeaders = function parseHeaders(p) {
  var headers = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readUIntv();

  for (i = 0; i < count; i++) {
    headers.push({
      version: p.read32(),
      prevBlock: p.readHash(),
      merkleRoot: p.readHash(),
      ts: p.readU32(),
      bits: p.readU32(),
      nonce: p.readU32(),
      totalTX: p.readUIntv()
    });
  }

  return headers;
};

Parser.parseBlock = function parseBlock(p) {
  var txs = [];
  var witnessSize = 0;
  var version, prevBlock, merkleRoot, ts, bits, nonce;
  var i, totalTX, tx;

  p = new BufferReader(p);
  p.start();

  version = p.read32();
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readUIntv();

  for (i = 0; i < totalTX; i++) {
    tx = Parser.parseTX(p);
    witnessSize += tx._witnessSize;
    txs.push(tx);
  }

  return {
    version: version,
    prevBlock: prevBlock,
    merkleRoot: merkleRoot,
    ts: ts,
    bits: bits,
    nonce: nonce,
    txs: txs,
    _size: p.end(),
    _witnessSize: witnessSize
  };
};

Parser.parseBlockCompact = function parseBlockCompact(p) {
  var height = -1;
  var version, prevBlock, merkleRoot, ts, bits, nonce;
  var i, totalTX, tx;
  var inCount, input, raw;

  p = new BufferReader(p);
  p.start();

  version = p.read32();
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();

  totalTX = p.readUIntv();

  if (version > 1 && totalTX > 0) {
    p.read32();
    inCount = p.readUIntv();

    if (inCount > 0)
      input = Parser.parseInput(p);
  }

  if (input) {
    if (Buffer.isBuffer(input.script.code[0]))
      height = input.script.code[0];
  }

  raw = p.data;

  p.end();

  return {
    version: version,
    prevBlock: prevBlock,
    merkleRoot: merkleRoot,
    ts: ts,
    bits: bits,
    nonce: nonce,
    totalTX: totalTX,
    coinbaseHeight: height,
    txs: [],
    _raw: raw,
    _size: raw.length
  };
};

Parser.parseInput = function parseInput(p) {
  var hash, index, script, sequence;

  p = new BufferReader(p);
  p.start();

  hash = p.readHash();
  index = p.readU32();
  script = new bcoin.script(p.readVarBytes());
  sequence = p.readU32();

  return {
    _size: p.end(),
    prevout: {
      hash: hash,
      index: index
    },
    script: script,
    sequence: sequence
  };
};

Parser.parseOutput = function parseOutput(p) {
  var value, script;

  p = new BufferReader(p);
  p.start();

  value = p.read64();
  script = new bcoin.script(p.readVarBytes());

  return {
    _size: p.end(),
    value: value,
    script: script
  };
};

Parser.parseCoin = function parseCoin(p, extended) {
  var version, height, value, script, hash, index, spent;

  p = new BufferReader(p);

  version = p.readU32();
  height = p.readU32();

  if (height === 0x7fffffff)
    height = -1;

  value = p.read64();

  script = new bcoin.script(p.readVarBytes());

  if (extended) {
    hash = p.readHash();
    index = p.readU32();
    spent = p.readU8() === 1;
  } else {
    hash = utils.slice(constants.zeroHash);
    index = 0xffffffff;
    spent = false;
  }

  return {
    version: version,
    height: height,
    value: value,
    script: script,
    hash: hash,
    index: index,
    spent: spent
  };
};

Parser.parseTX = function parseTX(p) {
  var inCount, txIn, tx;
  var outCount, txOut;
  var version, locktime, i;
  var raw, block;

  p = new BufferReader(p);
  p.start();

  block = p.offset !== 0;

  if (Parser.isWitnessTX(p))
    return Parser.parseWitnessTX(p);

  version = p.readU32();
  inCount = p.readUIntv();

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = Parser.parseInput(p);

    txIn[i] = tx;
    txIn[i].witness = new bcoin.script.witness([]);
  }

  outCount = p.readUIntv();
  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = Parser.parseOutput(p);
    txOut[i] = tx;
  }

  locktime = p.readU32();

  return {
    version: version,
    inputs: txIn,
    outputs: txOut,
    locktime: locktime,
    _witnessSize: 0,
    // _raw: raw,
    _size: p.end()
  };
};

Parser.isWitnessTX = function isWitnessTX(p) {
  p = new BufferReader(p);

  if (p.left() < 12)
    return false;

  return p.data[p.offset + 4] === 0 && p.data[p.offset + 5] !== 0;
};

Parser.parseWitnessTX = function parseWitnessTX(p) {
  var inCount, txIn, tx;
  var outCount, txOut;
  var marker, flag;
  var version, locktime, i;
  var witnessSize = 0;
  var raw, block;

  p = new BufferReader(p);
  p.start();

  block = p.offset !== 0;

  version = p.readU32();
  marker = p.readU8();
  flag = p.readU8();

  if (marker !== 0)
    throw new Error('Invalid witness tx (marker != 0)');

  if (flag === 0)
    throw new Error('Invalid witness tx (flag == 0)');

  inCount = p.readUIntv();

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = Parser.parseInput(p);
    txIn[i] = tx;
  }

  outCount = p.readUIntv();

  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = Parser.parseOutput(p);
    txOut[i] = tx;
  }

  for (i = 0; i < inCount; i++) {
    tx = Parser.parseWitness(p);
    txIn[i].witness = tx.witness;
    witnessSize += tx._size;
  }

  locktime = p.readU32();

  return {
    version: version,
    marker: marker,
    flag: flag,
    inputs: txIn,
    outputs: txOut,
    locktime: locktime,
    // _raw: raw,
    _size: p.end(),
    _witnessSize: witnessSize + 2
  };
};

Parser.parseWitness = function parseWitness(p) {
  var witness = [];
  var chunkCount, item, i;

  p = new BufferReader(p);
  p.start();

  chunkCount = p.readUIntv();

  for (i = 0; i < chunkCount; i++)
    witness.push(p.readVarBytes());

  return {
    _size: p.end(),
    witness: new bcoin.script.witness(witness)
  };
};

Parser.parseReject = function parseReject(p) {
  var message, ccode, reason, data;

  p = new BufferReader(p);

  message = p.readVarString('ascii');
  ccode = p.readU8();
  reason = p.readVarString('ascii');
  data = p.readHash();

  return {
    message: message,
    ccode: constants.rejectByVal[ccode] || ccode,
    reason: reason,
    data: data
  };
};

Parser.parseAddress = function parseAddress(p, full) {
  var ts, services, ip, port;

  p = new BufferReader(p);

  if (full) {
    ts = p.readU32();
  } else {
    ts = 0;
  }

  services = p.readU64();

  ip = p.readBytes(16);

  port = p.readU16BE();

  try {
    services = services.toNumber();
  } catch (e) {
    services = 1;
  }

  return {
    ts: ts,
    services: services,
    network: (services & constants.services.network) !== 0,
    getutxo: (services & constants.services.getutxo) !== 0,
    bloom: (services & constants.services.bloom) !== 0,
    witness: (services & constants.services.witness) !== 0,
    ipv6: utils.array2ip(ip, 6),
    ipv4: utils.array2ip(ip, 4),
    port: port
  };
};

Parser.parseAddr = function parseAddr(p) {
  var addrs = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readUIntv();

  for (i = 0; i < count; i++)
    addrs.push(Parser.parseAddress(p, true));

  return addrs;
};

Parser.parseMempool = function parseMempool(p) {
  return {};
};

function BufferReader(data, offset) {
  if (data instanceof BufferReader)
    return data;
  this.data = data;
  this.offset = offset || 0;
  this.stack = [];
}

BufferReader.prototype.start = function start() {
  this.stack.push(this.offset);
};

BufferReader.prototype.end = function end() {
  assert(this.stack.length > 0);
  var start = this.stack.pop();
  var end = this.offset;
  if (this.stack.length === 0) {
    delete this.offset;
    delete this.stack;
    delete this.data;
  }
  return end - start;
};

BufferReader.prototype.endData = function endData() {
  assert(this.stack.length > 0);
  var start = this.stack.pop();
  var end = this.offset;
  var size = end - start;
  var data = this.data;

  if (this.stack.length === 0) {
    delete this.offset;
    delete this.stack;
    delete this.data;
  }

  if (size === data.length)
    return data;

  return utils.slice(data, start, end);
};

BufferReader.prototype.readU8 = function readU8() {
  assert(this.offset + 1 <= this.data.length);
  var ret = utils.readU8(this.data, this.offset);
  this.offset += 1;
  return ret;
};

BufferReader.prototype.readU16 = function readU16() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.readU16(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.readU16BE = function readU16BE() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.readU16BE(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.readU32 = function readU32() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.readU32(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.readU32BE = function readU32BE() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.readU32BE(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.readU64 = function readU64() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.readU64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.readU64BE = function readU64BE() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.readU64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.read8 = function read8() {
  assert(this.offset + 1 <= this.data.length);
  var ret = utils.read8(this.data, this.offset);
  this.offset += 1;
  return ret;
};

BufferReader.prototype.read16 = function read16() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.read16(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.read16BE = function read16BE() {
  assert(this.offset + 2 <= this.data.length);
  var ret = utils.read16BE(this.data, this.offset);
  this.offset += 2;
  return ret;
};

BufferReader.prototype.read32 = function read32() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.read32(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.read32BE = function read32BE() {
  assert(this.offset + 4 <= this.data.length);
  var ret = utils.read32BE(this.data, this.offset);
  this.offset += 4;
  return ret;
};

BufferReader.prototype.read64 = function read64() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.read64(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.read64BE = function read64BE() {
  assert(this.offset + 8 <= this.data.length);
  var ret = utils.read64BE(this.data, this.offset);
  this.offset += 8;
  return ret;
};

BufferReader.prototype.readBytes = function readBytes(size) {
  assert(size >= 0);
  assert(this.offset + size <= this.data.length);
  var ret = utils.slice(this.data, this.offset, this.offset + size);
  this.offset += size;
  return ret;
};

BufferReader.prototype.readString = function readString(enc, size) {
  assert(size >= 0);
  assert(this.offset + size <= this.data.length);
  var ret = this.data.toString(enc, this.offset, this.offset + size);
  this.offset += size;
  return ret;
};

BufferReader.prototype.readHash = function readHash() {
  return this.readBytes(32);
};

BufferReader.prototype.readVarString = function readVarString(enc) {
  return this.readString(enc, this.readUIntv());
};

BufferReader.prototype.readVarBytes = function readVarBytes() {
  return this.readBytes(this.readUIntv());
};

BufferReader.prototype.readNullString = function readNullString(enc) {
  assert(this.offset + 1 <= this.data.length);
  for (var i = this.offset; i < this.data.length; i++) {
    if (this.data[i] === 0)
      break;
  }
  assert(i !== this.data.length);
  var ret = this.readString(enc, i - this.offset);
  this.offset = i + 1;
  return ret;
};

BufferReader.prototype.left = function left() {
  assert(this.offset <= this.data.length);
  return this.data.length - this.offset;
};

BufferReader.prototype.readIntv = function readIntv() {
  assert(this.offset + 1 <= this.data.length);
  var result = utils.readIntv(this.data, this.offset);
  assert(result.off <= this.data.length);
  this.offset = result.off;
  return result.r;
};

BufferReader.prototype.readUIntv = function readUIntv() {
  var result = this.readIntv();
  assert(result >= 0);
  return result;
};

/**
 * Expose
 */

module.exports = Parser;
