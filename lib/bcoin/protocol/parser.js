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
  var chunk, i, off, len;

  this.pendingTotal += data.length;
  this.pending.push(data);

  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    chunk = new Buffer(this.waiting);

    i = 0;
    off = 0;
    len = 0;

    for (; off < chunk.length; i++) {
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
  if (this.packet === null) {
    this.packet = this.parseHeader(chunk) || {};
    return;
  }

  this.packet.payload = chunk;

  if (utils.readU32(utils.checksum(this.packet.payload)) !== this.packet.checksum)
    return this._error('Invalid checksum');

  this.packet.payload = this.parsePayload(this.packet.cmd, this.packet.payload);
  if (this.packet.payload)
    this.emit('packet', this.packet);

  this.waiting = 24;
  this.packet = null;
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var i, magic, cmd;

  magic = utils.readU32(h, 0);

  if (magic !== network.magic) {
    return this._error('Invalid magic value: ' + magic.toString(16));
  }

  // Count length of the cmd
  for (i = 0; h[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  cmd = h.slice(4, 4 + i).toString('ascii');
  this.waiting = utils.readU32(h, 16);

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: utils.readU32(h, 20)
  };
};

Parser.prototype.parsePayload = function parsePayload(cmd, p) {
  if (cmd === 'version')
    return this.parseVersion(p);

  if (cmd === 'getdata' || cmd === 'inv' || cmd === 'notfound')
    return this.parseInvList(p);

  if (cmd === 'merkleblock')
    return this.parseMerkleBlock(p);

  if (cmd === 'headers')
    return this.parseHeaders(p);

  if (cmd === 'block')
    return this.parseBlock(p);

  if (cmd === 'tx')
    return this.parseTX(p);

  if (cmd === 'reject')
    return this.parseReject(p);

  if (cmd === 'addr')
    return this.parseAddr(p);

  if (cmd === 'ping')
    return this.parsePing(p);

  if (cmd === 'pong')
    return this.parsePong(p);

  return p;
};

Parser.prototype.parsePing = function parsePing(p) {
  if (p.length < 8)
    return this._error('pong packet is too small');

  return {
    nonce: utils.readU64(p, 0)
  };
};

Parser.prototype.parsePong = function parsePong(p) {
  if (p.length < 8)
    return this._error('ping packet is too small');

  return {
    nonce: utils.readU64(p, 0)
  };
};

Parser.prototype.parseVersion = function parseVersion(p) {
  var v, services, ts, recv, from, nonce, result, off, agent, height, relay;

  if (p.length < 85)
    return this._error('version packet is too small');

  v = utils.readU32(p, 0);
  services = utils.readU64(p, 4);

  // Timestamp
  ts = utils.read64(p, 12);

  // Our address (recv)
  recv = this._parseAddr(p, 20);

  // Their Address (from)
  from = this._parseAddr(p, 46);

  // Nonce, very dramatic
  nonce = utils.readU64(p, 72);

  // User agent length
  result = utils.readIntv(p, 80);
  off = result.off;
  agent = p.slice(off, off + result.r);
  off += result.r;

  // Start height
  height = utils.readU32(p, off);
  off += 4;

  // Relay
  relay = p.length > off ? p[off] === 1 : true;

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
    ts: ts,
    local: recv,
    remote: from,
    nonce: nonce,
    agent: agent.toString('ascii'),
    height: height,
    relay: relay
  };
};

Parser.prototype.parseInvList = function parseInvList(p) {
  var items = [];
  var i, off, count;

  count = utils.readIntv(p, 0);
  p = p.slice(count.off);
  count = count.r;

  if (p.length < count * 36)
    return this._error('Invalid getdata size');

  for (i = 0, off = 0; i < count; i++, off += 36) {
    items.push({
      type: constants.invByVal[utils.readU32(p, off)],
      hash: p.slice(off + 4, off + 36)
    });
  }

  return items;
};

Parser.prototype.parseMerkleBlock = function parseMerkleBlock(p) {
  var i, hashCount, off, hashes, flagCount, flags;

  if (p.length < 86)
    return this._error('Invalid merkleblock size');

  hashCount = utils.readIntv(p, 84);
  off = hashCount.off;
  hashCount = hashCount.r;

  if (off + 32 * hashCount + 1 > p.length)
    return this._error('Invalid hash count');

  hashes = new Array(hashCount);

  for (i = 0; i < hashCount; i++)
    hashes[i] = p.slice(off + i * 32, off + (i + 1) * 32);

  off = off + 32 * hashCount;
  flagCount = utils.readIntv(p, off);
  off = flagCount.off;
  flagCount = flagCount.r;

  if (off + flagCount > p.length)
    return this._error('Invalid flag count');

  flags = p.slice(off, off + flagCount);

  return {
    version: utils.read32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: utils.readU32(p, 68),
    bits: utils.readU32(p, 72),
    nonce: utils.readU32(p, 76),
    totalTX: utils.readU32(p, 80),
    hashes: hashes,
    flags: flags,
    _raw: p,
    _size: p.length
  };
};

Parser.prototype.parseHeaders = function parseHeaders(p) {
  var headers = [];
  var i, result, off, count, header, start, r;

  if (p.length < 81)
    return this._error('Invalid headers size');

  result = utils.readIntv(p, 0);
  off = result.off;
  count = result.r;

  if (p.length < count * 80)
    return this._error('Invalid headers size');

  for (i = 0; i < count; i++) {
    header = {};
    start = off;
    header.version = utils.read32(p, off);
    off += 4;
    header.prevBlock = p.slice(off, off + 32);
    off += 32;
    header.merkleRoot = p.slice(off, off + 32);
    off += 32;
    header.ts = utils.readU32(p, off);
    off += 4;
    header.bits = utils.readU32(p, off);
    off += 4;
    header.nonce = utils.readU32(p, off);
    off += 4;
    r = utils.readIntv(p, off);
    header.totalTX = r.r;
    off = r.off;
    header._raw = p.slice(start, start + 80);
    headers.push(header);
  }

  return headers;
};

Parser.prototype.parseBlock = function parseBlock(p) {
  var txs = [];
  var i, result, off, totalTX, tx;

  if (p.length < 81)
    return this._error('Invalid block size');

  result = utils.readIntv(p, 80);
  off = result.off;
  totalTX = result.r;

  for (i = 0; i < totalTX; i++) {
    tx = this.parseTX(p.slice(off));
    if (!tx)
      return this._error('Invalid tx count for block');
    tx._offset = off;
    off += tx._size;
    txs.push(tx);
  }

  return {
    version: utils.read32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: utils.readU32(p, 68),
    bits: utils.readU32(p, 72),
    nonce: utils.readU32(p, 76),
    totalTX: totalTX,
    txs: txs,
    _raw: p,
    _size: p.length
  };
};

Parser.prototype.parseInput = function parseInput(p) {
  var scriptLen, off;

  if (p.length < 41)
    return this._error('Invalid tx_in size');

  scriptLen = utils.readIntv(p, 36);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen + 4 > p.length)
    return this._error('Invalid tx_in script length');

  return {
    _size: off + scriptLen + 4,
    prevout: {
      hash: p.slice(0, 32),
      index: utils.readU32(p, 32)
    },
    script: bcoin.script.decode(p.slice(off, off + scriptLen)),
    sequence: utils.readU32(p, off + scriptLen)
  };
};

Parser.prototype.parseOutput = function parseOutput(p) {
  var scriptLen, off;

  if (p.length < 9)
    return this._error('Invalid tx_out size');

  scriptLen = utils.readIntv(p, 8);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen > p.length)
    return this._error('Invalid tx_out script length');

  return {
    _size: off + scriptLen,
    value: utils.read64(p, 0),
    script: bcoin.script.decode(p.slice(off, off + scriptLen))
  };
};

Parser.prototype.parseCoin = function parseCoin(p, extended) {
  var off = 0;
  var version, height, value, script, hash, index, spent, scriptLen;

  if (p.length < 17 + (extended ? 37 : 0))
    throw new Error('Invalid utxo size');

  version = utils.readU32(p, off);
  off += 4;

  height = utils.readU32(p, off);
  if (height === 0x7fffffff)
    height = -1;
  off += 4;

  value = utils.read64(p, off);
  off += 8;

  scriptLen = utils.readIntv(p, off);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen > p.length - (extended ? 37 : 0))
    throw new Error('Invalid utxo script length');

  script = bcoin.script.decode(p.slice(off, off + scriptLen));
  off += scriptLen;

  if (extended) {
    hash = p.slice(off, off + 32);
    off += 32;

    index = utils.readU32(p, off);
    off += 4;

    spent = utils.readU8(p, off) === 1;
    off += 1;
  } else {
    hash = constants.zeroHash;
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

Parser.prototype.parseTX = function parseTX(p) {
  var inCount, off, txIn, tx;
  var outCount, txOut;
  var i;

  if (p.length < 10)
    return this._error('Invalid tx size');

  inCount = utils.readIntv(p, 4);
  off = inCount.off;
  inCount = inCount.r;

  if (inCount < 0)
    return this._error('Invalid tx_in count (negative)');

  if (off + 41 * inCount + 5 > p.length)
    return this._error('Invalid tx_in count (too big)');

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = this.parseInput(p.slice(off));

    if (!tx)
      return;

    txIn[i] = tx;
    tx._offset = off;
    off += tx._size;

    if (off + 5 > p.length)
      return this._error('Invalid tx_in offset');
  }

  outCount = utils.readIntv(p, off);
  off = outCount.off;
  outCount = outCount.r;
  if (outCount < 0)
    return this._error('Invalid tx_out count (negative)');
  if (off + 9 * outCount + 4 > p.length)
    return this._error('Invalid tx_out count (too big)');

  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = this.parseOutput(p.slice(off));

    if (!tx)
      return;

    txOut[i] = tx;
    tx._offset = off;
    off += tx._size;

    if (off + 4 > p.length)
      return this._error('Invalid tx_out offset');
  }

  return {
    version: utils.read32(p, 0),
    inputs: txIn,
    outputs: txOut,
    locktime: utils.readU32(p, off),
    _raw: p.slice(0, off + 4),
    _size: off + 4
  };
};

Parser.prototype.parseReject = function parseReject(p) {
  var messageLen, off, message, ccode, reasonLen, reason, data;

  if (p.length < 3)
    return this._error('Invalid reject size');

  messageLen = utils.readIntv(p, 0);
  off = messageLen.off;
  messageLen = messageLen.r;

  if (off + messageLen + 2 > p.length)
    return this._error('Invalid reject message');

  message = p.slice(off, off + messageLen).toString('ascii');
  off += messageLen;

  ccode = utils.readU8(p, off);
  off++;

  reasonLen = utils.readIntv(p, off);
  off = reasonLen.off;
  reasonLen = reasonLen.r;

  if (off + reasonLen > p.length)
    return this._error('Invalid reject reason');

  reason = p.slice(off, off + reasonLen).toString('ascii');

  off += reasonLen;

  data = p.slice(off, off + 32);

  return {
    message: message,
    ccode: constants.rejectByVal[ccode] || ccode,
    reason: reason,
    data: data
  };
};

Parser.prototype._parseAddr = function _parseAddr(p, off, full) {
  var ts, services, ip, port;

  if (!off)
    off = 0;

  if (full) {
    ts = utils.readU32(p, off);
    off += 4;
  } else {
    ts = 0;
  }

  services = utils.readU64(p, off);
  off += 8;

  ip = p.slice(off, off + 16);
  off += 16;

  port = utils.readU16BE(p, off);
  off += 2;

  try {
    services = services.toNumber();
  } catch (e) {
    services = 1;
  }

  return {
    ts: ts,
    services: services,
    ipv6: utils.array2ip(ip, 6),
    ipv4: utils.array2ip(ip, 4),
    port: port
  };
};

Parser.prototype.parseAddr = function parseAddr(p) {
  if (p.length < 31)
    return this._error('Invalid addr size');

  var addrs = [];
  var i, off, count;

  count = utils.readIntv(p, 0);
  off = count.off;
  count = count.r;

  for (i = 0; i < count && off < p.length; i++) {
    addrs.push(this._parseAddr(p, off, true));
    off += 30;
  }

  return addrs;
};

Parser.prototype.parseMempool = function parseMempool(p) {
  if (p.length > 0)
    return this._error('Invalid mempool size');

  return {};
};

/**
 * Expose
 */

module.exports = Parser;
