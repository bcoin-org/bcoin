/**
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');

var bcoin = require('../../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = require('./constants');
var network = require('./network');

var readU32 = utils.readU32;
var readU64 = utils.readU64;

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

inherits(Parser, EventEmitter);

Parser.prototype._error = function _error(str) {
  this.emit('error', new Error(str));
};

Parser.prototype.feed = function feed(data) {
  var chunk, i, off, len;

  this.pendingTotal += data.length;
  this.pending.push(data);

  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    chunk = new Array(this.waiting);

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

  if (readU32(utils.checksum(this.packet.payload)) !== this.packet.checksum)
    return this._error('Invalid checksum');

  this.packet.payload = this.parsePayload(this.packet.cmd, this.packet.payload);
  if (this.packet.payload)
    this.emit('packet', this.packet);

  this.waiting = 24;
  this.packet = null;
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var i, magic, cmd;

  magic = readU32(h, 0);

  if (magic !== network.magic) {
    return this._error('Invalid magic value: ' + magic.toString(16));
  }

  // Count length of the cmd
  for (i = 0; h[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  cmd = utils.stringify(h.slice(4, 4 + i));
  this.waiting = readU32(h, 16);

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: readU32(h, 20)
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

  return p;
};

Parser.prototype.parseVersion = function parseVersion(p) {
  var v, services, ts, nonce, result, off, agent, height, relay;

  if (p.length < 85)
    return this._error('version packet is too small');

  v = readU32(p, 0);
  services = readU64(p, 4);

  // Timestamp
  ts = readU64(p, 12);

  // Nonce, very dramatic
  nonce = { lo: readU32(p, 72), hi: readU32(p, 76) };

  // User agent length
  result = readIntv(p, 80);
  off = result.off;
  agent = p.slice(off, off + result.r);
  off += result.r;

  // Start height
  height = readU32(p, off);
  off += 4;

  // Relay
  relay = p.length > off ? p[off] === 1 : true;

  return {
    v: v,
    services: services,
    ts: ts,
    nonce: nonce,
    agent: utils.stringify(agent),
    height: height,
    relay: relay
  };
};

function readIntv(p, off) {
  var r, bytes;

  if (!off)
    off = 0;

  if (p[off] < 0xfd) {
    r = p[off];
    bytes = 1;
  } else if (p[off] === 0xfd) {
    r = p[off + 1] | (p[off + 2] << 8);
    bytes = 3;
  } else if (p[off] === 0xfe) {
    r = readU32(p, off + 1);
    bytes = 5;
  } else {
    r = 0;
    bytes = 9;
  }

  return { off: off + bytes, r: r };
}

Parser.prototype.parseInvList = function parseInvList(p) {
  var items = [];
  var i, off, count;

  count = readIntv(p, 0);
  p = p.slice(count.off);
  count = count.r;

  if (p.length < count * 36)
    return this._error('Invalid getdata size');

  for (i = 0, off = 0; i < count; i++, off += 36) {
    items.push({
      type: constants.invByVal[readU32(p, off)],
      hash: p.slice(off + 4, off + 36)
    });
  }

  return items;
};

Parser.prototype.parseMerkleBlock = function parseMerkleBlock(p) {
  var i, hashCount, off, hashes, flagCount, flags;

  if (p.length < 86)
    return this._error('Invalid merkleblock size');

  hashCount = readIntv(p, 84);
  off = hashCount.off;
  hashCount = hashCount.r;

  if (off + 32 * hashCount + 1 > p.length)
    return this._error('Invalid hash count');

  hashes = new Array(hashCount);

  for (i = 0; i < hashCount; i++)
    hashes[i] = p.slice(off + i * 32, off + (i + 1) * 32);

  off = off + 32 * hashCount;
  flagCount = readIntv(p, off);
  off = flagCount.off;
  flagCount = flagCount.r;

  if (off + flagCount > p.length)
    return this._error('Invalid flag count');

  flags = p.slice(off, off + flagCount);

  return {
    version: readU32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: readU32(p, 68),
    bits: readU32(p, 72),
    nonce: readU32(p, 76),
    totalTX: readU32(p, 80),
    hashes: hashes,
    flags: flags,
    _raw: p.slice(0, 80),
    _size: p.length
  };
};

Parser.prototype.parseHeaders = function parseHeaders(p) {
  var headers = [];
  var i, result, off, count, header, start, r;

  if (p.length < 81)
    return this._error('Invalid headers size');

  result = readIntv(p, 0);
  off = result.off;
  count = result.r;

  if (p.length >= off + 81) {
    for (i = 0; i < count && off + 81 < p.length; i++) {
      header = {};
      start = off;
      header.version = readU32(p, off);
      off += 4;
      header.prevBlock = p.slice(off, off + 32);
      off += 32;
      header.merkleRoot = p.slice(off, off + 32);
      off += 32;
      header.ts = readU32(p, off);
      off += 4;
      header.bits = readU32(p, off);
      off += 4;
      header.nonce = readU32(p, off);
      off += 4;
      r = readIntv(p, off);
      header.totalTX = r.r;
      off = r.off;
      header._raw = p.slice(start, start + 80);
      headers.push(header);
    }
  }

  return headers;
};

Parser.prototype.parseBlock = function parseBlock(p) {
  var txs = [];
  var i, result, off, totalTX, tx;

  if (p.length < 81)
    return this._error('Invalid block size');

  result = readIntv(p, 80);
  off = result.off;
  totalTX = result.r;

  if (p.length >= off + 10) {
    for (i = 0; i < totalTX; i++) {
      tx = this.parseTX(p.slice(off));
      off += tx._off;
      txs.push(tx);
    }
  }

  return {
    version: readU32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: readU32(p, 68),
    bits: readU32(p, 72),
    nonce: readU32(p, 76),
    totalTX: totalTX,
    txs: txs,
    _raw: p.slice(0, 80),
    _size: p.length
  };
};

Parser.prototype.parseTXIn = function parseTXIn(p) {
  var scriptLen, off;

  if (p.length < 41)
    return this._error('Invalid tx_in size');

  scriptLen = readIntv(p, 36);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen + 4 > p.length)
    return this._error('Invalid tx_in script length');

  return {
    size: off + scriptLen + 4,
    out: {
      hash: p.slice(0, 32),
      index: readU32(p, 32)
    },
    script: bcoin.script.decode(p.slice(off, off + scriptLen)),
    seq: readU32(p, off + scriptLen)
  };
};

Parser.prototype.parseTXOut = function parseTXOut(p) {
  var scriptLen, off;

  if (p.length < 9)
    return this._error('Invalid tx_out size');

  scriptLen = readIntv(p, 8);
  off = scriptLen.off;
  scriptLen = scriptLen.r;

  if (off + scriptLen > p.length)
    return this._error('Invalid tx_out script length');

  return {
    size: off + scriptLen,
    value: new bn(p.slice(0, 8).reverse()),
    script: bcoin.script.decode(p.slice(off, off + scriptLen))
  };
};

Parser.prototype.parseTX = function parseTX(p) {
  var inCount, off, txIn, tx;
  var outCount, txOut;
  var i;

  if (p.length < 10)
    return this._error('Invalid tx size');

  inCount = readIntv(p, 4);
  off = inCount.off;
  inCount = inCount.r;

  if (inCount < 0)
    return this._error('Invalid tx_in count (negative)');

  if (off + 41 * inCount + 5 > p.length)
    return this._error('Invalid tx_in count (too big)');

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = this.parseTXIn(p.slice(off));

    if (!tx)
      return;

    txIn[i] = tx;
    off += tx.size;

    if (off + 5 > p.length)
      return this._error('Invalid tx_in offset');
  }

  outCount = readIntv(p, off);
  off = outCount.off;
  outCount = outCount.r;
  if (outCount < 0)
    return this._error('Invalid tx_out count (negative)');
  if (off + 9 * outCount + 4 > p.length)
    return this._error('Invalid tx_out count (too big)');

  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = this.parseTXOut(p.slice(off));

    if (!tx)
      return;

    txOut[i] = tx;
    off += tx.size;

    if (off + 4 > p.length)
      return this._error('Invalid tx_out offset');
  }

  return {
    _raw: p.slice(0, off + 4),
    version: readU32(p, 0),
    inputs: txIn,
    outputs: txOut,
    lock: readU32(p, off),
    _off: off + 4,
    _size: p.length
  };
};

Parser.prototype.parseReject = function parseReject(p) {
  var messageLen, off, message, ccode, reasonLen, reason, data;

  if (p.length < 3)
    return this._error('Invalid reject size');

  messageLen = readIntv(p, 0);
  off = messageLen.off;
  messageLen = messageLen.r;

  if (off + messageLen + 2 > p.length)
    return this._error('Invalid reject message');

  message = utils.stringify(p.slice(off, off + messageLen));
  off += messageLen;

  ccode = p[off];
  off++;

  reasonLen = readIntv(p, off);
  off = reasonLen.off;
  reasonLen = reasonLen.r;

  if (off + reasonLen > p.length)
    return this._error('Invalid reject reason');

  reason = utils.stringify(p.slice(off, off + reasonLen));

  off += reasonLen;

  data = p.slice(off, off + 32);

  return {
    message: message,
    ccode: constants.rejectByVal[ccode] || ccode,
    reason: reason,
    data: data
  };
};

Parser.prototype.parseAddr = function parseAddr(p) {
  if (p.length < 31)
    return this._error('Invalid addr size');

  var addrs = [];
  var i, len, off, count, ts, service, ipv6, ipv4, port;

  // count
  len = readIntv(p, 0);
  off = len.off;
  count = len.r;

  p = p.slice(off);

  for (i = 0; i < count && p.length; i++) {
    // timestamp - LE
    ts = utils.readU32(p, 0);

    // NODE_NETWORK service - LE
    service = utils.readU64(p, 4);

    // ipv6 - BE
    ipv6 = utils.toHex(p.slice(12, 24));
    ipv6 = '::' + ipv6.replace(/(.{4})/g, '$1:').slice(0, -1);

    // ipv4 - BE
    ipv4 = utils.readU32BE(p, 24);
    ipv4 = ((ipv4 >> 24) & 0xff)
      + '.' + ((ipv4 >> 16) & 0xff)
      + '.' + ((ipv4 >> 8) & 0xff)
      + '.' + ((ipv4 >> 0) & 0xff);

    // port - BE
    port = utils.readU16BE(p, 28);

    addrs.push({
      ts: ts,
      service: service,
      ipv6: ipv6,
      ipv4: ipv4,
      port: port
    });

    p = p.slice(30);
  }

  return addrs;
};

/**
 * Expose
 */

module.exports = Parser;
