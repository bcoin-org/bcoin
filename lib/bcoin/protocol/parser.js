var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');

var bcoin = require('../../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = require('./constants');

var readU32 = utils.readU32;
var readU64 = utils.readU64;

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
module.exports = Parser;

Parser.prototype._error = function _error(str) {
  this.emit('error', new Error(str));
};

Parser.prototype.feed = function feed(data) {
  this.pendingTotal += data.length;
  this.pending.push(data);
  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    var chunk = new Array(this.waiting);
    for (var i = 0, off = 0, len = 0; off < chunk.length; i++) {
      len = utils.copy(this.pending[0], chunk, off);
      if (len === this.pending[0].length)
        this.pending.shift();
      else if (!this.pending[0].slice && this.pending[0] instanceof Uint8Array)
        this.pending[0] = new Uint8Array(this.pending[0].buffer.slice(len));
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
  } else {
    this.packet.payload = chunk;
    if (readU32(utils.checksum(this.packet.payload)) !== this.packet.checksum)
      return this._error('Invalid checksum');
    this.packet.payload = this.parsePayload(this.packet.cmd,
                                            this.packet.payload);
    if (this.packet.payload)
      this.emit('packet', this.packet);

    this.waiting = 24;
    this.packet = null;
  }
};

Parser.prototype.parseHeader = function parseHeader(h) {
  var magic = readU32(h, 0);
  if (magic !== constants.magic) {
    return this._error('Invalid magic value: ' + magic.toString(16));
  }

  // Count length of the cmd
  for (var i = 0; h[i + 4] !== 0 && i < 12; i++);
  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  var cmd = utils.stringify(h.slice(4, 4 + i));
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
  else if (cmd === 'getdata' || cmd === 'inv' || cmd === 'notfound')
    return this.parseInvList(p);
  else if (cmd === 'merkleblock')
    return this.parseMerkleBlock(p);
  else if (cmd === 'block')
    return this.parseBlock(p);
  else if (cmd === 'tx')
    return this.parseTX(p);
  else if (cmd === 'reject')
    return this.parseReject(p);
  else if (cmd === 'addr')
    return this.parseAddr(p);
  else
    return p;
};

Parser.prototype.parseVersion = function parseVersion(p) {
  if (p.length < 85)
    return this._error('version packet is too small');

  var v = readU32(p, 0);
  var services = readU64(p, 4);

  // Timestamp
  var ts = readU64(p, 12);

  // Nonce, very dramatic
  var nonce = { lo: readU32(p, 72), hi: readU32(p, 76) };

  // Start height
  var weight = readU32(p, 81);

  // Relay
  var relay = p.length >= 86 ? p[85] === 1 : true;

  return {
    v: v,
    services: services,
    ts: ts,
    nonce: nonce,
    weight: weight,
    relay: relay
  };
};

function readIntv(p, off) {
  if (!off)
    off = 0;

  var r, bytes;
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
  var count = readIntv(p, 0);
  p = p.slice(count.off);
  count = count.r;
  if (p.length < count * 36)
    return this._error('Invalid getdata size');

  var items = [];
  for (var i = 0, off = 0; i < count; i++, off += 36) {
    items.push({
      type: constants.invByVal[readU32(p, off)],
      hash: p.slice(off + 4, off + 36)
    });
  }
  return items;
};

Parser.prototype.parseMerkleBlock = function parseMerkleBlock(p) {
  if (p.length < 86)
    return this._error('Invalid merkleblock size');

  var hashCount = readIntv(p, 84);
  var off = hashCount.off;
  hashCount = hashCount.r;
  if (off + 32 * hashCount + 1 > p.length)
    return this._error('Invalid hash count');

  var hashes = new Array(hashCount);
  for (var i = 0; i < hashCount; i++)
    hashes[i] = p.slice(off + i * 32, off + (i + 1) * 32);

  off = off + 32 * hashCount;
  var flagCount = readIntv(p, off);
  off = flagCount.off;
  flagCount = flagCount.r;

  if (off + flagCount > p.length)
    return this._error('Invalid flag count');

  var flags = p.slice(off, off + flagCount);

  return {
    version: readU32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: readU32(p, 68),
    bits: readU32(p, 72),
    nonce: readU32(p, 76),
    totalTX: readU32(p, 80),
    hashes: hashes,
    flags: flags
  };
};

Parser.prototype.parseBlock = function parseBlock(p) {
  if (p.length < 84)
    return this._error('Invalid block size');

  var result = readIntv(p, 80);
  var off = result.off;
  var totalTX = result.r;
  var txs = [];

  for (var i = 0; i < totalTX; i++) {
    var tx = this.parseTX(p.slice(off));
    off += tx._off;
    txs.push(tx);
  }

  return {
    version: readU32(p, 0),
    prevBlock: p.slice(4, 36),
    merkleRoot: p.slice(36, 68),
    ts: readU32(p, 68),
    bits: readU32(p, 72),
    nonce: readU32(p, 76),
    totalTX: totalTX,
    txs: txs
  };
};

Parser.prototype.parseTXIn = function parseTXIn(p) {
  if (p.length < 41)
    return this._error('Invalid tx_in size');

  var scriptLen = readIntv(p, 36);
  var off = scriptLen.off;
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
  if (p.length < 9)
    return this._error('Invalid tx_out size');

  var scriptLen = readIntv(p, 8);
  var off = scriptLen.off;
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
  if (p.length < 10)
    return this._error('Invalid tx size');

  var inCount = readIntv(p, 4);
  var off = inCount.off;
  inCount = inCount.r;
  if (inCount < 0)
    return this._error('Invalid tx_in count (negative)');
  if (off + 41 * inCount + 5 > p.length)
    return this._error('Invalid tx_in count (too big)');

  var txIn = new Array(inCount);
  for (var i = 0; i < inCount; i++) {
    var tx = this.parseTXIn(p.slice(off));
    if (!tx)
      return;
    txIn[i] = tx;
    off += tx.size;

    if (off + 5 > p.length)
      return this._error('Invalid tx_in offset');
  }

  var outCount = readIntv(p, off);
  var off = outCount.off;
  outCount = outCount.r;
  if (outCount < 0)
    return this._error('Invalid tx_out count (negative)');
  if (off + 9 * outCount + 4 > p.length)
    return this._error('Invalid tx_out count (too big)');

  var txOut = new Array(outCount);
  for (var i = 0; i < outCount; i++) {
    var tx = this.parseTXOut(p.slice(off));
    if (!tx)
      return;
    txOut[i] = tx;
    off += tx.size;

    if (off + 4 > p.length)
      return this._error('Invalid tx_out offset');
  }

  return {
    _raw: p,
    version: readU32(p, 0),
    inputs: txIn,
    outputs: txOut,
    lock: readU32(p, off),
    _off: off + 4
  };
};

Parser.prototype.parseReject = function parseReject(p) {
  if (p.length < 3)
    return this._error('Invalid reject size');

  var messageLen = readIntv(p, 0);
  var off = messageLen.off;
  messageLen = messageLen.r;
  if (off + messageLen + 2 > p.length)
    return this._error('Invalid reject message');

  var message = utils.stringify(p.slice(off, off + messageLen));
  off += messageLen;

  var ccode = p[off];
  off++;

  var reasonLen = readIntv(p, off);
  off = reasonLen.off;
  reasonLen = reasonLen.r;
  if (off + reasonLen > p.length)
    return this._error('Invalid reject reason');

  var reason = utils.stringify(p.slice(off, off + reasonLen));

  return {
    message: message,
    ccode: ccode,
    reason: reason
  };
};

Parser.prototype.parseAddr = function parseAddr(p) {
  if (p.length < 31)
    return this._error('Invalid addr size');

  var addrs = [];
  var len, off, count, ts, service, ipv4, ipv6, port, i;

  // count
  len = readIntv(p, 0);
  off = len.off;
  count = len.r;
  p = p.slice(off);

  for (i = 0; i < count; i++) {
    // timestamp - LE
    ts = utils.readU32(p, 0);

    // NODE_NETWORK service - LE
    service = utils.readU64(p, 4);

    // ipv6 - BE
    ipv6 = utils.toHex(p.slice(12, 24));
    ipv6 = '::' + ipv6.replace(/(.{4})/g, '$1:').slice(0, -1);

    // ipv4 - BE
    ipv4 = utils.readU32BE(p, 24);
    ipv4 = ((ipv4 >> 24) & 0xff) + '.' +
      ((ipv4 >> 16) & 0xff) + '.' +
      ((ipv4 >> 8) & 0xff) + '.' +
      ((ipv4 >> 0) & 0xff);

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
