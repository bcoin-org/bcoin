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

var writeU32 = utils.writeU32;
var writeAscii = utils.writeAscii;

/**
 * Framer
 */

function Framer(options) {
  if (!(this instanceof Framer))
    return new Framer(options);

  options = options || {};

  this.options = options;

  this.agent = utils.toArray(options.userAgent || constants.userAgent);
  this.agent = this.agent.slice(0, 0xfc);
}

Framer.prototype.header = function header(cmd, payload) {
  var h = new Array(24);
  var len, i;

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  // Magic value
  writeU32(h, network.magic, 0);

  // Command
  len = writeAscii(h, cmd, 4);
  for (i = 4 + len; i < 4 + 12; i++)
    h[i] = 0;

  // Payload length
  writeU32(h, payload.length, 16);

  // Checksum
  utils.copy(utils.checksum(payload), h, 20);

  return h;
};

Framer.prototype.packet = function packet(cmd, payload) {
  var h = this.header(cmd, payload);
  return h.concat(payload);
};

Framer.prototype._addr = function addr(buf, off) {
  writeU32(buf, 1, off);
  writeU32(buf, 0, off + 4);
  writeU32(buf, 0, off + 8);
  writeU32(buf, 0, off + 12);
  writeU32(buf, 0xffff0000, off + 16);
  writeU32(buf, 0, off + 20);
  buf[off + 24] = 0;
  buf[off + 25] = 0;
  return 26;
};

Framer.prototype.version = function version(packet) {
  var p = new Array(86 + this.agent.length);
  var off = 0;
  var ts, i;

  if (!packet)
    packet = {};

  // Version
  off += writeU32(p, constants.version, off);

  // Services
  off += writeU32(p, constants.services.network, off);
  off += writeU32(p, 0, off);

  // Timestamp
  ts = ((+new Date()) / 1000) | 0;
  off += writeU32(p, ts, off);
  off += writeU32(p, 0, off);

  // Remote and local addresses
  off += this._addr(p, off);
  off += this._addr(p, off);

  // Nonce, very dramatic
  off += writeU32(p, (Math.random() * 0xffffffff) | 0, off);
  off += writeU32(p, (Math.random() * 0xffffffff) | 0, off);

  // User-agent
  assert.equal(off, 80);
  if (!this.agent) {
    p[off++] = 0;
  } else {
    off += varint(p, this.agent.length, off);
    for (i = 0; i < this.agent.length; i++)
      p[off++] = this.agent[i];
  }

  // Start height
  off += writeU32(p, packet.height || 0, off);

  // Relay
  p[off++] = packet.relay ? 1 : 0;

  return this.packet('version', p);
};

Framer.prototype.verack = function verack() {
  return this.packet('verack', []);
};

function varint(arr, value, off) {
  if (!off)
    off = 0;

  if (value < 0xfd) {
    arr[off] = value;
    return 1;
  }

  if (value <= 0xffff) {
    arr[off] = 0xfd;
    arr[off + 1] = value & 0xff;
    arr[off + 2] = value >>> 8;
    return 3;
  }

  if (value <= 0xffffffff) {
    arr[off] = 0xfe;
    arr[off + 1] = value & 0xff;
    arr[off + 2] = (value >>> 8) & 0xff;
    arr[off + 3] = (value >>> 16) & 0xff;
    arr[off + 4] = value >>> 24;
    return 5;
  }

  arr[off] = 0xff;
  utils.writeU64(arr, value, off + 1);
  return 9;
}

Framer.prototype._inv = function _inv(command, items) {
  var res = [];
  var off = varint(res, items.length, 0);
  var i, hash;

  assert(items.length <= 50000);

  for (i = 0; i < items.length; i++) {
    // Type
    off += writeU32(res, constants.inv[items[i].type], off);

    // Hash
    hash = items[i].hash;
    if (typeof hash === 'string')
      hash = utils.toArray(hash, 'hex');
    assert.equal(hash.length, 32);
    res = res.concat(hash);

    off += hash.length;
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

Framer.prototype.ping = function ping(nonce) {
  return this.packet('ping', nonce);
};

Framer.prototype.pong = function pong(nonce) {
  return this.packet('pong', nonce.slice(0, 8));
};

Framer.prototype.filterLoad = function filterLoad(bloom, update) {
  var filter = bloom.toArray();
  var before = [];
  var after = new Array(9);

  varint(before, filter.length, 0);

  // Number of hash functions
  writeU32(after, bloom.n, 0);

  // nTweak
  writeU32(after, bloom.tweak, 4);

  // nFlags
  after[8] = constants.filterFlags[update];

  return this.packet('filterload', before.concat(filter, after));
};

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', []);
};

Framer.prototype.getHeaders = function getHeaders(hashes, stop) {
  return this._getBlocks('getheaders', hashes, stop);
};

Framer.prototype.getBlocks = function getBlocks(hashes, stop) {
  return this._getBlocks('getblocks', hashes, stop);
};

Framer.prototype._getBlocks = function _getBlocks(cmd, hashes, stop) {
  var p = [];
  var off, i, hash, len;

  writeU32(p, constants.version, 0);
  off = 4 + varint(p, hashes.length, 4);
  p.length = off + 32 * (hashes.length + 1);

  for (i = 0; i < hashes.length; i++) {
    hash = hashes[i];

    if (typeof hash === 'string')
      hash = utils.toArray(hash, 'hex');

    len = utils.copy(hash, p, off);

    for (; len < 32; len++)
      p[off + len] = 0;

    off += len;
  }

  if (stop) {
    stop = utils.toArray(stop, 'hex');
    len = utils.copy(stop, p, off);
  } else {
    len = 0;
  }

  for (; len < 32; len++)
    p[off + len] = 0;

  assert.equal(off + len, p.length);

  return this.packet(cmd, p);
};

Framer.tx = function tx(tx) {
  var p = [];
  var off, i, input, s, output, value, j;

  off = writeU32(p, tx.version, 0);
  off += varint(p, tx.inputs.length, off);

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    off += utils.copy(utils.toArray(input.out.hash, 'hex'), p, off, true);
    off += writeU32(p, input.out.index, off);

    s = bcoin.script.encode(input.script);
    off += varint(p, s.length, off);
    off += utils.copy(s, p, off, true);

    off += writeU32(p, input.seq, off);
  }

  off += varint(p, tx.outputs.length, off);
  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    // Put LE value
    value = output.value.toArray().slice().reverse();
    assert(value.length <= 8);

    off += utils.copy(value, p, off, true);

    for (j = value.length; j < 8; j++, off++)
      p[off] = 0;

    s = bcoin.script.encode(output.script);
    off += varint(p, s.length, off);
    off += utils.copy(s, p, off, true);
  }
  off += writeU32(p, tx.lock, off);

  return p;
};

Framer.prototype.tx = function tx(tx) {
  return this.packet('tx', Framer.tx(tx));
};

Framer.block = function _block(block, type) {
  var p = [];
  var off = 0;

  if (!type)
    type = block.subtype;

  // version
  off += writeU32(p, block.version, off);

  // prev_block
  utils.toArray(block.prevBlock, 'hex').forEach(function(ch) {
    p[off++] = ch;
  });

  // merkle_root
  utils.toArray(block.merkleRoot, 'hex').forEach(function(ch) {
    p[off++] = ch;
  });

  // timestamp
  off += writeU32(p, block.ts, off);

  // bits
  off += writeU32(p, block.bits, off);

  // nonce
  off += writeU32(p, block.nonce, off);

  assert.equal(off, 80);

  if (type === 'merkleblock') {
    // txn_count
    off += writeU32(p, block.totalTX, off);
    // hash count
    off += varint(p, block.hashes.length, off);
    // hashes
    block.hashes.forEach(function(hash) {
      utils.toArray(hash, 'hex').forEach(function(ch) {
        p[off++] = ch;
      });
    });
    // flag count
    off += varint(p, block.flags.length, off);
    // flags
    block.flags.forEach(function(flag) {
      p[off++] = flag;
    });
  } else if (type === 'block') {
    // txn_count
    off += varint(p, block.totalTX, off);
    // txs
    block.txs.forEach(function(tx) {
      var raw = tx._raw || tx.render();
      raw.forEach(function(ch) {
        p[off++] = ch;
      });
    });
  }

  return p;
};

Framer.prototype.block = function _block(block) {
  return this.packet(Framer.block(block, 'block'));
};

Framer.prototype.merkleBlock = function merkleBlock(block) {
  // XXX Technically we're also supposed to send `tx` packets accompanying the
  // merkleblock here if we have them, as per the offical bitcoin client.
  return this.packet(Framer.block(block, 'merkleblock'));
};

Framer.prototype.addr = function addr(peers) {
  var p = [];
  var i = 0;
  var off = 0;
  var peer;
  var start = (Date.now() / 1000 | 0) - process.uptime();
  var i;

  // count
  off += varint(p, peers.length, off);

  for (; i < peers.length; i++) {
    peer = peers[i];

    // timestamp
    off += utils.writeU32(p, peer.ts || start, off);

    // NODE_NETWORK service
    off += utils.writeU64(p, 1, off);

    // ipv6
    off += utils.writeU32BE(p, utils.readU32BE(peer.ipv6, 4), off);
    off += utils.writeU32BE(p, utils.readU32BE(peer.ipv6, 8), off);
    off += utils.writeU32BE(p, utils.readU32BE(peer.ipv6, 12), off);

    // ipv4
    off += utils.writeU32BE(p, utils.readU32BE(peer.ipv4, 0), off);

    // port
    off += utils.writeU16BE(p, peer.port, off);
  }

  return this.packet('addr', p);
};

/**
 * Expose
 */

module.exports = Framer;
