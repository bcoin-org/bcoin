/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var utils = require('../utils');
var assert = utils.assert;
var constants = require('./constants');
var BufferReader = require('../reader');

/**
 * Protocol packet parser
 * @exports Parser
 * @constructor
 * @param {Object?} options
 * @emits Parser#error
 * @emits Parser#packet
 */

function Parser(options) {
  if (!(this instanceof Parser))
    return new Parser(options);

  if (!options)
    options = {};

  EventEmitter.call(this);

  this.network = bcoin.network.get(options.network);
  this.bip151 = options.bip151;

  this.pending = [];
  this.pendingTotal = 0;
  this.waiting = 24;
  this.packet = null;

  this._init();
}

utils.inherits(Parser, EventEmitter);

/**
 * Initialize. Bind to events.
 * @private
 * @param {String} str
 */

Parser.prototype._init = function _init(str) {
  var self = this;

  if (!this.bip151)
    return;

  this.bip151.on('packet', function(cmd, body) {
    var packet = new Packet(cmd, body.length);
    try {
      packet.payload = self.parsePayload(cmd, body);
    } catch (e) {
      return self._error(e);
    }
    self.emit('packet', packet);
  });
};

/**
 * Emit an error.
 * @private
 * @param {String} str
 */

Parser.prototype._error = function _error(str) {
  this.emit('error', new Error(str));
};

/**
 * Feed data to the parser.
 * @param {Buffer} data
 */

Parser.prototype.feed = function feed(data) {
  var chunk, off, len;

  if (this.bip151 && this.bip151.handshake)
    return this.bip151.feed(data);

  this.pendingTotal += data.length;
  this.pending.push(data);

  while (this.pendingTotal >= this.waiting) {
    // Concat chunks
    chunk = new Buffer(this.waiting);

    off = 0;
    len = 0;

    while (off < chunk.length) {
      len = this.pending[0].copy(chunk, off);
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

/**
 * Parse a fully-buffered chunk.
 * @param {Buffer} chunk
 */

Parser.prototype.parse = function parse(chunk) {
  var checksum;

  if (chunk.length > constants.MAX_MESSAGE) {
    this.waiting = 24;
    this.packet = null;
    return this._error('Packet too large: %dmb.', utils.mb(chunk.length));
  }

  if (!this.packet) {
    this.packet = this.parseHeader(chunk);
    return;
  }

  this.packet.payload = chunk;

  checksum = utils.checksum(this.packet.payload).readUInt32LE(0, true);

  if (checksum !== this.packet.checksum) {
    this.waiting = 24;
    this.packet = null;
    return this._error('Invalid checksum');
  }

  try {
    this.packet.payload = this.parsePayload(this.packet.cmd, this.packet.payload);
  } catch (e) {
    this.emit('error', e);
    this.waiting = 24;
    this.packet = null;
    return;
  }

  this.emit('packet', this.packet);
  this.waiting = 24;
  this.packet = null;
};

/**
 * Parse buffered packet header.
 * @param {Buffer} h - Header.
 * @returns {Object} Packet header in the form
 * of `{cmd:String, length:Number, checksum:Number}`.
 */

Parser.prototype.parseHeader = function parseHeader(h) {
  var i, magic, cmd, chk;

  magic = h.readUInt32LE(0, true);

  if (magic !== this.network.magic)
    return this._error('Invalid magic value: ' + magic.toString(16));

  // Count length of the cmd
  for (i = 0; h[i + 4] !== 0 && i < 12; i++);

  if (i === 12)
    return this._error('Not NULL-terminated cmd');

  cmd = h.toString('ascii', 4, 4 + i);

  this.waiting = h.readUInt32LE(16, true);

  if (this.waiting > constants.MAX_MESSAGE) {
    this.waiting = 24;
    return this._error('Packet length too large: %dmb', utils.mb(this.waiting));
  }

  chk = h.readUInt32LE(20, true);

  return new Packet(cmd, this.waiting, chk);
};

/**
 * Parse mempool packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseMempool = function parseMempool(p) {
  return {};
};

/**
 * Parse submitorder packet.
 * @param {Buffer|BufferReader} p
 * @returns {SubmitOrderPacket}
 */

Parser.parseSubmitOrder = function parseSubmitOrder(p) {
  p = new BufferReader(p);
  return {
    hash: p.readHash('hex'),
    tx: Parser.parseTX(p)
  };
};

/**
 * Parse checkorder packet.
 * @param {Buffer|BufferReader} p
 * @returns {SubmitOrderPacket}
 */

Parser.parseCheckOrder = function parseCheckOrder(p) {
  return Parser.parseSubmitOrder(p);
};

/**
 * Parse reply packet.
 * @param {Buffer|BufferReader} p
 * @returns {ReplyPacket}
 */

Parser.parseReply = function parseReply(p) {
  p = new BufferReader(p);
  return {
    hash: p.readHash('hex'),
    code: p.readU32(),
    publicKey: p.readVarBytes()
  };
};

/**
 * Parse sendheaders packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseSendHeaders = function parseSendHeaders(p) {
  return {};
};

/**
 * Parse havewitness packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseHaveWitness = function parseHaveWitness(p) {
  return {};
};

/**
 * Parse getaddr packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseGetAddr = function parseGetAddr(p) {
  return {};
};

/**
 * Parse filterload packet.
 * @param {Buffer|BufferReader} p
 * @returns {Bloom}
 */

Parser.parseFilterLoad = function parseFilterLoad(p) {
  return bcoin.bloom.fromRaw(p);
};

/**
 * Parse filteradd packet.
 * @param {Buffer|BufferReader} p
 * @returns {FilterAddPacket}
 */

Parser.parseFilterAdd = function parseFilterAdd(p) {
  p = new BufferReader(p);
  return {
    data: p.readVarBytes()
  };
};

/**
 * Parse filterclear packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseFilterClear = function parseFilterClear(p) {
  return {};
};

/**
 * Parse a payload.
 * @param {String} cmd - Packet type.
 * @param {Buffer} p - Payload.
 * @returns {Object}
 */

Parser.prototype.parsePayload = function parsePayload(cmd, p) {
  switch (cmd) {
    case 'version':
      return Parser.parseVersion(p);
    case 'verack':
      return Parser.parseVerack(p);
    case 'mempool':
      return Parser.parseMempool(p);
    case 'getaddr':
      return Parser.parseGetAddr(p);
    case 'submitorder':
      return Parser.parseSubmitOrder(p);
    case 'checkorder':
      return Parser.parseCheckOrder(p);
    case 'reply':
      return Parser.parseReply(p);
    case 'sendheaders':
      return Parser.parseSendHeaders(p);
    case 'havewitness':
      return Parser.parseHaveWitness(p);
    case 'filterload':
      return Parser.parseFilterLoad(p);
    case 'filteradd':
      return Parser.parseFilterAdd(p);
    case 'filterclear':
      return Parser.parseFilterClear(p);
    case 'inv':
      return Parser.parseInv(p);
    case 'getdata':
      return Parser.parseGetData(p);
    case 'notfound':
      return Parser.parseNotFound(p);
    case 'getheaders':
      return Parser.parseGetHeaders(p);
    case 'getblocks':
      return Parser.parseGetBlocks(p);
    case 'merkleblock':
      return Parser.parseMerkleBlock(p);
    case 'headers':
      return Parser.parseHeaders(p);
    case 'block':
      return Parser.parseMemBlock(p);
    case 'tx':
      return Parser.parseTX(p);
    case 'reject':
      return Parser.parseReject(p);
    case 'addr':
      return Parser.parseAddr(p);
    case 'ping':
      return Parser.parsePing(p);
    case 'pong':
      return Parser.parsePong(p);
    case 'alert':
      return Parser.parseAlert(p);
    case 'getutxos':
      return Parser.parseGetUTXOs(p);
    case 'utxos':
      return Parser.parseUTXOs(p);
    case 'feefilter':
      return Parser.parseFeeFilter(p);
    case 'encinit':
      return Parser.parseEncinit(p);
    case 'encack':
      return Parser.parseEncack(p);
    case 'sendcmpct':
      return Parser.parseSendCmpct(p);
    case 'cmpctblock':
      return Parser.parseCmpctBlock(p);
    case 'getblocktxn':
      return Parser.parseGetBlockTxn(p);
    case 'blocktxn':
      return Parser.parseBlockTxn(p);
    default:
      return p;
  }
};

/**
 * Parse getutxos packet.
 * @param {Buffer|BufferReader} p
 * @returns {GetUTXOsPacket}
 */

Parser.parseGetUTXOs = function parseGetUTXOs(p) {
  var mempool, prevout, count, i;

  p = new BufferReader(p);

  mempool = p.readU8() === 1;
  prevout = [];
  count = p.readVarint();

  for (i = 0; i < count; i++)
    prevout.push(bcoin.outpoint.fromRaw(p));

  return {
    mempool: mempool,
    prevout: prevout
  };
};

/**
 * Parse utxos packet.
 * @param {Buffer|BufferReader} p
 * @returns {UTXOsPacket}
 */

Parser.parseUTXOs = function parseUTXOs(p) {
  var chainHeight, tip, map, count, coins;
  var coin, version, height, i, hits, j;

  p = new BufferReader(p);

  chainHeight = p.readU32();
  tip = p.readHash('hex');
  map = p.readVarBytes();
  count = p.readVarint();
  coins = [];
  hits = [];

  for (i = 0; i < map.length; i++) {
    for (j = 0; j < 8; j++)
      hits.push((map[i] >> j) & 1);
  }

  for (i = 0; i < count; i++) {
    version = p.readU32();
    height = p.readU32();

    if (height === 0x7fffffff)
      height = -1;

    coin = bcoin.output.fromRaw(p);
    coin.version = version;
    coin.height = height;
    coins.push(new bcoin.coin(coin));
  }

  return {
    height: chainHeight,
    tip: tip,
    map: map,
    coins: coins,
    hits: hits
  };
};

/**
 * Parse ping packet.
 * @param {Buffer|BufferReader} p
 * @returns {PingPacket}
 */

Parser.parsePing = function parsePing(p) {
  p = new BufferReader(p);

  return {
    nonce: p.readU64()
  };
};

/**
 * Parse pong packet.
 * @param {Buffer|BufferReader} p
 * @returns {PingPacket}
 */

Parser.parsePong = function parsePong(p) {
  p = new BufferReader(p);

  return {
    nonce: p.readU64()
  };
};

/**
 * Parse version packet.
 * @param {Buffer|BufferReader} p
 * @returns {VersionPacket}
 */

Parser.parseVersion = function parseVersion(p) {
  return bcoin.packets.VersionPacket.fromRaw(p);
};

/**
 * Parse verack packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseVerack = function parseVerack(p) {
  return {};
};

/**
 * Parse notfound packet.
 * @param {Buffer|BufferReader} p
 * @returns {InvItem[]}
 */

Parser.parseNotFound = function parseNotFound(p) {
  return Parser.parseInv(p);
};

/**
 * Parse getdata packet.
 * @param {Buffer|BufferReader} p
 * @returns {InvItem[]}
 */

Parser.parseGetData = function parseGetData(p) {
  return Parser.parseInv(p);
};

/**
 * Parse getblocks packet.
 * @param {Buffer|BufferReader} p
 * @returns {GetBlocksPacket}
 */

Parser.parseGetBlocks = function parseGetBlocks(p) {
  return bcoin.packets.GetBlocksPacket.fromRaw(p);
};

/**
 * Parse getheaders packet.
 * @param {Buffer|BufferReader} p
 * @returns {GetBlocksPacket}
 */

Parser.parseGetHeaders = function parseGetHeaders(p) {
  return bcoin.packets.GetBlocksPacket.fromRaw(p);
};

/**
 * Parse inv packet.
 * @param {Buffer|BufferReader} p
 * @returns {InvItem[]}
 */

Parser.parseInv = function parseInv(p) {
  var items = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readVarint();

  assert(count <= 50000, 'Item count too high.');

  for (i = 0; i < count; i++)
    items.push(bcoin.packets.InvItem.fromRaw(p));

  return items;
};

/**
 * Parse merkleblock packet.
 * @param {Buffer|BufferReader} p
 * @returns {Block}
 */

Parser.parseMerkleBlock = function parseMerkleBlock(p) {
  return bcoin.merkleblock.fromRaw(p);
};

/**
 * Parse headers packet.
 * @param {Buffer|BufferReader} p
 * @returns {Headers[]}
 */

Parser.parseHeaders = function parseHeaders(p) {
  var headers = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readVarint();

  for (i = 0; i < count; i++)
    headers.push(bcoin.headers.fromRaw(p));

  return headers;
};

/**
 * Parse block packet.
 * @param {Buffer|BufferReader} p
 * @returns {Block}
 */

Parser.parseBlock = function parseBlock(p) {
  return bcoin.block.fromRaw(p);
};

/**
 * Parse block packet.
 * @param {Buffer|BufferReader} p
 * @returns {Block}
 */

Parser.parseMemBlock = function parseMemBlock(p) {
  return bcoin.memblock.fromRaw(p);
};

/**
 * Parse tx packet (will automatically switch to witness
 * parsing if a witness transaction is detected).
 * @param {Buffer|BufferReader} p
 * @returns {TX}
 */

Parser.parseTX = function parseTX(p) {
  return bcoin.tx.fromRaw(p);
};

/**
 * Parse reject packet.
 * @param {Buffer|BufferReader} p
 * @returns {RejectPacket}
 */

Parser.parseReject = function parseReject(p) {
  return bcoin.packets.RejectPacket.fromRaw(p);
};

/**
 * Parse addr packet.
 * @param {Buffer|BufferReader} p
 * @returns {NetworkAddress[]}
 */

Parser.parseAddr = function parseAddr(p) {
  var addrs = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readVarint();

  assert(count <= 10000, 'Too many addresses.');

  for (i = 0; i < count; i++)
    addrs.push(bcoin.packets.NetworkAddress.fromRaw(p, true));

  return addrs;
};

/**
 * Parse mempool packet.
 * @param {Buffer|BufferReader} p
 * @returns {Object}
 */

Parser.parseMempool = function parseMempool(p) {
  return {};
};

/**
 * Parse alert packet.
 * @param {Buffer|BufferReader} p
 * @returns {AlertPacket}
 */

Parser.parseAlert = function parseAlert(p) {
  return bcoin.packets.AlertPacket.fromRaw(p);
};

/**
 * Parse feefilter packet.
 * @param {Buffer|BufferReader} p
 * @returns {FeeFilterPacket}
 */

Parser.parseFeeFilter = function parseFeeFilter(p) {
  p = new BufferReader(p);
  return {
    rate: p.read64N()
  };
};

Parser.parseEncinit = function parseEncinit(p) {
  // Handled elsewhere.
  return p;
};

Parser.parseEncack = function parseEncack(p) {
  // Handled elsewhere.
  return p;
};

Parser.parseSendCmpct = function parseSendCmpct(p) {
  return bcoin.bip152.SendCompact.fromRaw(p);
};

Parser.parseCmpctBlock = function parseCmpctBlock(p) {
  return bcoin.bip152.CompactBlock.fromRaw(p);
};

Parser.parseGetBlockTxn = function parseGetBlockTxn(p) {
  return bcoin.bip152.TXRequest.fromRaw(p);
};

Parser.parseBlockTxn = function parseBlockTxn(p) {
  return bcoin.bip152.TXResponse.fromRaw(p);
};

/**
 * Packet
 * @constructor
 * @private
 */

function Packet(cmd, size, checksum) {
  this.cmd = cmd;
  this.size = size;
  this.checksum = checksum;
  this.payload = null;
}

/*
 * Expose
 */

module.exports = Parser;
