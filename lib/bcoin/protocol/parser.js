/*!
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var utils = require('../utils');
var assert = utils.assert;
var constants = require('./constants');
var network = bcoin.protocol.network;
var BufferReader = require('../reader');

/**
 * Protocol packet parser
 * @exports Parser
 * @constructor
 * @param {Object?} options
 * @emits Parser#error
 * @emits Parser#packet
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
  if (chunk.length > constants.MAX_MESSAGE)
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

/**
 * Parse buffered packet header.
 * @param {Buffer} h - Header.
 * @returns {Object} Packet header in the form
 * of `{cmd:String, length:Number, checksum:Number}`.
 */

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

  if (this.waiting > constants.MAX_MESSAGE)
    return this._error('Packet length too large: %dmb', utils.mb(this.waiting));

  return {
    cmd: cmd,
    length: this.waiting,
    checksum: utils.readU32(h, 20)
  };
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
  var hash, tx;
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
  var hash, code, publicKey;
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
 * @returns {Object}
 */

Parser.parseFilterLoad = function parseFilterLoad(p) {
  var filter, n, tweak, update;

  p = new BufferReader(p);

  filter = p.readVarBytes();
  n = p.readU32();
  tweak = p.readU32();
  update = p.readU8();

  assert(constants.filterFlagsByVal[update] != null, 'Bad filter flag.');

  return {
    filter: filter,
    n: n,
    tweak: tweak,
    update: update
  };
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
      return Parser.parseBlockCompact(p);
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
    default:
      bcoin.debug('Unknown packet: %s', cmd);
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

  for (i = 0; i < count; i++) {
    prevout.push({
      hash: p.readHash('hex'),
      index: p.readU32()
    });
  }

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
  var coin, version, height, i, hits, ch, j;

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

    coin = Parser.parseOutput(p);
    coin.version = version;
    coin.height = height;
    coins.push(coin);
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
  var version, services, ts, recv, from, nonce, agent, height, relay;

  p = new BufferReader(p);

  version = p.read32();
  services = p.readU53();
  ts = p.read53();
  recv = Parser.parseAddress(p, false);
  from = Parser.parseAddress(p, false);
  nonce = p.readU64();
  agent = p.readVarString('ascii');
  height = p.read32();

  if (p.left() > 0)
    relay = p.readU8() === 1;
  else
    relay = true;

  assert(version >= 0, 'Version is negative.');
  assert(ts >= 0, 'Timestamp is negative.');
  assert(height >= 0, 'Height is negative.');

  return {
    version: version,
    services: services,
    network: (services & constants.services.NETWORK) !== 0,
    getutxo: (services & constants.services.GETUTXO) !== 0,
    bloom: (services & constants.services.BLOOM) !== 0,
    witness: (services & constants.services.WITNESS) !== 0,
    ts: ts,
    local: recv,
    remote: from,
    nonce: nonce,
    agent: agent,
    height: height,
    relay: relay
  };
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

Parser._parseGetBlocks = function _parseGetBlocks(p) {
  var version, count, locator, i, stop;

  p = new BufferReader(p);

  version = p.readU32();
  count = p.readVarint();
  locator = [];

  for (i = 0; i < count; i++)
    locator.push(p.readHash('hex'));

  stop = p.readHash('hex');

  if (stop === constants.NULL_HASH)
    stop = null;

  return {
    version: version,
    locator: locator,
    stop: stop
  };
};

/**
 * Parse getblocks packet.
 * @param {Buffer|BufferReader} p
 * @returns {GetBlocksPacket}
 */

Parser.parseGetBlocks = function parseGetBlocks(p) {
  var data = Parser._parseGetBlocks(p);
  assert(data.locator.length > 0, 'getblocks requires a locator.');
  return data;
};

/**
 * Parse getheaders packet.
 * @param {Buffer|BufferReader} p
 * @returns {GetBlocksPacket}
 */

Parser.parseGetHeaders = function parseGetHeaders(p) {
  var data = Parser._parseGetBlocks(p);
  if (data.locator.length === 0)
    data.locator = null;
  return data;
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

  assert(count < 50000, 'Item count too high.');

  for (i = 0; i < count; i++) {
    items.push({
      type: p.readU32(),
      hash: p.readHash('hex')
    });
  }

  return items;
};

/**
 * Parse merkleblock packet.
 * @param {Buffer|BufferReader} p
 * @returns {NakedBlock}
 */

Parser.parseMerkleBlock = function parseMerkleBlock(p) {
  var version, prevBlock, merkleRoot, ts, bits, nonce, totalTX;
  var i, hashCount, hashes, flags;

  p = new BufferReader(p);

  version = p.readU32();
  prevBlock = p.readHash('hex');
  merkleRoot = p.readHash('hex');
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readU32();

  hashCount = p.readVarint();

  hashes = new Array(hashCount);

  for (i = 0; i < hashCount; i++)
    hashes[i] = p.readHash('hex');

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
    flags: flags
  };
};

/**
 * Parse headers packet.
 * @param {Buffer|BufferReader} p
 * @returns {NakedBlock[]}
 */

Parser.parseHeaders = function parseHeaders(p) {
  var headers = [];
  var i, count;

  p = new BufferReader(p);

  count = p.readVarint();

  for (i = 0; i < count; i++) {
    headers.push({
      version: p.readU32(), // Technically signed
      prevBlock: p.readHash('hex'),
      merkleRoot: p.readHash('hex'),
      ts: p.readU32(),
      bits: p.readU32(),
      nonce: p.readU32(),
      totalTX: p.readVarint()
    });
  }

  return headers;
};

/**
 * Parse headers packet.
 * @param {Buffer|BufferReader} p
 * @returns {NakedBlock}
 */

Parser.parseBlockHeaders = function parseBlockHeaders(p) {
  p = new BufferReader(p);

  return {
    version: p.readU32(), // Technically signed
    prevBlock: p.readHash('hex'),
    merkleRoot: p.readHash('hex'),
    ts: p.readU32(),
    bits: p.readU32(),
    nonce: p.readU32()
  }
};

/**
 * Parse block packet.
 * @param {Buffer|BufferReader} p
 * @returns {NakedBlock}
 */

Parser.parseBlock = function parseBlock(p) {
  var txs = [];
  var version, prevBlock, merkleRoot, ts, bits, nonce;
  var i, totalTX, tx;

  p = new BufferReader(p);

  version = p.readU32(); // Technically signed
  prevBlock = p.readHash('hex');
  merkleRoot = p.readHash('hex');
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readVarint();

  for (i = 0; i < totalTX; i++) {
    tx = Parser.parseTX(p);
    txs.push(tx);
  }

  return {
    version: version,
    prevBlock: prevBlock,
    merkleRoot: merkleRoot,
    ts: ts,
    bits: bits,
    nonce: nonce,
    txs: txs
  };
};

/**
 * Parse block packet.
 * @param {Buffer|BufferReader} p
 * @returns {NakedBlock}
 */

Parser.parseBlockCompact = function parseBlockCompact(p) {
  var version, prevBlock, merkleRoot;
  var ts, bits, nonce, totalTX, height;
  var inCount, input;

  p = new BufferReader(p);

  version = p.readU32(); // Technically signed
  prevBlock = p.readHash('hex');
  merkleRoot = p.readHash('hex');
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();

  totalTX = p.readVarint();

  if (version > 1 && totalTX > 0) {
    p.readU32(); // Technically signed
    inCount = p.readVarint();

    if (inCount === 0) {
      if (p.readU8() === 0)
        throw new Error('Invalid witness tx (flag == 0)');
      inCount = p.readVarint();
    }

    if (inCount > 0)
      input = Parser.parseInput(p);
  }

  if (input)
    height = bcoin.script.getCoinbaseHeight(input.script.code);
  else
    height = -1;

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
    raw: p.data
  };
};

/**
 * Parse serialized input.
 * @param {Buffer|BufferReader} p
 * @returns {NakedInput}
 */

Parser.parseInput = function parseInput(p) {
  var hash, index, script, sequence;

  p = new BufferReader(p);

  hash = p.readHash('hex');
  index = p.readU32();
  script = Parser.parseScript(p);
  sequence = p.readU32();

  return {
    prevout: {
      hash: hash,
      index: index
    },
    coin: null,
    script: script,
    sequence: sequence
  };
};

/**
 * Parse serialized output.
 * @param {Buffer|BufferReader} p
 * @returns {NakedOutput}
 */

Parser.parseOutput = function parseOutput(p) {
  var value, script;

  p = new BufferReader(p);

  value = p.read64();
  script = Parser.parseScript(p);

  return {
    value: value,
    script: script
  };
};

/**
 * Parse serialized coin.
 * @param {Buffer|BufferReader} p
 * @param {Boolean} extended - Whether to parse the hash and index.
 * @returns {NakedCoin}
 */

Parser.parseCoin = function parseCoin(p, extended) {
  var version, height, value, script, hash, index, coinbase;

  p = new BufferReader(p);

  version = p.readU32();
  height = p.readU32();
  value = p.read64();
  script = Parser.parseScript(p);
  coinbase = p.readU8() === 1;

  if (extended) {
    hash = p.readHash('hex');
    index = p.readU32();
  }

  if (height === 0x7fffffff)
    height = -1;

  return {
    version: version,
    height: height,
    value: value,
    script: script,
    coinbase: coinbase,
    hash: hash,
    index: index
  };
};

/**
 * Parse tx packet (will automatically switch to witness
 * parsing if a witness transaction is detected).
 * @param {Buffer|BufferReader} p
 * @returns {NakedTX}
 */

Parser.parseTX = function parseTX(p) {
  var inCount, inputs;
  var outCount, outputs;
  var version, locktime, i;

  if (Parser.isWitnessTX(p))
    return Parser.parseWitnessTX(p);

  p = new BufferReader(p);

  version = p.readU32(); // Technically signed
  inCount = p.readVarint();

  inputs = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    inputs[i] = Parser.parseInput(p);
    inputs[i].witness = { items: [] };
  }

  outCount = p.readVarint();
  outputs = new Array(outCount);
  for (i = 0; i < outCount; i++)
    outputs[i] = Parser.parseOutput(p);

  locktime = p.readU32();

  return {
    version: version,
    flag: 1,
    inputs: inputs,
    outputs: outputs,
    locktime: locktime
  };
};

/**
 * Test whether data is a witness transaction.
 * @param {Buffer|BufferReader} p
 * @returns {Boolean}
 */

Parser.isWitnessTX = function isWitnessTX(p) {
  if (Buffer.isBuffer(p)) {
    if (p.length < 12)
      return false;

    return p[4] === 0 && p[5] !== 0;
  }

  if (p.left() < 12)
    return false;

  return p.data[p.offset + 4] === 0 && p.data[p.offset + 5] !== 0;
};

/**
 * Parse tx packet in witness serialization.
 * @param {Buffer|BufferReader} p
 * @returns {NakedTX}
 */

Parser.parseWitnessTX = function parseWitnessTX(p) {
  var inCount, inputs, witness;
  var outCount, outputs;
  var marker, flag;
  var version, locktime, i;

  p = new BufferReader(p);

  version = p.readU32(); // Technically signed
  marker = p.readU8();

  if (marker !== 0)
    throw new Error('Invalid witness tx (marker != 0)');

  flag = p.readU8();

  if (flag === 0)
    throw new Error('Invalid witness tx (flag == 0)');

  inCount = p.readVarint();

  inputs = new Array(inCount);
  for (i = 0; i < inCount; i++)
    inputs[i] = Parser.parseInput(p);

  outCount = p.readVarint();

  outputs = new Array(outCount);
  for (i = 0; i < outCount; i++)
    outputs[i] = Parser.parseOutput(p);

  for (i = 0; i < inCount; i++) {
    witness = Parser.parseWitness(p);
    inputs[i].witness = witness;
  }

  locktime = p.readU32();

  return {
    version: version,
    flag: flag,
    inputs: inputs,
    outputs: outputs,
    locktime: locktime
  };
};

/**
 * Parse serialized script (with varint length).
 * @param {Buffer|BufferReader} p
 * @returns {NakedScript}
 */

Parser.parseScript = function parseScript(p) {
  var data;

  p = new BufferReader(p);
  data = p.readVarBytes();

  return {
    raw: data,
    code: bcoin.script.decode(data)
  };
};

/**
 * Parse serialized witness.
 * @param {Buffer|BufferReader} p
 * @returns {NakedWitness}
 */

Parser.parseWitness = function parseWitness(p) {
  var items = [];
  var chunkCount, i;

  p = new BufferReader(p);

  chunkCount = p.readVarint();

  for (i = 0; i < chunkCount; i++)
    items.push(p.readVarBytes());

  return {
    items: items
  };
};

/**
 * Parse reject packet.
 * @param {Buffer|BufferReader} p
 * @returns {RejectPacket}
 */

Parser.parseReject = function parseReject(p) {
  var message, ccode, reason, data;

  p = new BufferReader(p);

  message = p.readVarString('ascii');
  ccode = p.readU8();
  reason = p.readVarString('ascii');

  if (p.left() >= 32)
    data = p.readHash('hex');
  else
    data = null;

  return {
    message: message,
    ccode: constants.rejectByVal[ccode] || ccode,
    reason: reason,
    data: data
  };
};

/**
 * Parse serialized network address.
 * @param {Buffer|BufferReader} p
 * @returns {NetworkAddress}
 */

Parser.parseAddress = function parseAddress(p, full) {
  var ts, services, ip, port;

  p = new BufferReader(p);

  if (full) // only version >= 31402
    ts = p.readU32();
  else
    ts = 0;

  services = p.readU53();

  ip = p.readBytes(16);

  port = p.readU16BE();

  return {
    ts: ts,
    services: services,
    network: (services & constants.services.NETWORK) !== 0,
    getutxo: (services & constants.services.GETUTXO) !== 0,
    bloom: (services & constants.services.BLOOM) !== 0,
    witness: (services & constants.services.WITNESS) !== 0,
    ipv6: utils.array2ip(ip, 6),
    ipv4: utils.array2ip(ip, 4),
    port: port
  };
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

  for (i = 0; i < count; i++)
    addrs.push(Parser.parseAddress(p, true));

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
  var version, relayUntil, expiration, id, cancel;
  var cancels, count, i, minVer, maxVer, subVers;
  var priority, comment, statusBar, reserved;
  var payload;

  p = new BufferReader(p);

  payload = p.readVarBytes();
  signature = p.readVarBytes();

  p = new BufferReader(payload);

  version = p.read32();
  relayUntil = p.read53();
  expiration = p.read53();
  id = p.read32();
  cancel = p.read32();
  cancels = [];
  count = p.readVarint();
  for (i = 0; i < count; i++)
    cancels.push(p.read32());
  minVer = p.read32();
  maxVer = p.read32();
  subVers = [];
  count = p.readVarint();
  for (i = 0; i < count; i++)
    subVers.push(p.readVarString('ascii'));
  priority = p.read32();
  comment = p.readVarString('ascii');
  statusBar = p.readVarString('ascii');
  reserved = p.readVarString('ascii');

  return {
    version: version,
    relayUntil: relayUntil,
    expiration: expiration,
    id: id,
    cancel: cancel,
    cancels: cancels,
    minVer: minVer,
    maxVer: maxVer,
    subVers: subVers,
    priority: priority,
    comment: comment,
    statusBar: statusBar,
    reserved: reserved,
    payload: payload,
    signature: signature
  };
};

return Parser;
};
