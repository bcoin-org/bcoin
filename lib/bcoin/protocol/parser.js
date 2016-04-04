/**
 * parser.js - packet parser for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../../bcoin');
var utils = require('../utils');
var assert = utils.assert;
var constants = require('./constants');
var network = require('./network');
var BufferReader = require('../reader');

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
  this.version = constants.minVersion;
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

Parser.parseMempool = function parseMempool(p) {
  return {};
};

Parser.parseSubmitOrder = function parseSubmitOrder(p) {
  var hash, tx;
  p = new BufferReader(p);
  p.start();
  return {
    hash: p.readHash(),
    tx: Parser.parseTX(p),
    _size: p.end()
  };
};

Parser.parseCheckOrder = function parseCheckOrder(p) {
  return Parser.parseSubmitOrder(p);
};

Parser.parseReply = function parseReply(p) {
  var hash, code, publicKey;
  p = new BufferReader(p);
  p.start();
  return {
    hash: p.readHash(),
    code: p.readU32(),
    publicKey: p.readVarBytes(),
    _size: p.end()
  };
};

Parser.parseSendHeaders = function parseSendHeaders(p) {
  return {};
};

Parser.parseHaveWitness = function parseHaveWitness(p) {
  return {};
};

Parser.parseGetAddr = function parseGetAddr(p) {
  return {};
};

Parser.parseFilterLoad = function parseFilterLoad(p) {
  return {};
};

Parser.parseFilterAdd = function parseFilterAdd(p) {
  p = new BufferReader(p);
  p.start();
  return {
    data: p.readVarBytes(),
    _size: p.end()
  };
};

Parser.parseFilterClear = function parseFilterClear(p) {
  return {};
};

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
      utils.debug('Unknown packet: %s', cmd);
      return p;
  }
};

Parser.parseGetUTXOs = function parseGetUTXOs(p) {
  var mempool, prevout, count, i;

  p = new BufferReader(p);
  p.start();

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
    prevout: prevout,
    _size: p.end()
  };
};

Parser.parseUTXOs = function parseUTXOs(p) {
  var chainHeight, tip, map, count, coins;
  var coin, version, height, i, notfound, ch, j;

  p = new BufferReader(p);
  p.start();

  chainHeight = p.readU32();
  tip = p.readHash('hex');
  map = p.readVarBytes();
  count = p.readVarint();
  coins = [];
  notfound = [];

  for (i = 0; i < map.length; i++) {
    ch = map[i];
    for (j = 0; j < 8; j++) {
      if ((ch & 1) === 0)
        notfound.push(i + j);
      ch >>>= 1;
    }
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
    notfound: notfound,
    _size: p.end()
  };
};

Parser.parsePing = function parsePing(p) {
  p = new BufferReader(p);
  p.start();

  return {
    nonce: p.readU64(),
    _size: p.end()
  };
};

Parser.parsePong = function parsePong(p) {
  p = new BufferReader(p);
  p.start();

  return {
    nonce: p.readU64(),
    _size: p.end()
  };
};

Parser.parseVersion = function parseVersion(p) {
  var version, services, ts, recv, from, nonce, agent, height, relay;

  p = new BufferReader(p);
  p.start();

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

  this.version = version;

  return {
    version: version,
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
    relay: relay,
    _size: p.end()
  };
};

Parser.parseVerack = function parseVerack(p) {
  return {};
};

Parser.parseNotFound = function parseNotFound(p) {
  return Parser.parseInv(p);
};

Parser.parseGetData = function parseGetData(p) {
  return Parser.parseInv(p);
};

Parser._parseGetBlocks = function _parseGetBlocks(p) {
  var version, count, locator, i, stop;

  p = new BufferReader(p);
  p.start();

  version = p.readU32();
  count = p.readVarint();
  locator = [];

  for (i = 0; i < count; i++)
    locator.push(p.readHash('hex'));

  stop = p.readHash('hex');

  if (stop === constants.nullHash)
    stop = null;

  return {
    version: version,
    locator: locator,
    stop: stop,
    _size: p.end()
  };
};

Parser.parseGetBlocks = function parseGetBlocks(p) {
  var data = Parser._parseGetBlocks(p);
  assert(data.locator.length > 0, 'getblocks requires a locator.');
  return data;
};

Parser.parseGetHeaders = function parseGetHeaders(p) {
  var data = Parser._parseGetBlocks(p);
  if (data.locator.length === 0)
    data.locator = null;
  return data;
};

Parser.parseInv = function parseInv(p) {
  var items = [];
  var i, count;

  p = new BufferReader(p);
  p.start();

  count = p.readVarint();

  for (i = 0; i < count; i++) {
    items.push({
      type: p.readU32(),
      hash: p.readHash()
    });
  }

  items._size = p.end();

  return items;
};

Parser.parseMerkleBlock = function parseMerkleBlock(p) {
  var version, prevBlock, merkleRoot, ts, bits, nonce, totalTX;
  var i, hashCount, hashes, flags;

  p = new BufferReader(p);
  p.start();

  version = p.readU32(); // Technically signed
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readU32();

  hashCount = p.readVarint();

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
  p.start();

  count = p.readVarint();

  for (i = 0; i < count; i++) {
    headers.push({
      version: p.readU32(), // Technically signed
      prevBlock: p.readHash(),
      merkleRoot: p.readHash(),
      ts: p.readU32(),
      bits: p.readU32(),
      nonce: p.readU32(),
      totalTX: p.readVarint()
    });
  }

  headers._size = p.end();

  return headers;
};

Parser.parseBlockHeaders = function parseBlockHeaders(p) {
  p = new BufferReader(p);
  p.start();

  return {
    version: p.readU32(), // Technically signed
    prevBlock: p.readHash('hex'),
    merkleRoot: p.readHash('hex'),
    ts: p.readU32(),
    bits: p.readU32(),
    nonce: p.readU32(),
    totalTX: p.readVarint(),
    _size: p.end()
  }
};

Parser.parseBlock = function parseBlock(p) {
  var txs = [];
  var witnessSize = 0;
  var version, prevBlock, merkleRoot, ts, bits, nonce;
  var i, totalTX, tx;

  p = new BufferReader(p);
  p.start();

  version = p.readU32(); // Technically signed
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
  ts = p.readU32();
  bits = p.readU32();
  nonce = p.readU32();
  totalTX = p.readVarint();

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
    _witnessSize: witnessSize,
    _size: p.end()
  };
};

Parser.parseBlockCompact = function parseBlockCompact(p) {
  var version, prevBlock, merkleRoot, ts, bits, nonce;
  var totalTX, height;
  var inCount, input, raw;

  p = new BufferReader(p);
  p.start();

  version = p.readU32(); // Technically signed
  prevBlock = p.readHash();
  merkleRoot = p.readHash();
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
  script = Parser.parseScript(p);
  sequence = p.readU32();

  return {
    prevout: {
      hash: hash,
      index: index
    },
    coin: null,
    script: script,
    sequence: sequence,
    _size: p.end()
  };
};

Parser.parseOutput = function parseOutput(p) {
  var value, script;

  p = new BufferReader(p);
  p.start();

  value = p.read64();
  script = Parser.parseScript(p);

  return {
    value: value,
    script: script,
    _size: p.end()
  };
};

Parser.parseUTXO = function parseUTXO(p) {
  var version, height, value, script;

  p = new BufferReader(p);
  p.start();

  version = p.readU32();
  height = p.readU32();
  value = p.read64();
  script = Parser.parseScript(p);

  if (height === 0x7fffffff)
    height = -1;

  return {
    version: version,
    height: height,
    value: value,
    script: script,
    _size: p.end()
  };
};

Parser.parseCoin = function parseCoin(p, extended) {
  var version, height, value, script, hash, index, coinbase;

  p = new BufferReader(p);
  p.start();

  version = p.readU32();
  height = p.readU32();
  value = p.read64();
  script = Parser.parseScript(p);
  coinbase = p.readU8() === 1;

  if (extended) {
    hash = p.readHash();
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
    index: index,
    _size: p.end()
  };
};

Parser.parseTX = function parseTX(p) {
  var inCount, txIn, tx;
  var outCount, txOut;
  var version, locktime, i;
  var raw;

  if (Parser.isWitnessTX(p))
    return Parser.parseWitnessTX(p);

  p = new BufferReader(p);
  p.start();

  version = p.readU32(); // Technically signed
  inCount = p.readVarint();

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = Parser.parseInput(p);

    txIn[i] = tx;
    txIn[i].witness = { items: [] };
  }

  outCount = p.readVarint();
  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = Parser.parseOutput(p);
    txOut[i] = tx;
  }

  locktime = p.readU32();

  raw = p.endData();

  return {
    version: version,
    flag: 1,
    inputs: txIn,
    outputs: txOut,
    locktime: locktime,
    _witnessSize: 0,
    _raw: raw,
    _size: raw.length
    // _size: p.end()
  };
};

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

Parser.parseWitnessTX = function parseWitnessTX(p) {
  var inCount, txIn, tx;
  var outCount, txOut;
  var marker, flag;
  var version, locktime, i;
  var witnessSize = 0;
  var raw;

  p = new BufferReader(p);
  p.start();

  version = p.readU32(); // Technically signed
  marker = p.readU8();

  if (marker !== 0)
    throw new Error('Invalid witness tx (marker != 0)');

  flag = p.readU8();

  if (flag === 0)
    throw new Error('Invalid witness tx (flag == 0)');

  inCount = p.readVarint();

  txIn = new Array(inCount);
  for (i = 0; i < inCount; i++) {
    tx = Parser.parseInput(p);
    txIn[i] = tx;
  }

  outCount = p.readVarint();

  txOut = new Array(outCount);
  for (i = 0; i < outCount; i++) {
    tx = Parser.parseOutput(p);
    txOut[i] = tx;
  }

  for (i = 0; i < inCount; i++) {
    tx = Parser.parseWitness(p);
    txIn[i].witness = tx;
    witnessSize += tx._size;
  }

  locktime = p.readU32();

  raw = p.endData();

  return {
    version: version,
    flag: flag,
    inputs: txIn,
    outputs: txOut,
    locktime: locktime,
    _raw: raw,
    _size: raw.length,
    // _size: p.end(),
    _witnessSize: witnessSize + 2
  };
};

Parser.parseScript = function parseScript(p) {
  var data;

  p = new BufferReader(p);
  p.start();
  data = p.readVarBytes();

  return {
    raw: data,
    code: bcoin.script.decode(data),
    _size: p.end()
  };
};

Parser.parseWitness = function parseWitness(p) {
  var items = [];
  var chunkCount, i;

  p = new BufferReader(p);
  p.start();

  chunkCount = p.readVarint();

  for (i = 0; i < chunkCount; i++)
    items.push(p.readVarBytes());

  return {
    items: items,
    _size: p.end()
  };
};

Parser.parseReject = function parseReject(p) {
  var message, ccode, reason, data;

  p = new BufferReader(p);
  p.start();

  message = p.readVarString('ascii');
  ccode = p.readU8();
  reason = p.readVarString('ascii');

  try {
    data = p.readHash();
  } catch (e) {
    data = null;
  }

  return {
    message: message,
    ccode: constants.rejectByVal[ccode] || ccode,
    reason: reason,
    data: data,
    _size: p.end()
  };
};

Parser.parseAddress = function parseAddress(p, full) {
  var ts, services, ip, port;

  p = new BufferReader(p);
  p.start();

  if (full && this.version >= 31402)
    ts = p.readU32();
  else
    ts = 0;

  services = p.readU53();

  ip = p.readBytes(16);

  port = p.readU16BE();

  return {
    ts: ts,
    services: services,
    network: (services & constants.services.network) !== 0,
    getutxo: (services & constants.services.getutxo) !== 0,
    bloom: (services & constants.services.bloom) !== 0,
    witness: (services & constants.services.witness) !== 0,
    ipv6: utils.array2ip(ip, 6),
    ipv4: utils.array2ip(ip, 4),
    port: port,
    _size: p.end()
  };
};

Parser.parseAddr = function parseAddr(p) {
  var addrs = [];
  var i, count;

  p = new BufferReader(p);
  p.start();

  count = p.readVarint();

  for (i = 0; i < count; i++)
    addrs.push(Parser.parseAddress(p, true));

  addrs._size = p.end();

  return addrs;
};

Parser.parseMempool = function parseMempool(p) {
  return {};
};

Parser.parseAlert = function parseAlert(p) {
  var version, relayUntil, expiration, id, cancel;
  var cancels, count, i, minVer, maxVer, subVers;
  var priority, comment, statusBar, reserved;
  var payload, size;

  p = new BufferReader(p);
  p.start();

  payload = p.readVarBytes();
  signature = p.readVarBytes();
  size = p.end();

  p = new BufferReader(payload);
  p.start();
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
  p.end();

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
    signature: signature,
    _size: size
  };
};

/**
 * Expose
 */

module.exports = Parser;
