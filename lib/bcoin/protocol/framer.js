/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../env');
var constants = require('./constants');
var utils = require('../utils');
var assert = utils.assert;
var BufferWriter = require('../writer');
var DUMMY = new Buffer([]);

/**
 * Protocol packet framer
 * @exports Framer
 * @constructor
 * @param {Object} options
 */

function Framer(options) {
  if (!(this instanceof Framer))
    return new Framer(options);

  if (!options)
    options = {};

  this.options = options;
  this.network = bcoin.network.get(options.network);
}

/**
 * Create a header for a payload.
 * @param {String} cmd - Packet type.
 * @param {Buffer} payload
 * @returns {Buffer} Header.
 */

Framer.prototype.header = function header(cmd, payload, checksum) {
  var h = new Buffer(24);
  var len, i;

  cmd = new Buffer(cmd, 'ascii');

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  // Magic value
  h.writeUInt32LE(this.network.magic, 0, true);

  // Command
  len = cmd.copy(h, 4);
  for (i = 4 + len; i < 4 + 12; i++)
    h[i] = 0;

  // Payload length
  h.writeUInt32LE(payload.length, 16, true);

  if (!checksum)
    checksum = utils.dsha256(payload);

  // Checksum
  checksum.copy(h, 20, 0, 4);

  return h;
};

/**
 * Frame a payload with a header.
 * @param {String} cmd - Packet type.
 * @param {Buffer} payload
 * @returns {Buffer} Payload with header prepended.
 */

Framer.prototype.packet = function packet(cmd, payload, checksum) {
  var header;

  assert(payload, 'No payload.');

  header = this.header(cmd, payload, checksum);

  return Buffer.concat([header, payload]);
};

/**
 * Create a version packet with a header.
 * @param {Object} options - See {@link Framer.version}.
 * @returns {Buffer} version packet.
 */

Framer.prototype.version = function version(options) {
  return this.packet('version', Framer.version(options));
};

/**
 * Create a verack packet with a header.
 * See {@link Framer.verack}.
 * @returns {Buffer} verack packet.
 */

Framer.prototype.verack = function verack() {
  return this.packet('verack', Framer.verack());
};

/**
 * Create a mempool packet with a header.
 * See {@link Framer.mempool}.
 * @returns {Buffer} mempool packet.
 */

Framer.prototype.mempool = function mempool() {
  return this.packet('mempool', Framer.mempool());
};

/**
 * Create a getutxos packet with a header.
 * @param {Object} data - See {@link Framer.getUTXOs}.
 * @returns {Buffer} getutxos packet.
 */

Framer.prototype.getUTXOs = function getUTXOs(data) {
  return this.packet('getutxos', Framer.getUTXOs(data));
};

/**
 * Create a utxos packet with a header.
 * @param {Object} data - See {@link Framer.utxos}.
 * @returns {Buffer} utxos packet.
 */

Framer.prototype.UTXOs = function UTXOs(data) {
  return this.packet('utxos', Framer.UTXOs(data));
};

/**
 * Create a getaddr packet with a header.
 * @returns {Buffer} getaddr packet.
 */

Framer.prototype.getAddr = function getAddr() {
  return this.packet('getaddr', Framer.getAddr());
};

/**
 * Create a submitorder packet with a header.
 * @param {Object} order - See {@link Framer.submitOrder}.
 * @returns {Buffer} submitorder packet.
 */

Framer.prototype.submitOrder = function submitOrder(order) {
  return this.packet('submitorder', Framer.submitOrder(order));
};

/**
 * Create a checkorder packet with a header.
 * @param {Object} order - See {@link Framer.checkOrder}.
 * @returns {Buffer} checkorder packet.
 */

Framer.prototype.checkOrder = function checkOrder(order) {
  return this.packet('checkorder', Framer.checkOrder(order));
};

/**
 * Create a reply packet with a header.
 * @param {Object} data - See {@link Framer.reply}.
 * @returns {Buffer} reply packet.
 */

Framer.prototype.reply = function reply(data) {
  return this.packet('reply', Framer.reply(data));
};

/**
 * Create a sendheaders packet with a header.
 * @param {Object} options - See {@link Framer.sendHeaders}.
 * @returns {Buffer} sendheaders packet.
 */

Framer.prototype.sendHeaders = function sendHeaders() {
  return this.packet('sendheaders', Framer.sendHeaders());
};

/**
 * Create a havewitness packet with a header.
 * @returns {Buffer} havewitness packet.
 */

Framer.prototype.haveWitness = function haveWitness() {
  return this.packet('havewitness', Framer.haveWitness());
};

/**
 * Create a filteradd packet with a header.
 * @param {Object} data - See {@link Framer.filteradd}.
 * @returns {Buffer} filteradd packet.
 */

Framer.prototype.filterAdd = function filterAdd(data) {
  return this.packet('filteradd', Framer.filterAdd(data));
};

/**
 * Create a filterclear packet with a header.
 * @returns {Buffer} filterclear packet.
 */

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', Framer.filterClear());
};

/**
 * Create an inv packet with a header.
 * @param {Object} items - See {@link Framer.inv}.
 * @returns {Buffer} inv packet.
 */

Framer.prototype.inv = function inv(items) {
  return this.packet('inv', Framer.inv(items));
};

/**
 * Create a getdata packet with a header.
 * @param {Object} items - See {@link Framer.getData}.
 * @returns {Buffer} getdata packet.
 */

Framer.prototype.getData = function getData(items) {
  return this.packet('getdata', Framer.getData(items));
};

/**
 * Create a notfound packet with a header.
 * @param {Object} items - See {@link Framer.notFound}.
 * @returns {Buffer} notfound packet.
 */

Framer.prototype.notFound = function notFound(items) {
  return this.packet('notfound', Framer.notFound(items));
};

/**
 * Create a ping packet with a header.
 * @param {Object} data - See {@link Framer.ping}.
 * @returns {Buffer} ping packet.
 */

Framer.prototype.ping = function ping(data) {
  return this.packet('ping', Framer.ping(data));
};

/**
 * Create a pong packet with a header.
 * @param {Object} data - See {@link Framer.pong}.
 * @returns {Buffer} pong packet.
 */

Framer.prototype.pong = function pong(data) {
  return this.packet('pong', Framer.pong(data));
};

/**
 * Create a filterload packet with a header.
 * @param {Object} data - See {@link Framer.filterLoad}.
 * @returns {Buffer} filterload packet.
 */

Framer.prototype.filterLoad = function filterLoad(data) {
  return this.packet('filterload', Framer.filterLoad(data));
};

/**
 * Create a getheaders packet with a header.
 * @param {Object} options - See {@link Framer.getHeaders}.
 * @returns {Buffer} getheaders packet.
 */

Framer.prototype.getHeaders = function getHeaders(data) {
  return this.packet('getheaders', Framer.getHeaders(data));
};

/**
 * Create a getblocks packet with a header.
 * @param {Object} data - See {@link Framer.getBlocks}.
 * @returns {Buffer} getblocks packet.
 */

Framer.prototype.getBlocks = function getBlocks(data) {
  return this.packet('getblocks', Framer.getBlocks(data));
};

/**
 * Create a tx packet with a header.
 * @param {TX} tx - See {@link Framer.tx}.
 * @returns {Buffer} tx packet.
 */

Framer.prototype.tx = function tx(tx) {
  var checksum;

  // Save some time by using the
  // cached hash as our checksum.
  if (tx.hash)
    checksum = tx.hash();

  return this.packet('tx', Framer.renderTX(tx, false), checksum);
};

/**
 * Create a tx packet with a header, using witness serialization.
 * @param {TX} tx - See {@link Framer.witnessTX}.
 * @returns {Buffer} tx packet.
 */

Framer.prototype.witnessTX = function witnessTX(tx) {
  var checksum;

  // Save some time by using the
  // cached hash as our checksum.
  if (tx.witnessHash) {
    if (tx.hasWitness()) {
      // We can't use the coinbase
      // hash since it is all zeroes.
      if (!tx.isCoinbase())
        checksum = tx.witnessHash();
    } else {
      checksum = tx.hash();
    }
  }

  return this.packet('tx', Framer.renderTX(tx, true), checksum);
};

/**
 * Create a block packet with a header.
 * @param {Block} block - See {@link Framer.block}.
 * @returns {Buffer} block packet.
 */

Framer.prototype.block = function _block(block) {
  return this.packet('block', Framer.block(block));
};

/**
 * Create a block packet with a header, using witness serialization.
 * @param {Block} block - See {@link Framer.witnessBlock}.
 * @returns {Buffer} block packet.
 */

Framer.prototype.witnessBlock = function witnessBlock(block) {
  return this.packet('block', Framer.witnessBlock(block));
};

/**
 * Create a merkleblock packet with a header.
 * @param {MerkleBlock} block - See {@link Framer.merkleBlock}.
 * @returns {Buffer} merkleblock packet.
 */

Framer.prototype.merkleBlock = function merkleBlock(block) {
  return this.packet('merkleblock', Framer.merkleBlock(block));
};

/**
 * Create a headers packet with a header.
 * @param {Headers[]} headers - See {@link Framer.headers}.
 * @returns {Buffer} headers packet.
 */

Framer.prototype.headers = function _headers(headers) {
  return this.packet('headers', Framer.headers(headers));
};

/**
 * Create a reject packet with a header.
 * @param {Object} details - See {@link Framer.reject}.
 * @returns {Buffer} reject packet.
 */

Framer.prototype.reject = function reject(details) {
  return this.packet('reject', Framer.reject(details));
};

/**
 * Create an addr packet with a header.
 * @param {Object} peers - See {@link Framer.addr}.
 * @returns {Buffer} addr packet.
 */

Framer.prototype.addr = function addr(peers) {
  return this.packet('addr', Framer.addr(peers));
};

/**
 * Create an alert packet with a header.
 * @param {Object} options - See {@link Framer.alert}.
 * @returns {Buffer} alert packet.
 */

Framer.prototype.alert = function alert(options) {
  options.network = this.network;
  return this.packet('alert', Framer.alert(options));
};

/**
 * Create a feefilter packet with a header.
 * @param {Object} options - See {@link Framer.feefilter}.
 * @returns {Buffer} feefilter packet.
 */

Framer.prototype.feeFilter = function feeFilter(options) {
  return this.packet('feefilter', Framer.feeFilter(options));
};

/**
 * Serialize an address.
 * @param {NetworkAddress} data
 * @param {Boolean?} full - Whether to include the timestamp.
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.address = function address(data, full, writer) {
  var p = new BufferWriter(writer);

  if (full) {
    if (!data.ts)
      p.writeU32(utils.now() - (process.uptime() | 0));
    else
      p.writeU32(data.ts);
  }

  p.writeU64(data.services || 0);
  p.writeBytes(utils.ip.toBuffer(data.host));
  p.writeU16BE(data.port || 0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a version packet (without a header).
 * @param {VersionPacket} options
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.version = function version(options, writer) {
  var p = new BufferWriter(writer);
  var agent = options.agent || constants.USER_AGENT;
  var services = options.services;
  var remote = options.remote || {};
  var local = options.local || {};
  var nonce = options.nonce;

  if (services == null)
    services = constants.LOCAL_SERVICES;

  if (local.services == null)
    local.services = constants.LOCAL_SERVICES;

  if (!nonce)
    nonce = utils.nonce();

  p.write32(options.version || constants.VERSION);
  p.writeU64(services);
  p.write64(options.ts || bcoin.now());
  Framer.address(remote, false, p);
  Framer.address(local, false, p);
  p.writeU64(nonce);
  p.writeVarString(agent, 'ascii');
  p.write32(options.height || 0);
  p.writeU8(options.relay ? 1 : 0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a verack packet (without a header).
 * @returns {Buffer}
 */

Framer.verack = function verack() {
  return DUMMY;
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
      type = constants.inv[items[i].type.toUpperCase()];
    assert(constants.invByVal[type] != null);
    p.writeU32(type);
    p.writeHash(items[i].hash);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create an inv packet (without a header).
 * @param {InvItem[]} items
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.inv = function inv(items, writer) {
  return Framer._inv(items, writer);
};

/**
 * Create a getdata packet (without a header).
 * @param {InvItem[]} items
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getData = function getData(items, writer) {
  return Framer._inv(items, writer);
};

/**
 * Create a notfound packet (without a header).
 * @param {InvItem[]} items
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.notFound = function notFound(items, writer) {
  return Framer._inv(items, writer);
};

/**
 * Create a ping packet (without a header).
 * @param {PingPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.ping = function ping(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return p;
};

/**
 * Create a pong packet (without a header).
 * @param {PingPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.pong = function pong(data) {
  var p = new Buffer(8);
  utils.writeU64(p, data.nonce, 0);
  return p;
};

/**
 * Create a filterload packet (without a header).
 * @param {FilterLoadPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.filterLoad = function filterLoad(data, writer) {
  var p = new BufferWriter(writer);
  var update = data.update;

  if (typeof update === 'string')
    update = constants.filterFlags[update.toUpperCase()];

  assert(update != null, 'Bad filter flag.');

  p.writeVarBytes(data.filter);
  p.writeU32(data.n);
  p.writeU32(data.tweak);
  p.writeU8(update);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a getheaders packet (without a header).
 * @param {GetBlocksPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getHeaders = function getHeaders(data, writer) {
  return Framer._getBlocks(data, writer, true);
};

/**
 * Create a getblocks packet (without a header).
 * @param {GetBlocksPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getBlocks = function getBlocks(data, writer) {
  return Framer._getBlocks(data, writer, false);
};

Framer._getBlocks = function _getBlocks(data, writer, headers) {
  var version = data.version;
  var locator = data.locator;
  var stop = data.stop;
  var p, i;

  if (!version)
    version = constants.VERSION;

  if (!locator) {
    if (headers)
      locator = [];
    else
      assert(false, 'getblocks requires a locator');
  }

  if (!stop)
    stop = constants.ZERO_HASH;

  p = new BufferWriter(writer);

  p.writeU32(version);
  p.writeVarint(locator.length);

  for (i = 0; i < locator.length; i++)
    p.writeHash(locator[i]);

  p.writeHash(stop);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize a coin.
 * @param {NakedCoin|Coin} coin
 * @param {Boolean} extended - Whether to include the hash and index.
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.coin = function _coin(coin, extended, writer) {
  var p = new BufferWriter(writer);
  var height = coin.height;

  if (height === -1)
    height = 0x7fffffff;

  p.writeU32(coin.version);
  p.writeU32(height);
  p.write64(coin.value);
  Framer.script(coin.script, p);
  p.writeU8(coin.coinbase ? 1 : 0);

  if (extended) {
    p.writeHash(coin.hash);
    p.writeU32(coin.index);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize transaction without witness.
 * @param {NakedTX|TX} tx
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

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

/**
 * Serialize an outpoint.
 * @param {Hash} hash
 * @param {Number} index
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.outpoint = function outpoint(hash, index, writer) {
  var p = new BufferWriter(writer);

  p.writeHash(hash);
  p.writeU32(index);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize an input.
 * @param {NakedInput|Input} input
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.input = function _input(input, writer) {
  var p = new BufferWriter(writer);

  p.writeHash(input.prevout.hash);
  p.writeU32(input.prevout.index);
  Framer.script(input.script, p);
  p.writeU32(input.sequence);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize an output.
 * @param {NakedOutput|Output} output
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.output = function _output(output, writer) {
  var p = new BufferWriter(writer);

  p.write64(output.value);
  Framer.script(output.script, p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `_witnessSize`).
 * @param {NakedTX|TX} tx
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.witnessTX = function _witnessTX(tx, writer) {
  var p = new BufferWriter(writer);
  var witnessSize = 0;
  var i, start;

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
    start = p.written;
    Framer.witness(tx.inputs[i].witness, p);
    witnessSize += p.written - start;
  }

  p.writeU32(tx.locktime);

  if (!writer)
    p = p.render();

  p._witnessSize = witnessSize + 2;

  return p;
};

/**
 * Serialize a script. Note that scripts require
 * extra magic since they're so goddamn bizarre.
 * Normally in an "encoded" script we don't
 * include the varint size because scripthashes
 * don't include them. This is why
 * script.encode/decode is separate from the
 * framer and parser.
 * @param {NakedScript|Script} script
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.script = function _script(script, writer) {
  var p = new BufferWriter(writer);
  var data;

  if (script.encode)
    data = script.encode();
  else
    data = script.raw || bcoin.script.encode(script.code);

  p.writeVarBytes(data);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize a witness.
 * @param {NakedWitness|Witness} witness
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

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

/**
 * Serialize a block without witness data.
 * @param {NakedBlock|Block} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.block = function _block(block, writer) {
  return Framer._block(block, false, writer);
};

/**
 * Serialize a block with witness data. Calculates the witness
 * size as it is framing (exposed on return value as `_witnessSize`).
 * @param {NakedBlock|Block} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.witnessBlock = function _witnessBlock(block, writer) {
  return Framer._block(block, true, writer);
};

/**
 * Serialize a transaction lazily (use existing raw data if present).
 * @param {NakedTX|TX} tx
 * @param {Boolean} useWitness - Whether to include witness data.
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.renderTX = function renderTX(tx, useWitness, writer) {
  var p = new BufferWriter(writer);
  var witnessSize;

  // Cache the serialization if we can.
  if (tx.render && !tx.mutable && !tx._raw)
    tx.render();

  // Try the cached raw data first.
  if (tx._raw) {
    if (useWitness) {
      // If we're serializing the witness,
      // we can use whatever data getRaw()
      // gave us.
      p.writeBytes(tx._raw);
      witnessSize = tx._witnessSize;
    } else {
      // We have to use the standard format
      // here. Try to grab it from cache.
      if (bcoin.protocol.parser.isWitnessTX(tx._raw)) {
        Framer.tx(tx, p);
        witnessSize = p._witnessSize;
      } else {
        p.writeBytes(tx._raw);
        witnessSize = tx._witnessSize;
      }
    }
  } else {
    if (useWitness) {
      if (bcoin.tx.prototype.hasWitness.call(tx)) {
        Framer.witnessTX(tx, p);
      } else {
        // Only use the witness serialization if
        // we have a witness. This clause isn't
        // necessary above since we already
        // determined this in getRaw().
        Framer.tx(tx, p);
      }
    } else {
      // Any other case, we use
      // the standard serialization.
      Framer.tx(tx, p);
    }
    witnessSize = p._witnessSize;
  }

  if (!writer)
    p = p.render();

  p._witnessSize = witnessSize;

  return p;
};

/**
 * Serialize a transaction to BCoin "extended format".
 * This is the serialization format BCoin uses internally
 * to store transactions in the database. The extended
 * serialization includes the height, block hash, index,
 * timestamp, pending-since time, and optionally a vector
 * for the serialized coins.
 * @param {NakedTX|TX} tx
 * @param {Boolean?} saveCoins - Whether to serialize the coins.
 * @param {String?} enc - One of `"hex"` or `null`.
 * @returns {Buffer}
 */

Framer.extendedTX = function extendedTX(tx, saveCoins, writer) {
  var height = tx.height;
  var index = tx.index;
  var changeIndex = tx.changeIndex != null ? tx.changeIndex : -1;
  var p = new BufferWriter(writer);
  var i, input;

  if (height === -1)
    height = 0x7fffffff;

  if (index === -1)
    index = 0x7fffffff;

  if (changeIndex === -1)
    changeIndex = 0x7fffffff;

  Framer.renderTX(tx, true, p);
  p.writeU32(height);
  p.writeHash(tx.block || constants.ZERO_HASH);
  p.writeU32(index);
  p.writeU32(tx.ts);
  p.writeU32(tx.ps);
  // p.writeU32(changeIndex);

  if (saveCoins) {
    p.writeVarint(tx.inputs.length);
    for (i = 0; i < tx.inputs.length; i++) {
      input = tx.inputs[i];

      if (!input.coin) {
        p.writeVarint(0);
        continue;
      }

      p.writeVarBytes(Framer.coin(input.coin, false));
    }
  }

  if (!writer)
    p = p.render();

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

/**
 * Serialize a merkle block.
 * @param {NakedBlock|MerkleBlock} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.merkleBlock = function _merkleBlock(block, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeU32(block.version);
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

/**
 * Serialize headers.
 * @param {NakedBlock[]|Headers[]} headers
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.headers = function _headers(headers, writer) {
  var p = new BufferWriter(writer);
  var i, header;

  p.writeVarint(headers.length);

  for (i = 0; i < headers.length; i++) {
    header = headers[i];
    p.write32(header.version);
    p.writeHash(header.prevBlock);
    p.writeHash(header.merkleRoot);
    p.writeU32(header.ts);
    p.writeU32(header.bits);
    p.writeU32(header.nonce);
    p.writeVarint(header.totalTX);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Serialize a block header without any transaction count field.
 * @param {NakedBlock|Block|MerkleBlock|Headers|ChainEntry} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.blockHeaders = function blockHeaders(block, writer) {
  var p = new BufferWriter(writer);

  p.write32(block.version);
  p.writeHash(block.prevBlock);
  p.writeHash(block.merkleRoot);
  p.writeU32(block.ts);
  p.writeU32(block.bits);
  p.writeU32(block.nonce);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a reject packet (without a header).
 * @param {RejectPacket} details
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.reject = function reject(details, writer) {
  var p = new BufferWriter(writer);
  var ccode = details.ccode;

  if (typeof ccode === 'string')
    ccode = constants.reject[ccode.toUpperCase()];

  if (!ccode)
    ccode = constants.reject.INVALID;

  if (ccode >= constants.reject.INTERNAL)
    ccode = constants.reject.INVALID;

  p.writeVarString(details.message || '', 'ascii');
  p.writeU8(ccode);
  p.writeVarString(details.reason || '', 'ascii');
  if (details.data)
    p.writeHash(details.data);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create an addr packet (without a header).
 * @param {NetworkAddress[]} hosts
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.addr = function addr(hosts, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeVarint(hosts.length);

  for (i = 0; i < hosts.length; i++)
    Framer.address(hosts[i], true, p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create an alert packet (without a header).
 * @param {AlertPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.alert = function alert(data, writer) {
  var network = bcoin.network.get(data.network);
  var key = data.key;
  var p, i, payload;

  if (!key && network.alertPrivateKey)
    key = network.alertPrivateKey;

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
    p.writeVarString(data.reserved || '', 'ascii');
    payload = p.render();
  } else {
    payload = data.payload;
  }

  p = new BufferWriter(writer);
  p.writeVarBytes(payload);

  if (data.signature)
    p.writeVarBytes(data.signature);
  else if (key)
    p.writeVarBytes(bcoin.ec.sign(utils.dsha256(payload), key));
  else
    assert(false, 'No key or signature.');

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a mempool packet (without a header).
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.mempool = function mempool() {
  return DUMMY;
};

/**
 * Create a getaddr packet (without a header).
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getAddr = function getAddr() {
  return DUMMY;
};

/**
 * Create a getutxos packet (without a header).
 * @param {GetUTXOsPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getUTXOs = function getUTXOs(data, writer) {
  var p = new BufferWriter(writer);
  var i, prevout;

  p.writeU8(data.mempool ? 1 : 0);
  p.writeVarint(data.prevout.length);

  for (i = 0; i < data.prevout.length; i++) {
    prevout = data.prevout[i];
    p.writeHash(prevout.hash);
    p.writeU32(prevout.index);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a utxos packet (without a header).
 * @param {UTXOsPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.UTXOs = function UTXOs(data, writer) {
  var p = new BufferWriter(writer);
  var i, coin, height, map;

  if (!data.map) {
    assert(data.hits);
    map = new Buffer((data.hits.length + 7) / 8 | 0);
    for (i = 0; i < data.hits.length; i++)
      map[i / 8 | 0] |= +data.hits[i] << (i % 8);
  } else {
    map = data.map;
  }

  p.writeU32(data.height);
  p.writeHash(data.tip);
  p.writeVarBytes(map);
  p.writeVarInt(data.coins.length);

  for (i = 0; i < data.coins.length; i++) {
    coin = data.coins[i];
    height = coin.height;

    if (height === -1)
      height = 0x7fffffff;

    p.writeU32(coin.version);
    p.writeU32(height);
    Framer.output(coin, p);
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a submitorder packet (without a header).
 * @param {SubmitOrderPacket} order
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.submitOrder = function submitOrder(order, writer) {
  var p = new BufferWriter(writer);

  p.writeHash(order.hash);
  Framer.renderTX(order.tx, true, p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a checkorder packet (without a header).
 * @param {SubmitOrderPacket} order
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.checkOrder = function checkOrder(order, writer) {
  return Framer.submitOrder(order, writer);
};

/**
 * Create a reply packet (without a header).
 * @param {ReplyPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.reply = function reply(data, writer) {
  var p = new BufferWriter(writer);

  p.writeHash(data.hash);
  p.writeU32(data.code || 0);

  if (data.publicKey)
    p.writeVarBytes(data.publicKey);
  else
    p.writeVarInt(0);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a sendheaders packet (without a header).
 * @returns {Buffer}
 */

Framer.sendHeaders = function sendHeaders() {
  return DUMMY;
};

/**
 * Create a havewitness packet (without a header).
 * @returns {Buffer}
 */

Framer.haveWitness = function haveWitness() {
  return DUMMY;
};

/**
 * Create a filteradd packet (without a header).
 * @param {Object|Buffer} data - Data to be added to bloom filter.
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.filterAdd = function filterAdd(data, writer) {
  var p = new BufferWriter(writer);

  p.writeVarBytes(data.data || data);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create a filterclear packet (without a header).
 * @returns {Buffer}
 */

Framer.filterClear = function filterClear() {
  return DUMMY;
};

/**
 * Create a feefilter packet (without a header).
 * @param {FeeFilterPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.feeFilter = function feeFilter(data, writer) {
  var p = new BufferWriter(writer);

  p.write64(data.rate);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Calculate total block size and
 * witness size without serializing.
 * @param {NakedBlock|Block} block
 * @returns {Object} In the form of `{size: Number, witnessSize: Number}`.
 */

Framer.block.sizes = function blockSizes(block) {
  var writer = new BufferWriter();
  Framer.witnessBlock(block, writer);
  return {
    size: writer.written,
    witnessSize: writer._witnessSize
  };
};

/**
 * Calculate total transaction size and
 * witness size without serializing.
 * @param {NakedBlock|Block} block
 * @returns {Object} In the form of `{size: Number, witnessSize: Number}`.
 */

Framer.tx.sizes = function txSizes(tx) {
  var writer = new BufferWriter();
  Framer.renderTX(tx, true, writer);
  return {
    size: writer.written,
    witnessSize: writer._witnessSize
  };
};

/**
 * Calculate block size with witness (if present).
 * @param {NakedBlock|Block} block
 * @returns {Number} Size.
 */

Framer.block.witnessSize = function blockWitnessSize(block) {
  return Framer.block.sizes(block).size;
};

/**
 * Calculate transaction size with witness (if present).
 * @param {NakedTX|TX} tx
 * @returns {Number} Size.
 */

Framer.tx.witnessSize = function txWitnessSize(tx) {
  return Framer.tx.sizes(tx).size;
};

/**
 * Calculate transaction size without witness.
 * @param {NakedBlock|Block} block
 * @returns {Number} Size.
 */

Framer.block.size = function blockSize(block) {
  var writer = new BufferWriter();
  Framer.block(block, writer);
  return writer.written;
};

/**
 * Calculate transaction size without witness.
 * @param {NakedTX|TX} tx
 * @returns {Number} Size.
 */

Framer.tx.size = function txSize(tx) {
  var writer = new BufferWriter();
  Framer.renderTX(tx, false, writer);
  return writer.written;
};

/**
 * Calculate block virtual size.
 * @param {NakedBlock|Block} block
 * @returns {Number} Virtual size.
 */

Framer.block.virtualSize = function blockVirtualSize(block) {
  var scale = constants.WITNESS_SCALE_FACTOR;
  return (Framer.block.cost(block) + scale - 1) / scale | 0;
};

/**
 * Calculate transaction virtual size.
 * @param {NakedTX|TX} tx
 * @returns {Number} Virtual size.
 */

Framer.tx.virtualSize = function txVirtualSize(tx) {
  var scale = constants.WITNESS_SCALE_FACTOR;
  return (Framer.tx.cost(tx) + scale - 1) / scale | 0;
};

/**
 * Calculate block cost.
 * @param {NakedBlock|Block} block
 * @returns {Number} cost
 */

Framer.block.cost = function blockCost(block) {
  var sizes = Framer.block.sizes(block);
  var base = sizes.size - sizes.witnessSize;
  var scale = constants.WITNESS_SCALE_FACTOR;
  return base * (scale - 1) + sizes.size;
};

/**
 * Calculate transaction cost.
 * @param {NakedTX|TX} tx
 * @returns {Number} cost
 */

Framer.tx.cost = function txCost(tx) {
  var sizes = Framer.tx.sizes(tx);
  var base = sizes.size - sizes.witnessSize;
  var scale = constants.WITNESS_SCALE_FACTOR;
  return base * (scale - 1) + sizes.size;
};

/*
 * Expose
 */

module.exports = Framer;
