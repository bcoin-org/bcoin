/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
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
  this.bip151 = options.bip151;
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
    checksum = utils.hash256(payload);

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

  if (this.bip151 && this.bip151.handshake)
    return this.bip151.packet(cmd, payload);

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

Framer.prototype.tx = function _tx(tx) {
  return this.packet('tx', Framer.tx(tx), tx.hash());
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
  if (tx.hasWitness()) {
    // We can't use the coinbase
    // hash since it is all zeroes.
    if (!tx.isCoinbase())
      checksum = tx.witnessHash();
  } else {
    checksum = tx.hash();
  }

  return this.packet('tx', Framer.witnessTX(tx), checksum);
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

Framer.prototype.alert = function _alert(alert) {
  return this.packet('alert', Framer.alert(alert));
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
 * Create an encinit packet with a header.
 * @param {Object} options - See {@link Framer.encinit}.
 * @returns {Buffer} encinit packet.
 */

Framer.prototype.encinit = function encinit(options) {
  return this.packet('encinit', Framer.encinit(options));
};

/**
 * Create an encack packet with a header.
 * @param {Object} options - See {@link Framer.encack}.
 * @returns {Buffer} encack packet.
 */

Framer.prototype.encack = function encack(options) {
  return this.packet('encack', Framer.encack(options));
};

/**
 * Create a sendcmpct packet with a header.
 * @param {Object} options - See {@link Framer.sendCmpct}.
 * @returns {Buffer} sendCmpct packet.
 */

Framer.prototype.sendCmpct = function sendCmpct(options) {
  return this.packet('sendcmpct', Framer.sendCmpct(options));
};

/**
 * Create a cmpctblock packet with a header.
 * @param {Object} options - See {@link Framer.cmpctBlock}.
 * @returns {Buffer} cmpctBlock packet.
 */

Framer.prototype.cmpctBlock = function cmpctBlock(options) {
  return this.packet('cmpctblock', Framer.cmpctBlock(options));
};

/**
 * Create a getblocktxn packet with a header.
 * @param {Object} options - See {@link Framer.getBlockTxn}.
 * @returns {Buffer} getBlockTxn packet.
 */

Framer.prototype.getBlockTxn = function getBlockTxn(options) {
  return this.packet('getblocktxn', Framer.getBlockTxn(options));
};

/**
 * Create a blocktxn packet with a header.
 * @param {Object} options - See {@link Framer.blockTxn}.
 * @returns {Buffer} blockTxn packet.
 */

Framer.prototype.blockTxn = function blockTxn(options) {
  return this.packet('blocktxn', Framer.blockTxn(options));
};

/**
 * Create a version packet (without a header).
 * @param {VersionPacket} options
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.version = function _version(version, writer) {
  return version.toRaw(writer);
};

/**
 * Create a verack packet (without a header).
 * @returns {Buffer}
 */

Framer.verack = function verack() {
  return DUMMY;
};

 /**
 * Create an inv, getdata, or notfound packet.
 * @private
 * @param {InvItem[]} items
 * @returns {Buffer}
 */

Framer._inv = function _inv(items, writer) {
  var p = new BufferWriter(writer);
  var i;

  assert(items.length <= 50000);

  p.writeVarint(items.length);

  for (i = 0; i < items.length; i++)
    items[i].toRaw(p);

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
 * @param {Bloom} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.filterLoad = function filterLoad(filter, writer) {
  return filter.toRaw(writer);
};

/**
 * Create a getheaders packet (without a header).
 * @param {GetBlocksPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getHeaders = function getHeaders(data, writer) {
  return data.toRaw(writer);
};

/**
 * Create a getblocks packet (without a header).
 * @param {GetBlocksPacket} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getBlocks = function getBlocks(data, writer) {
  return data.toRaw(writer);
};

/**
 * Serialize transaction without witness.
 * @param {TX} tx
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.tx = function _tx(tx, writer) {
  return tx.toNormal(writer);
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `_witnessSize`).
 * @param {TX} tx
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.witnessTX = function _witnessTX(tx, writer) {
  return tx.toRaw(writer);
};

/**
 * Serialize a block without witness data.
 * @param {Block} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.block = function _block(block, writer) {
  return block.toNormal(writer);
};

/**
 * Serialize a block with witness data. Calculates the witness
 * size as it is framing (exposed on return value as `_witnessSize`).
 * @param {Block} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.witnessBlock = function _witnessBlock(block, writer) {
  return block.toRaw(writer);
};

/**
 * Serialize a merkle block.
 * @param {MerkleBlock} block
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.merkleBlock = function _merkleBlock(block, writer) {
  return block.toRaw(writer);
};

/**
 * Serialize headers.
 * @param {Headers[]} headers
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.headers = function _headers(headers, writer) {
  var p = new BufferWriter(writer);
  var i;

  p.writeVarint(headers.length);

  for (i = 0; i < headers.length; i++)
    headers[i].toRaw(p);

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

Framer.reject = function _reject(reject, writer) {
  return reject.toRaw(writer);
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
    hosts[i].toRaw(true, p);

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Create an alert packet (without a header).
 * @param {AlertPacket} data
 * @param {Buffer|KeyPair} key
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.alert = function _alert(alert, writer) {
  return alert.toRaw(writer);
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
  var i;

  p.writeU8(data.mempool ? 1 : 0);
  p.writeVarint(data.prevout.length);

  for (i = 0; i < data.prevout.length; i++)
    data.prevout[i].toRaw(p);

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
    p.write64(coin.value);
    p.writeVarBytes(coin.script.toRaw());
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
  order.tx.toRaw(p);

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
 * Create an encinit packet (without a header).
 * @param {BIP151} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.encinit = function encinit(data, writer) {
  if (writer) {
    writer.writeBytes(data);
    return writer;
  }
  return data;
};

/**
 * Create an encinit packet (without a header).
 * @param {BIP151} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.encack = function encack(data, writer) {
  if (writer) {
    writer.writeBytes(data);
    return writer;
  }
  return data;
};

/**
 * Create a sendcmpct packet (without a header).
 * @param {SendCompact} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.sendCmpct = function sendCmpct(data, writer) {
  return data.toRaw(writer);
};

/**
 * Create a cmpctblock packet (without a header).
 * @param {CompactBlock} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.cmpctBlock = function cmpctBlock(data, writer) {
  return data.toRaw(false, writer);
};

/**
 * Create a getblocktxn packet (without a header).
 * @param {BlockTXRequest} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.getBlockTxn = function getBlockTxn(data, writer) {
  return data.toRaw(writer);
};

/**
 * Create a blocktxn packet (without a header).
 * @param {BlockTX} data
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

Framer.blockTxn = function blockTxn(data, writer) {
  return data.toRaw(false, writer);
};

/*
 * Expose
 */

module.exports = Framer;
