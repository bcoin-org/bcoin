/*!
 * framer.js - packet framer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var assert = utils.assert;
var BufferWriter = require('../utils/writer');
var DUMMY = new Buffer(0);

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
 * Frame a payload with a header.
 * @param {String} cmd - Packet type.
 * @param {Buffer} payload
 * @returns {Buffer} Payload with header prepended.
 */

Framer.prototype.packet = function packet(cmd, payload, checksum) {
  var i, packet;

  assert(payload, 'No payload.');

  if (this.bip151 && this.bip151.handshake)
    return this.bip151.packet(cmd, payload);

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  packet = new Buffer(24 + payload.length);

  // Magic value
  packet.writeUInt32LE(this.network.magic, 0, true);

  // Command
  packet.write(cmd, 4, 'ascii');

  for (i = 4 + cmd.length; i < 16; i++)
    packet[i] = 0;

  // Payload length
  packet.writeUInt32LE(payload.length, 16, true);

  if (!checksum)
    checksum = utils.hash256(payload);

  // Checksum
  checksum.copy(packet, 20, 0, 4);

  payload.copy(packet, 24);

  return packet;
};

/**
 * Create a version packet with a header.
 * @param {VersionPacket} payload
 * @returns {Buffer} version packet.
 */

Framer.prototype.version = function version(payload) {
  return this.packet('version', payload.toRaw());
};

/**
 * Create a verack packet with a header.
 * @returns {Buffer} verack packet.
 */

Framer.prototype.verack = function verack() {
  return this.packet('verack', DUMMY);
};

/**
 * Create a ping packet with a header.
 * @param {BN} nonce
 * @returns {Buffer} ping packet.
 */

Framer.prototype.ping = function ping(nonce) {
  if (!nonce)
    return this.packet('ping', DUMMY);
  return this.packet('ping', framePing(nonce));
};

/**
 * Create a pong packet with a header.
 * @param {BN} nonce
 * @returns {Buffer} pong packet.
 */

Framer.prototype.pong = function pong(nonce) {
  return this.packet('pong', framePing(nonce));
};

/**
 * Create an alert packet with a header.
 * @param {AlertPacket} alert
 * @returns {Buffer} alert packet.
 */

Framer.prototype.alert = function _alert(alert) {
  return this.packet('alert', alert.toRaw());
};

/**
 * Create a getaddr packet with a header.
 * @returns {Buffer} getaddr packet.
 */

Framer.prototype.getAddr = function getAddr() {
  return this.packet('getaddr', DUMMY);
};

/**
 * Create an addr packet with a header.
 * @param {NetworkAddress[]} hosts
 * @returns {Buffer} addr packet.
 */

Framer.prototype.addr = function addr(hosts) {
  return this.packet('addr', frameAddr(hosts));
};

/**
 * Create an inv packet with a header.
 * @param {InvItem[]} items
 * @returns {Buffer} inv packet.
 */

Framer.prototype.inv = function inv(items) {
  return this.packet('inv', frameItems(items));
};

/**
 * Create a getdata packet with a header.
 * @param {InvItem[]} items
 * @returns {Buffer} getdata packet.
 */

Framer.prototype.getData = function getData(items) {
  return this.packet('getdata', frameItems(items));
};

/**
 * Create a notfound packet with a header.
 * @param {InvItem[]} items
 * @returns {Buffer} notfound packet.
 */

Framer.prototype.notFound = function notFound(items) {
  return this.packet('notfound', frameItems(items));
};

/**
 * Create a getblocks packet with a header.
 * @param {GetBlocksPacket} data
 * @returns {Buffer} getblocks packet.
 */

Framer.prototype.getBlocks = function getBlocks(data) {
  return this.packet('getblocks', data.toRaw());
};

/**
 * Create a getheaders packet with a header.
 * @param {GetBlocksPacket} data
 * @returns {Buffer} getheaders packet.
 */

Framer.prototype.getHeaders = function getHeaders(data) {
  return this.packet('getheaders', data.toRaw());
};

/**
 * Create a headers packet with a header.
 * @param {Headers[]} headers
 * @returns {Buffer} headers packet.
 */

Framer.prototype.headers = function _headers(headers) {
  return this.packet('headers', frameItems(headers));
};

/**
 * Create a sendheaders packet with a header.
 * @returns {Buffer} sendheaders packet.
 */

Framer.prototype.sendHeaders = function sendHeaders() {
  return this.packet('sendheaders', DUMMY);
};

/**
 * Create a block packet with a header.
 * @param {Block} block
 * @returns {Buffer} block packet.
 */

Framer.prototype.block = function _block(block) {
  return this.packet('block', block.toNormal());
};

/**
 * Create a block packet with a header,
 * using witness serialization.
 * @param {Block} block
 * @returns {Buffer} block packet.
 */

Framer.prototype.witnessBlock = function witnessBlock(block) {
  return this.packet('block', block.toRaw());
};

/**
 * Create a tx packet with a header.
 * @param {TX} tx
 * @returns {Buffer} tx packet.
 */

Framer.prototype.tx = function _tx(tx) {
  return this.packet('tx', tx.toNormal(), tx.hash());
};

/**
 * Create a tx packet with a header,
 * using witness serialization.
 * @param {TX} tx
 * @returns {Buffer} tx packet.
 */

Framer.prototype.witnessTX = function witnessTX(tx) {
  var checksum;

  // Save some time by using the
  // cached hash as our checksum.
  if (tx.hasWitness()) {
    // We can't use the coinbase
    // hash since it is all zeroes.
    // We really shouldn't be
    // relaying coinbases in the
    // first place, but oh well.
    if (!tx.isCoinbase())
      checksum = tx.witnessHash();
  } else {
    checksum = tx.hash();
  }

  return this.packet('tx', tx.toRaw(), checksum);
};

/**
 * Create a reject packet with a header.
 * @param {RejectPacket} details
 * @returns {Buffer} reject packet.
 */

Framer.prototype.reject = function reject(details) {
  return this.packet('reject', details.toRaw());
};

/**
 * Create a mempool packet with a header.
 * @returns {Buffer} mempool packet.
 */

Framer.prototype.mempool = function mempool() {
  return this.packet('mempool', DUMMY);
};

/**
 * Create a filterload packet with a header.
 * @param {Bloom} filter
 * @returns {Buffer} filterload packet.
 */

Framer.prototype.filterLoad = function filterLoad(filter) {
  return this.packet('filterload', filter.toRaw());
};

/**
 * Create a filteradd packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} filteradd packet.
 */

Framer.prototype.filterAdd = function filterAdd(data) {
  return this.packet('filteradd', frameFilterAdd(data));
};

/**
 * Create a filterclear packet with a header.
 * @returns {Buffer} filterclear packet.
 */

Framer.prototype.filterClear = function filterClear() {
  return this.packet('filterclear', DUMMY);
};

/**
 * Create a merkleblock packet with a header.
 * @param {MerkleBlock} block
 * @returns {Buffer} merkleblock packet.
 */

Framer.prototype.merkleBlock = function merkleBlock(block) {
  return this.packet('merkleblock', block.toRaw());
};

/**
 * Create a getutxos packet with a header.
 * @param {GetUTXOsPacket} data
 * @returns {Buffer} getutxos packet.
 */

Framer.prototype.getUTXOs = function getUTXOs(data) {
  return this.packet('getutxos', data.toRaw());
};

/**
 * Create a utxos packet with a header.
 * @param {UTXOsPacket} utxos
 * @returns {Buffer} utxos packet.
 */

Framer.prototype.UTXOs = function UTXOs(utxos) {
  return this.packet('utxos', utxos.toRaw());
};

/**
 * Create a havewitness packet with a header.
 * @returns {Buffer} havewitness packet.
 */

Framer.prototype.haveWitness = function haveWitness() {
  return this.packet('havewitness', DUMMY);
};

/**
 * Create a feefilter packet with a header.
 * @param {Rate} rate
 * @returns {Buffer} feefilter packet.
 */

Framer.prototype.feeFilter = function feeFilter(rate) {
  return this.packet('feefilter', frameFeeFilter(rate));
};

/**
 * Create a sendcmpct packet with a header.
 * @param {SendCompact} data
 * @returns {Buffer} sendcmpct packet.
 */

Framer.prototype.sendCmpct = function sendCmpct(data) {
  return this.packet('sendcmpct', data.toRaw());
};

/**
 * Create a cmpctblock packet with a header.
 * @param {CompactBlock} block
 * @returns {Buffer} cmpctblock packet.
 */

Framer.prototype.cmpctBlock = function cmpctBlock(block) {
  return this.packet('cmpctblock', block.toRaw(false));
};

/**
 * Create a getblocktxn packet with a header.
 * @param {TXRequest} req
 * @returns {Buffer} getblocktxn packet.
 */

Framer.prototype.getBlockTxn = function getBlockTxn(req) {
  return this.packet('getblocktxn', req.toRaw());
};

/**
 * Create a blocktxn packet with a header.
 * @param {TXResponse} res
 * @returns {Buffer} blocktxn packet.
 */

Framer.prototype.blockTxn = function blockTxn(res) {
  return this.packet('blocktxn', res.toRaw(false));
};

/**
 * Create an encinit packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} encinit packet.
 */

Framer.prototype.encinit = function encinit(data) {
  return this.packet('encinit', data);
};

/**
 * Create an encack packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} encack packet.
 */

Framer.prototype.encack = function encack(data) {
  return this.packet('encack', data);
};

/**
 * Create a authchallenge packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} authchallenge packet.
 */

Framer.prototype.authChallenge = function authChallenge(data) {
  return this.packet('authchallenge', data);
};

/**
 * Create a authreply packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} authreply packet.
 */

Framer.prototype.authReply = function authReply(data) {
  return this.packet('authreply', data);
};

/**
 * Create a authpropose packet with a header.
 * @param {Buffer} data
 * @returns {Buffer} authpropose packet.
 */

Framer.prototype.authPropose = function authPropose(data) {
  return this.packet('authpropose', data);
};

/*
 * Helpers
 */

function frameItems(items) {
  var p = new BufferWriter();
  var i;

  p.writeVarint(items.length);

  for (i = 0; i < items.length; i++)
    items[i].toRaw(p);

  return p.render();
}

function framePing(nonce) {
  var p = new BufferWriter();
  p.writeU64(nonce);
  return p.render();
}

function frameAddr(hosts) {
  var p = new BufferWriter();
  var i;

  p.writeVarint(hosts.length);

  for (i = 0; i < hosts.length; i++)
    hosts[i].toRaw(true, p);

  return p.render();
}

function frameFilterAdd(data) {
  var p = new BufferWriter();
  p.writeVarBytes(data);
  return p.render();
}

function frameFeeFilter(rate) {
  var p = new BufferWriter();
  p.write64(rate);
  return p.render();
}

/*
 * Expose
 */

module.exports = Framer;
