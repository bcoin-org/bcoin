/*!
 * socket.js - zmq sockets for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* jshint -W069 */
/* jshint noyield: true */

var assert = require('assert');
var zmq = require('zeromq');

/**
 * ZeroMQSockets
 * @exports ZeroMQSockets
 * @constructor
 * @param {Object} options
 * @param {Fullnode} options.node
 */

function ZeroMQSockets(options) {
  if (!(this instanceof ZeroMQSockets))
    return new ZeroMQSocket(options);

  if (!options)
    options = {};

  this.options = options;
  this.node = options.node;

  assert(this.node, 'ZeroMQ requires a Node.');

  var sockets = {};

  var topics = {
    pubHashTx: null,
    pubHashBlock: null,
    pubRawTx: null,
    pubRawBlock: null
  };

  this.topics = topics;

  var address;
  for (var topic in this.topics) {
    address = this.options[topic];
    if (address) {
      if (!sockets[address]) {
        sockets[address] = zmq.socket('pub');
        sockets[address].bindSync(address)
      }
      topics[topic] = sockets[address];
    }
  }

  this.mempool = this.node.mempool;
  this.chain = this.node.chain;
  
  this.mempool.on('tx', function (tx) {
    if (topics.pubHashTx) topics.pubHashTx.send(['hashtx', tx.rhash]);
    if (topics.pubRawTx) topics.pubHashTx.send(['rawtx', tx.getRaw()]);
  });

  this.chain.on('block', function (block) {
    if (topics.pubHashBlock) topics.pubHashBlock.send(['hashblock', block.rhash]);
    if (topics.pubRawBlock) topics.pubRawBlock.send(['rawblock', block.getRaw()]);
  });
}

/*
 * Expose
 */

module.exports = ZeroMQSockets;
