/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

module.exports = function(bcoin) {

var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var utils = require('./utils');

/**
 * Base class from which every other
 * Node-like object inherits.
 * @exports Node
 * @constructor
 * @abstract
 * @param {Object} options
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  this.network = network;
  this.mempool = null;
  this.pool = null;
  this.chain = null;
  this.miner = null;
  this.walletdb = null;
}

utils.inherits(Node, EventEmitter);

return Node;
};
