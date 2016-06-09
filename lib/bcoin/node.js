/*!
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
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
  this.network = bcoin.network.get(options.network);

  this.mempool = null;
  this.pool = null;
  this.chain = null;
  this.miner = null;
  this.walletdb = null;
}

utils.inherits(Node, EventEmitter);

/*
 * Expose
 */

module.exports = Node;
