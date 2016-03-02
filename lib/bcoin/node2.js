/**
 * node.js - node object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;

/**
 * Node
 */

function Node(options) {
  if (!(this instanceof Node))
    return new Node(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;

  if (this.options.debug != null)
    bcoin.debug = this.options.debug;

  if (this.options.debugFile != null)
    bcoin.debugFile = this.options.debugFile;

  if (this.options.network)
    network.set(this.options.network);

  this.network = network;
  this.blockdb = null;
  this.mempool = null;
  this.pool = null;
  this.chain = null;
  this.miner = null;
  this.profiler = null;

  Node.global = this;
}

utils.inherits(Node, EventEmitter);

/**
 * Expose
 */

module.exports = Node;
