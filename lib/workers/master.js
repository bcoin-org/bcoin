/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var EventEmitter = require('events').EventEmitter;
var util = require('../utils/util');
var Network = require('../protocol/network');
var jobs = require('./jobs');
var Parser = require('./parser-client');
var Framer = require('./framer');
var packets = require('./packets');
var global = util.global;
var server;

/**
 * Represents the master process.
 * @alias module:workers.Master
 * @constructor
 */

function Master() {
  if (!(this instanceof Master))
    return new Master();

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();
  this.env = {};
  this.listening = false;
  this.color = false;

  this._init();
}

util.inherits(Master, EventEmitter);

/**
 * Initialize master. Bind events.
 * @private
 */

Master.prototype._init = function _init() {
  var self = this;

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(err) {
    self.emit('error', err);
  });

  this.parser.on('packet', function(packet) {
    self.emit('packet', packet);
  });

  if (util.isBrowser) {
    // Web workers
    this._initWebWorkers();
  } else {
    // Child process + pipes
    this._initChildProcess();
  }
};

/**
 * Initialize master (web workers).
 * @private
 */

Master.prototype._initWebWorkers = function _initWebWorkers() {
  var self = this;

  global.onerror = function onerror(err) {
    self.emit('error', err);
  };

  global.onmessage = function onmessage(event) {
    var data;
    if (typeof event.data !== 'string') {
      data = event.data.buf;
      data.__proto__ = Buffer.prototype;
    } else {
      data = new Buffer(event.data, 'hex');
    }
    self.emit('data', data);
  };
};

/**
 * Initialize master (node.js).
 * @private
 */

Master.prototype._initChildProcess = function _initChildProcess() {
  var self = this;

  process.stdin.on('data', function(data) {
    self.emit('data', data);
  });

  // Nowhere to send these errors:
  process.stdin.on('error', util.nop);
  process.stdout.on('error', util.nop);
  process.stderr.on('error', util.nop);

  process.on('uncaughtException', function(err) {
    self.send(new packets.ErrorPacket(err));
    util.nextTick(function() {
      process.exit(1);
    });
  });
};

/**
 * Set primary network.
 * @param {NetworkType|Network} network
 */

Master.prototype.set = function set(network) {
  return Network.set(network);
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Master.prototype.write = function write(data) {
  if (util.isBrowser) {
    if (global.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      global.postMessage({ buf: data }, [data]);
    } else {
      global.postMessage(data.toString('hex'));
    }
    return true;
  }
  return process.stdout.write(data);
};

/**
 * Frame and send a packet.
 * @param {Packet} packet
 * @returns {Boolean}
 */

Master.prototype.send = function send(packet) {
  return this.write(this.framer.packet(packet));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Master.prototype.sendEvent = function sendEvent() {
  var items = new Array(arguments.length);
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  return this.send(new packets.EventPacket(items));
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  if (util.isBrowser)
    return global.close();
  return process.exit(0);
};

/**
 * Write a message to stdout in the master process.
 * @param {Object|String} obj
 * @param {...String} args
 */

Master.prototype.log = function log() {
  var items = new Array(arguments.length);
  var i, text;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  text = util.format(items, this.color);

  this.send(new packets.LogPacket(text));
};

/**
 * Listen for messages from master process (only if worker).
 * @param {Object} env
 * @returns {Master}
 */

Master.prototype.listen = function listen(env) {
  var self = this;

  assert(!this.listening, 'Already listening.');

  this.env = env;
  this.listening = true;
  this.color = +env.BCOIN_WORKER_ISTTY === 1;

  this.set(env.BCOIN_WORKER_NETWORK);

  util.log = this.log.bind(this);
  util.error = util.log;

  this.on('error', function(err) {
    self.send(new packets.ErrorPacket(err));
  });

  this.on('packet', function(packet) {
    try {
      self.handlePacket(packet);
    } catch (e) {
      self.emit('error', e);
    }
  });

  return this;
};

/**
 * Handle packet.
 * @private
 * @param {Packet}
 */

Master.prototype.handlePacket = function handlePacket(packet) {
  var result;

  switch (packet.cmd) {
    case packets.types.EVENT:
      this.emit('event', packet.items);
      this.emit.apply(this, packet.items);
      break;
    case packets.types.ERROR:
      this.emit('error', packet.error);
      break;
    default:
      result = jobs.execute(packet);
      result.id = packet.id;
      this.send(result);
      break;
  }
};

/*
 * Expose
 */

server = new Master();

if (util.isBrowser)
  global.master = server;

module.exports = server;
