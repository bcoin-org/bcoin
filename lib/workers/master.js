/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var EventEmitter = require('events').EventEmitter;
var utils = require('../utils/utils');
var global = utils.global;
var Network = require('../protocol/network');
var jobs = require('./jobs');
var Parser = require('./parser-client');
var Framer = require('./framer');
var global = utils.global;
var server;

/**
 * Represents the master process.
 * @exports Master
 * @constructor
 */

function Master() {
  if (!(this instanceof Master))
    return new Master();

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();

  this._init();
}

utils.inherits(Master, EventEmitter);

/**
 * Initialize master. Bind events.
 * @private
 */

Master.prototype._init = function _init() {
  var self = this;

  if (utils.isBrowser) {
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
  } else {
    process.stdin.on('data', function(data) {
      self.emit('data', data);
    });
    // Nowhere to send these errors:
    process.stdin.on('error', utils.nop);
    process.stdout.on('error', utils.nop);
    process.stderr.on('error', utils.nop);
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(packet) {
    self.emit('packet', packet);
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
  if (utils.isBrowser) {
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
 * @param {String} job
 * @param {String} cmd
 * @param {Array} items
 * @returns {Boolean}
 */

Master.prototype.send = function send(job, cmd, items) {
  return this.write(this.framer.packet(job, cmd, items));
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

  return this.send(0, 'event', items);
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  if (utils.isBrowser)
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
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  this.sendEvent('log', items);
};

/**
 * Listen for messages from master process (only if worker).
 * @param {Object} env
 * @returns {Master}
 */

Master.prototype.listen = function listen(env) {
  var self = this;

  Network.set(env.BCOIN_WORKER_NETWORK);

  utils.log = this.log.bind(this);
  utils.error = utils.log;

  this.on('error', function(err) {
    self.sendEvent('worker error', fromError(err));
  });

  this.on('packet', function(packet) {
    var result;

    if (packet.cmd === 'event') {
      self.emit('event', packet.items);
      self.emit.apply(self, packet.items);
      return;
    }

    try {
      result = jobs.execute(packet.cmd, packet.items);
    } catch (e) {
      self.send(packet.job, 'response', [fromError(e)]);
      return;
    }

    self.send(packet.job, 'response', [null, result]);
  });
};

/*
 * Helpers
 */

function fromError(err) {
  return [err.message, err.stack + '', err.type];
}

/*
 * Expose
 */

server = new Master();

if (utils.isBrowser)
  global.master = server;

module.exports = server;
