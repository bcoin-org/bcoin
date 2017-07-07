/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const util = require('../utils/util');
const Network = require('../protocol/network');
const jobs = require('./jobs');
const Parser = require('./parser');
const Framer = require('./framer');
const packets = require('./packets');
const Parent = require('./parent');

/**
 * Represents the master process.
 * @alias module:workers.Master
 * @constructor
 */

function Master() {
  if (!(this instanceof Master))
    return new Master();

  EventEmitter.call(this);

  this.parent = new Parent();
  this.framer = new Framer();
  this.parser = new Parser();
  this.env = {};
  this.listening = false;
  this.color = false;

  this.init();
}

util.inherits(Master, EventEmitter);

/**
 * Initialize master. Bind events.
 * @private
 */

Master.prototype.init = function init() {
  this.parent.on('data', (data) => {
    this.parser.feed(data);
  });

  this.parser.on('error', (err) => {
    this.emit('error', err);
  });

  this.parser.on('packet', (packet) => {
    this.emit('packet', packet);
  });

  this.parent.on('exception', (err) => {
    this.send(new packets.ErrorPacket(err));
    setTimeout(() => this.destroy(), 1000);
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
  return this.parent.write(data);
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

Master.prototype.sendEvent = function sendEvent(...items) {
  return this.send(new packets.EventPacket(items));
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  return this.parent.destroy();
};

/**
 * Write a message to stdout in the master process.
 * @param {Object|String} obj
 * @param {...String} args
 */

Master.prototype.log = function log(...items) {
  let text = util.format(items, this.color);
  this.send(new packets.LogPacket(text));
};

/**
 * Listen for messages from master process (only if worker).
 * @param {Object} env
 * @returns {Master}
 */

Master.prototype.listen = function listen(env) {
  assert(!this.listening, 'Already listening.');

  this.env = env;
  this.listening = true;
  this.color = +env.BCOIN_WORKER_ISTTY === 1;

  this.set(env.BCOIN_WORKER_NETWORK);

  util.log = this.log.bind(this);
  util.error = util.log;

  this.on('error', (err) => {
    this.send(new packets.ErrorPacket(err));
  });

  this.on('packet', (packet) => {
    try {
      this.handlePacket(packet);
    } catch (e) {
      this.emit('error', e);
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
  let result;

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

module.exports = Master;
