/*!
 * workerpool.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const os = require('os');
const util = require('../utils/util');
const co = require('../utils/co');
const Network = require('../protocol/network');
const Child = require('./child');
const jobs = require('./jobs');
const Parser = require('./parser');
const Framer = require('./framer');
const packets = require('./packets');

/**
 * A worker pool.
 * @alias module:workers.WorkerPool
 * @constructor
 * @param {Object} options
 * @param {Number} [options.size=num-cores] - Max pool size.
 * @param {Number} [options.timeout=120000] - Execution timeout.
 * @property {Number} size
 * @property {Number} timeout
 * @property {Map} children
 * @property {Number} uid
 */

function WorkerPool(options) {
  if (!(this instanceof WorkerPool))
    return new WorkerPool(options);

  EventEmitter.call(this);

  this.enabled = false;
  this.size = getCores();
  this.timeout = 120000;
  this.file = process.env.BCOIN_WORKER_FILE || 'worker.js';

  this.children = new Map();
  this.uid = 0;

  this.set(options);
}

util.inherits(WorkerPool, EventEmitter);

/**
 * Set worker pool options.
 * @param {Object} options
 */

WorkerPool.prototype.set = function set(options) {
  if (!options)
    return;

  if (options.enabled != null) {
    assert(typeof options.enabled === 'boolean');
    this.enabled = options.enabled;
  }

  if (options.size != null) {
    assert(util.isNumber(options.size));
    assert(options.size > 0);
    this.size = options.size;
  }

  if (options.timeout != null) {
    assert(util.isNumber(options.timeout));
    assert(options.timeout > 0);
    this.timeout = options.timeout;
  }

  if (options.file != null) {
    assert(typeof options.file === 'string');
    this.file = options.file;
  }
};

/**
 * Open worker pool.
 * @returns {Promise}
 */

WorkerPool.prototype.open = async function open() {
  ;
};

/**
 * Close worker pool.
 * @returns {Promise}
 */

WorkerPool.prototype.close = async function close() {
  this.destroy();
};

/**
 * Spawn a new worker.
 * @param {Number} id - Worker ID.
 * @returns {Worker}
 */

WorkerPool.prototype.spawn = function spawn(id) {
  let child = new Worker(this.file);

  child.id = id;

  child.on('error', (err) => {
    this.emit('error', err, child);
  });

  child.on('exit', (code) => {
    this.emit('exit', code, child);

    if (this.children.get(id) === child)
      this.children.delete(id);
  });

  child.on('event', (items) => {
    this.emit('event', items, child);
    this.emit(...items);
  });

  child.on('log', (text) => {
    this.emit('log', text, child);
  });

  this.emit('spawn', child);

  return child;
};

/**
 * Allocate a new worker, will not go above `size` option
 * and will automatically load balance the workers.
 * @returns {Worker}
 */

WorkerPool.prototype.alloc = function alloc() {
  let id = this.uid++ % this.size;

  if (!this.children.has(id))
    this.children.set(id, this.spawn(id));

  return this.children.get(id);
};

/**
 * Emit an event on the worker side (all workers).
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

WorkerPool.prototype.sendEvent = function sendEvent() {
  let result = true;

  for (let child of this.children.values()) {
    if (!child.sendEvent.apply(child, arguments))
      result = false;
  }

  return result;
};

/**
 * Destroy all workers.
 */

WorkerPool.prototype.destroy = function destroy() {
  for (let child of this.children.values())
    child.destroy();
};

/**
 * Call a method for a worker to execute.
 * @param {Packet} packet
 * @param {Number} timeout
 * @returns {Promise}
 */

WorkerPool.prototype.execute = function execute(packet, timeout) {
  let child;

  if (!this.enabled || !Child.hasSupport()) {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        let result;
        try {
          result = jobs.handle(packet);
        } catch (e) {
          reject(e);
          return;
        }
        resolve(result);
      });
    });
  }

  if (!timeout)
    timeout = this.timeout;

  child = this.alloc();

  return child.execute(packet, timeout);
};

/**
 * Execute the tx check job (default timeout).
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Promise}
 */

WorkerPool.prototype.check = async function check(tx, view, flags) {
  let packet = new packets.CheckPacket(tx, view, flags);
  let result = await this.execute(packet, -1);

  if (result.error)
    throw result.error;

  return null;
};

/**
 * Execute the tx signing job (default timeout).
 * @method
 * @param {MTX} tx
 * @param {KeyRing[]} ring
 * @param {SighashType} type
 * @returns {Promise}
 */

WorkerPool.prototype.sign = async function sign(tx, ring, type) {
  let rings = ring;
  let packet, result;

  if (!Array.isArray(rings))
    rings = [rings];

  packet = new packets.SignPacket(tx, rings, type);
  result = await this.execute(packet, -1);

  result.inject(tx);

  return result.total;
};

/**
 * Execute the tx input check job (default timeout).
 * @method
 * @param {TX} tx
 * @param {Number} index
 * @param {Coin|Output} coin
 * @param {VerifyFlags} flags
 * @returns {Promise}
 */

WorkerPool.prototype.checkInput = async function checkInput(tx, index, coin, flags) {
  let packet = new packets.CheckInputPacket(tx, index, coin, flags);
  let result = await this.execute(packet, -1);

  if (result.error)
    throw result.error;

  return null;
};

/**
 * Execute the tx input signing job (default timeout).
 * @method
 * @param {MTX} tx
 * @param {Number} index
 * @param {Coin|Output} coin
 * @param {KeyRing} ring
 * @param {SighashType} type
 * @returns {Promise}
 */

WorkerPool.prototype.signInput = async function signInput(tx, index, coin, ring, type) {
  let packet = new packets.SignInputPacket(tx, index, coin, ring, type);
  let result = await this.execute(packet, -1);
  result.inject(tx);
  return result.value;
};

/**
 * Execute the secp256k1 verify job (no timeout).
 * @method
 * @param {Buffer} msg
 * @param {Buffer} sig - DER formatted.
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecVerify = async function ecVerify(msg, sig, key) {
  let packet = new packets.ECVerifyPacket(msg, sig, key);
  let result = await this.execute(packet, -1);
  return result.value;
};

/**
 * Execute the secp256k1 signing job (no timeout).
 * @method
 * @param {Buffer} msg
 * @param {Buffer} key
 * @returns {Promise}
 */

WorkerPool.prototype.ecSign = async function ecSign(msg, key) {
  let packet = new packets.ECSignPacket(msg, key);
  let result = await this.execute(packet, -1);
  return result.sig;
};

/**
 * Execute the mining job (no timeout).
 * @method
 * @param {Buffer} data
 * @param {Buffer} target
 * @param {Number} min
 * @param {Number} max
 * @returns {Promise} - Returns {Number}.
 */

WorkerPool.prototype.mine = async function mine(data, target, min, max) {
  let packet = new packets.MinePacket(data, target, min, max);
  let result = await this.execute(packet, -1);
  return result.nonce;
};

/**
 * Execute scrypt job (no timeout).
 * @method
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Promise}
 */

WorkerPool.prototype.scrypt = async function scrypt(passwd, salt, N, r, p, len) {
  let packet = new packets.ScryptPacket(passwd, salt, N, r, p, len);
  let result = await this.execute(packet, -1);
  return result.key;
};

/**
 * Represents a worker.
 * @alias module:workers.Worker
 * @constructor
 * @param {String} file
 */

function Worker(file) {
  if (!(this instanceof Worker))
    return new Worker(file);

  EventEmitter.call(this);

  this.id = -1;
  this.framer = new Framer();
  this.parser = new Parser();
  this.pending = new Map();

  this.child = new Child(file);

  this.init();
}

util.inherits(Worker, EventEmitter);

/**
 * Initialize worker. Bind to events.
 * @private
 */

Worker.prototype.init = function init() {
  this.child.on('data', (data) => {
    this.parser.feed(data);
  });

  this.child.on('exit', (code, signal) => {
    this.emit('exit', code, signal);
  });

  this.child.on('error', (err) => {
    this.emit('error', err);
  });

  this.parser.on('error', (err) => {
    this.emit('error', err);
  });

  this.parser.on('packet', (packet) => {
    this.emit('packet', packet);
  });

  this.listen();
};

/**
 * Listen for packets.
 * @private
 */

Worker.prototype.listen = function listen() {
  this.on('exit', (code, signal) => {
    this.killJobs();
  });

  this.on('error', (err) => {
    this.killJobs();
  });

  this.on('packet', (packet) => {
    try {
      this.handlePacket(packet);
    } catch (e) {
      this.emit('error', e);
    }
  });

  this.sendEnv({
    BCOIN_WORKER_NETWORK: Network.type,
    BCOIN_WORKER_ISTTY: process.stdout
      ? (process.stdout.isTTY ? '1' : '0')
      : '0'
  });
};

/**
 * Handle packet.
 * @private
 * @param {Packet} packet
 */

Worker.prototype.handlePacket = function handlePacket(packet) {
  switch (packet.cmd) {
    case packets.types.EVENT:
      this.emit('event', packet.items);
      this.emit(...packet.items);
      break;
    case packets.types.LOG:
      this.emit('log', packet.text);
      break;
    case packets.types.ERROR:
      this.emit('error', packet.error);
      break;
    case packets.types.ERRORRESULT:
      this.rejectJob(packet.id, packet.error);
      break;
    default:
      this.resolveJob(packet.id, packet);
      break;
  }
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  return this.child.write(data);
};

/**
 * Frame and send a packet.
 * @param {Packet} packet
 * @returns {Boolean}
 */

Worker.prototype.send = function send(packet) {
  return this.write(this.framer.packet(packet));
};

/**
 * Send environment.
 * @param {Object} env
 * @returns {Boolean}
 */

Worker.prototype.sendEnv = function sendEnv(env) {
  return this.send(new packets.EnvPacket(env));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Worker.prototype.sendEvent = function sendEvent(...items) {
  return this.send(new packets.EventPacket(items));
};

/**
 * Destroy the worker.
 */

Worker.prototype.destroy = function destroy() {
  return this.child.destroy();
};

/**
 * Call a method for a worker to execute.
 * @param {Packet} packet
 * @param {Number} timeout
 * @returns {Promise}
 */

Worker.prototype.execute = function execute(packet, timeout) {
  return new Promise((resolve, reject) => {
    this._execute(packet, timeout, resolve, reject);
  });
};

/**
 * Call a method for a worker to execute.
 * @private
 * @param {Packet} packet
 * @param {Number} timeout
 * @param {Function} resolve
 * @param {Function} reject
 * the worker method specifies.
 */

Worker.prototype._execute = function _execute(packet, timeout, resolve, reject) {
  let job = new PendingJob(this, packet.id, resolve, reject);

  assert(!this.pending.has(packet.id), 'ID overflow.');

  this.pending.set(packet.id, job);

  job.start(timeout);

  this.send(packet);
};

/**
 * Resolve a job.
 * @param {Number} id
 * @param {Packet} result
 */

Worker.prototype.resolveJob = function resolveJob(id, result) {
  let job = this.pending.get(id);

  if (!job)
    throw new Error(`Job ${id} is not in progress.`);

  job.resolve(result);
};

/**
 * Reject a job.
 * @param {Number} id
 * @param {Error} err
 */

Worker.prototype.rejectJob = function rejectJob(id, err) {
  let job = this.pending.get(id);

  if (!job)
    throw new Error(`Job ${id} is not in progress.`);

  job.reject(err);
};

/**
 * Kill all jobs associated with worker.
 */

Worker.prototype.killJobs = function killJobs() {
  for (let job of this.pending.values())
    job.destroy();
};

/**
 * Pending Job
 * @constructor
 * @ignore
 * @param {Worker} worker
 * @param {Number} id
 * @param {Function} resolve
 * @param {Function} reject
 */

function PendingJob(worker, id, resolve, reject) {
  this.worker = worker;
  this.id = id;
  this.job = co.job(resolve, reject);
  this.timer = null;
}

/**
 * Start the timer.
 * @param {Number} timeout
 */

PendingJob.prototype.start = function start(timeout) {
  if (!timeout || timeout <= 0)
    return;

  this.timer = setTimeout(() => {
    this.reject(new Error('Worker timed out.'));
  }, timeout);
};

/**
 * Destroy the job with an error.
 */

PendingJob.prototype.destroy = function destroy() {
  this.reject(new Error('Job was destroyed.'));
};

/**
 * Cleanup job state.
 * @returns {Job}
 */

PendingJob.prototype.cleanup = function cleanup() {
  let job = this.job;

  assert(job, 'Already finished.');

  this.job = null;

  if (this.timer != null) {
    clearTimeout(this.timer);
    this.timer = null;
  }

  assert(this.worker.pending.has(this.id));
  this.worker.pending.delete(this.id);

  return job;
};

/**
 * Complete job with result.
 * @param {Object} result
 */

PendingJob.prototype.resolve = function resolve(result) {
  let job = this.cleanup();
  job.resolve(result);
};

/**
 * Complete job with error.
 * @param {Error} err
 */

PendingJob.prototype.reject = function reject(err) {
  let job = this.cleanup();
  job.reject(err);
};

/*
 * Helpers
 */

function getCores() {
  return Math.max(2, os.cpus().length);
}

/*
 * Expose
 */

module.exports = WorkerPool;
