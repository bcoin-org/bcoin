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
const path = require('path');
const cp = require('./cp');
const util = require('../utils/util');
const co = require('../utils/co');
const Network = require('../protocol/network');
const jobs = require('./jobs');
const Parser = require('./parser');
const Framer = require('./framer');
const packets = require('./packets');

const HAS_WORKERS = typeof global.Worker === 'function';
const HAS_CP = typeof cp.spawn === 'function';
const HAS_SUPPORT = HAS_WORKERS || HAS_CP;

const pools = new Set();
let exitBound = false;

/**
 * A worker pool.
 * @alias module:workers.WorkerPool
 * @constructor
 * @param {Object} options
 * @param {Number} [options.size=num-cores] - Max pool size.
 * @param {Number} [options.timeout=10000] - Execution timeout.
 * @property {Number} size
 * @property {Number} timeout
 * @property {Map} children
 * @property {Number} nonce
 */

function WorkerPool(options) {
  if (!(this instanceof WorkerPool))
    return new WorkerPool(options);

  EventEmitter.call(this);

  this.size = WorkerPool.CORES;
  this.timeout = 60000;
  this.children = new Map();
  this.nonce = 0;
  this.enabled = true;

  this.workerFile = WorkerPool.WORKER_FILE;
  this.workerURL = WorkerPool.WORKER_URL;
  this.masterURL = WorkerPool.MASTER_URL;

  bindExit();
  pools.add(this);

  this.set(options);
}

util.inherits(WorkerPool, EventEmitter);

/**
 * Number of CPUs/cores available.
 * @type {Number}
 */

WorkerPool.CORES = getCores();

/**
 * Default worker file.
 * @const {String}
 */

WorkerPool.WORKER_FILE = process.env.BCOIN_WORKER_FILE || 'worker.js';

/**
 * Default worker URL.
 * @const {String}
 */

WorkerPool.WORKER_URL = process.env.BCOIN_WORKER_URL || '/bcoin-worker.js';

/**
 * Default master URL.
 * @const {String}
 */

WorkerPool.MASTER_URL = process.env.BCOIN_MASTER_URL || '/bcoin-master.js';

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

  if (options.workerFile != null) {
    assert(typeof options.workerFile === 'string');
    this.workerFile = options.workerFile;
  }

  if (options.workerURL != null) {
    assert(typeof options.workerURL === 'string');
    this.workerURL = options.workerURL;
  }

  if (options.masterURL != null) {
    assert(typeof options.masterURL === 'string');
    this.masterURL = options.masterURL;
  }
};

/**
 * Enable the worker pool.
 */

WorkerPool.prototype.enable = function enable() {
  this.enabled = true;
};

/**
 * Disable the worker pool.
 */

WorkerPool.prototype.disable = function disable() {
  this.enabled = true;
};

/**
 * Open worker pool.
 * @returns {Promise}
 */

WorkerPool.prototype.open = async function open() {
  pools.add(this);
};

/**
 * Close worker pool.
 * @returns {Promise}
 */

WorkerPool.prototype.close = async function close() {
  pools.delete(this);
  this.destroy();
};

/**
 * Spawn a new worker.
 * @param {Number} id - Worker ID.
 * @returns {Worker}
 */

WorkerPool.prototype.spawn = function spawn(id) {
  let child = new Worker(id, this.masterURL);

  child.on('error', (err) => {
    this.emit('error', err, child);
  });

  child.on('exit', (code) => {
    this.emit('exit', code, child);
    if (this.children.get(child.id) === child)
      this.children.delete(child.id);
  });

  child.on('event', (items) => {
    this.emit('event', items, child);
    this.emit.apply(this, items);
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
  let id = this.nonce++ % this.size;

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
  let result, child;

  if (!this.enabled || !HAS_SUPPORT) {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          result = jobs._execute(packet);
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
 * Execute the tx verification job (default timeout).
 * @method
 * @param {TX} tx
 * @param {CoinView} view
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verify = async function verify(tx, view, flags) {
  let packet = new packets.VerifyPacket(tx, view, flags);
  let result = await this.execute(packet, -1);
  return result.value;
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
 * Execute the tx input verification job (default timeout).
 * @method
 * @param {TX} tx
 * @param {Number} index
 * @param {Coin|Output} coin
 * @param {VerifyFlags} flags
 * @returns {Promise} - Returns Boolean.
 */

WorkerPool.prototype.verifyInput = async function verifyInput(tx, index, coin, flags) {
  let packet = new packets.VerifyInputPacket(tx, index, coin, flags);
  let result = await this.execute(packet, -1);
  return result.value;
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
 * @param {Number} id
 * @param {String} masterURL
 */

function Worker(id, masterURL) {
  if (!(this instanceof Worker))
    return new Worker(id, masterURL);

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();

  this.id = id;
  this.child = null;
  this.pending = new Map();

  this.env = {
    BCOIN_MASTER_URL: masterURL,
    BCOIN_WORKER_NETWORK: Network.type,
    BCOIN_WORKER_ISTTY: process.stdout
      ? (process.stdout.isTTY ? '1' : '0')
      : '0'
  };

  this._init();
}

util.inherits(Worker, EventEmitter);

/**
 * Initialize worker. Bind to events.
 * @private
 */

Worker.prototype._init = function _init() {
  this.on('data', (data) => {
    this.parser.feed(data);
  });

  this.parser.on('error', (err) => {
    this.emit('error', err);
  });

  this.parser.on('packet', (packet) => {
    this.emit('packet', packet);
  });

  if (HAS_WORKERS) {
    // Web workers
    this._initWebWorkers();
  } else if (HAS_CP) {
    // Child process + pipes
    this._initChildProcess();
  } else {
    throw new Error('Workers not available.');
  }

  this._listen();
};

/**
 * Initialize worker (web workers).
 * @private
 */

Worker.prototype._initWebWorkers = function _initWebWorkers() {
  this.child = new global.Worker(this.workerURL);

  this.child.onerror = (err) => {
    this.emit('error', err);
    this.emit('exit', -1, null);
  };

  this.child.onmessage = (event) => {
    let data;
    if (typeof event.data === 'string') {
      data = Buffer.from(event.data, 'hex');
      assert(data.length === event.data.length / 2);
    } else {
      assert(event.data && typeof event.data === 'object');
      assert(event.data.data && typeof event.data.data.length === 'number');
      data = event.data.data;
      data.__proto__ = Buffer.prototype;
    }
    this.emit('data', data);
  };

  this.child.postMessage(JSON.stringify(this.env));
};

/**
 * Initialize worker (node.js).
 * @private
 */

Worker.prototype._initChildProcess = function _initChildProcess() {
  let bin = process.argv[0];
  let file = path.resolve(__dirname, this.workerFile);
  let env = Object.assign({}, process.env, this.env);
  let options = { stdio: 'pipe', env: env };

  this.child = cp.spawn(bin, [file], options);

  this.child.unref();
  this.child.stdin.unref();
  this.child.stdout.unref();
  this.child.stderr.unref();

  this.child.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.on('exit', (code, signal) => {
    this.emit('exit', code == null ? -1 : code, signal);
  });

  this.child.on('close', () => {
    this.emit('exit', -1, null);
  });

  this.child.stdin.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stdout.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stderr.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stdout.on('data', (data) => {
    this.emit('data', data);
  });
};

/**
 * Listen for packets.
 * @private
 */

Worker.prototype._listen = function _listen() {
  this.on('exit', () => {
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
};

/**
 * Handle packet.
 * @private
 * @param {Packet} packet
 */

Worker.prototype.handlePacket = function handlePacket(packet) {
  switch (packet.cmd) {
    case packets.types.EVENT:
      this.emit.apply(this, packet.items);
      this.emit('event', packet.items);
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
  if (HAS_WORKERS) {
    if (this.child.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      this.child.postMessage({ data }, [data]);
    } else {
      this.child.postMessage(data.toString('hex'));
    }
    return true;
  }
  return this.child.stdin.write(data);
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
  if (HAS_WORKERS) {
    this.child.terminate();
    this.emit('exit', -1, 'SIGTERM');
    return;
  }
  return this.child.kill('SIGTERM');
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
  if (!timeout || timeout === -1)
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

function bindExit() {
  let onSighup, onSigint, onSigterm, onError;

  if (!HAS_CP)
    return;

  if (exitBound)
    return;

  exitBound = true;

  onSighup = () => {
    process.exit(1 | 0x80);
  };

  onSigint = () => {
    process.exit(2 | 0x80);
  };

  onSigterm = () => {
    process.exit(15 | 0x80);
  };

  onError = (err) => {
    if (err && err.stack)
      console.error(err.stack + '');
    else
      console.error(err + '');

    process.exit(1);
  };

  process.once('exit', () => {
    for (let pool of pools)
      pool.destroy();
  });

  if (process.listenerCount('SIGHUP') === 0)
    process.once('SIGHUP', onSighup);

  if (process.listenerCount('SIGINT') === 0)
    process.once('SIGINT', onSigint);

  if (process.listenerCount('SIGTERM') === 0)
    process.once('SIGTERM', onSigterm);

  if (process.listenerCount('uncaughtException') === 0)
    process.once('uncaughtException', onError);

  process.on('newListener', (name) => {
    switch (name) {
      case 'SIGHUP':
        process.removeListener(name, onSighup);
        break;
      case 'SIGINT':
        process.removeListener(name, onSigint);
        break;
      case 'SIGTERM':
        process.removeListener(name, onSigterm);
        break;
      case 'uncaughtException':
        process.removeListener(name, onError);
        break;
    }
  });
}

/*
 * Expose
 */

module.exports = WorkerPool;
