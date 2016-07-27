/*!
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('./env');
var EventEmitter = require('events').EventEmitter;
var bn = require('bn.js');
var utils = require('./utils');
var global = utils.global;
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var jobs;

/**
 * A worker pool.
 * @exports Workers
 * @constructor
 * @param {Object} options
 * @param {Number} [options.size=num-cores] - Max pool size.
 * @param {Number} [options.timeout=10000] - Execution timeout.
 * @property {Number} size
 * @property {Number} timeout
 * @property {Object} children
 * @property {Number} nonce
 */

function Workers(options) {
  if (!(this instanceof Workers))
    return new Workers(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.size = Math.max(1, options.size || Workers.CORES);
  this.timeout = options.timeout || 60000;
  this.children = [];
  this.nonce = 0;
}

utils.inherits(Workers, EventEmitter);

/**
 * Number of CPUs/cores available.
 * @const {Number}
 */

Workers.CORES = getCores();

/**
 * Global list of workers.
 * @type {Array}
 */

Workers.children = [];

/**
 * Destroy all workers.
 * Used for cleaning up workers on exit.
 * @private
 */

Workers.cleanup = function cleanup() {
  while (Workers.children.length > 0)
    Workers.children.pop().destroy();
};

Workers._exitBound = false;

/**
 * Bind to process events in order to cleanup listeners.
 * @private
 */

Workers._bindExit = function _bindExit() {
  if (utils.isBrowser)
    return;

  if (Workers._exitBound)
    return;

  Workers._exitBound = true;

  function onExit(err) {
    Workers.cleanup();

    if (err) {
      utils.error(err.stack + '');
      process.exit(1);
      return;
    }

    process.exit(0);
  }

  process.once('exit', function() {
    Workers.cleanup();
  });

  if (process.listeners('SIGINT').length === 0)
    process.once('SIGINT', onExit);

  if (process.listeners('SIGTERM').length === 0)
    process.once('SIGTERM', onExit);

  if (process.listeners('uncaughtException').length === 0)
    process.once('uncaughtException', onExit);

  process.on('newListener', function(name) {
    if (name === 'SIGINT'
        || name === 'SIGTERM'
        || name === 'uncaughtException') {
      process.removeListener(name, onExit);
    }
  });
};

/**
 * Spawn a new worker.
 * @param {Number} id - Worker ID.
 * @returns {Worker}
 */

Workers.prototype.spawn = function spawn(id) {
  var self = this;
  var child;

  child = new Worker(id);

  child.on('error', function(err) {
    self.emit('error', err, child);
  });

  child.on('exit', function(code) {
    self.emit('exit', code, child);
    if (self.children[child.id] === child)
      self.children[child.id] = null;
  });

  child.on('event', function(items) {
    self.emit('event', items, child);
    self.emit.apply(self, items);
  });

  this.emit('spawn', child);

  return child;
};

/**
 * Allocate a new worker, will not go above `size` option
 * and will automatically load balance the workers.
 * @returns {Worker}
 */

Workers.prototype.alloc = function alloc() {
  var id = this.nonce++ % this.size;
  if (!this.children[id])
    this.children[id] = this.spawn(id);
  return this.children[id];
};

/**
 * Emit an event on the worker side (all workers).
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Workers.prototype.sendEvent = function sendEvent() {
  var i, child;
  var result = true;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (!child)
      continue;

    if (!child.sendEvent.apply(child, arguments))
      result = false;
  }

  return result;
};

/**
 * Destroy all workers.
 */

Workers.prototype.destroy = function destroy() {
  var i, child;

  for (i = 0; i < this.children.length; i++) {
    child = this.children[i];

    if (!child)
      continue;

    child.destroy();
  }
};

/**
 * Call a method for a worker to execute.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @param {Function} callback - Returns whatever
 * the worker method specifies.
 */

Workers.prototype.execute = function execute(method, args, timeout, callback) {
  var child;

  if (!timeout)
    timeout = this.timeout;

  child = this.alloc();

  child.execute(method, args, timeout, callback);

  return child;
};

/**
 * Execute the tx verification job (default timeout).
 * @param {TX} tx
 * @param {VerifyFlags} flags
 * @param {Function} callback - Returns [Error, Boolean].
 */

Workers.prototype.verify = function verify(tx, flags, callback) {
  return this.execute('verify', [tx, flags], -1, callback);
};

/**
 * Execute the tx signing job (default timeout).
 * @param {KeyRing[]} addresses
 * @param {HDPrivateKey} master
 * @param {MTX} tx
 * @param {Number?} index
 * @param {SighashType?} type
 * @param {Function} callback
 */

Workers.prototype.sign = function sign(addresses, master, tx, index, type, callback) {
  var args = [addresses, master, tx, index, type];
  var i, input, sig, sigs, total;

  return this.execute('sign', args, -1, function(err, result) {
    if (err)
      return callback(err);

    sigs = result[0];
    total = result[1];

    for (i = 0; i < sigs.length; i++) {
      sig = sigs[i];
      input = tx.inputs[i];
      input.script = sig[0];
      input.witness = sig[1];
    }

    return callback(null, total);
  });
};

/**
 * Execute the mining job (no timeout).
 * @param {MinerBlock} attempt
 * @param {Function} callback - Returns [Error, {@link MinerBlock}].
 */

Workers.prototype.mine = function mine(attempt, callback) {
  return this.execute('mine', [attempt], -1, callback);
};

/**
 * Execute scrypt job (no timeout).
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @param {Function} callback
 * @returns {Buffer}
 */

Workers.prototype.scrypt = function scrypt(passwd, salt, N, r, p, len, callback) {
  return this.execute('scrypt', [passwd, salt, N, r, p, len], -1, callback);
};

/**
 * Represents a worker.
 * @exports Worker
 * @constructor
 * @param {Number?} id
 */

function Worker(id) {
  var self = this;
  var penv, cp;

  if (!(this instanceof Worker))
    return new Worker();

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();
  this.setMaxListeners(utils.MAX_SAFE_INTEGER);
  this.uid = 0;
  this.id = id != null ? id : -1;

  penv = {
    BCOIN_WORKER_NETWORK: bcoin.network.get().type
  };

  if (utils.isBrowser) {
    this.child = new global.Worker('/bcoin-worker.js');

    this.child.onerror = function onerror(err) {
      self.emit('error', err);
      self.emit('exit', -1, null);
    };

    this.child.onmessage = function onmessage(event) {
      var data;
      if (typeof event.data !== 'string') {
        data = event.data.buf;
        data.__proto__ = Buffer.prototype;
      } else {
        data = new Buffer(event.data, 'hex');
      }
      self.emit('data', data);
    };

    this.child.postMessage(JSON.stringify(penv));
  } else {
    cp = require('child_' + 'process');

    this.child = cp.spawn(process.argv[0], [__dirname + '/worker.js'], {
      stdio: 'pipe',
      env: utils.merge({}, process.env, penv)
    });

    this.child.on('error', function(err) {
      self.emit('error', err);
    });

    this.child.on('exit', function(code, signal) {
      self.emit('exit', code == null ? -1 : code, signal);
    });

    this.child.on('close', function() {
      self.emit('exit', -1, null);
    });

    this.child.stdin.on('error', function(err) {
      self.emit('error', err);
    });

    this.child.stdout.on('error', function(err) {
      self.emit('error', err);
    });

    this.child.stderr.on('error', function(err) {
      self.emit('error', err);
    });

    this.child.stdout.on('data', function(data) {
      self.emit('data', data);
    });
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

  this._init();
}

/**
 * Initialize worker.
 * @private
 */

Worker.prototype._init = function _init() {
  var self = this;

  this.on('worker error', function(err) {
    self.emit('error', toError(err));
  });

  this.on('exit', function(code) {
    var i = Workers.children.indexOf(self);
    if (i !== -1)
      Workers.children.splice(i, 1);
  });

  this.on('log', function(items) {
    utils.log('Worker %d:', self.id);
    utils.log.apply(utils, items);
  });

  this.on('packet', function(packet) {
    var err, result;

    if (packet.cmd === 'event') {
      self.emit.apply(self, packet.items);
      self.emit('event', packet.items);
      return;
    }

    if (packet.cmd === 'response') {
      err = packet.items[0];
      result = packet.items[1];

      if (err)
        err = toError(err);

      self.emit('response ' + packet.job, err, result);

      return;
    }

    err = new Error('Unknown packet: ' + packet.cmd);
    self.emit('error', err);
  });

  Workers.children.push(this);

  Workers._bindExit();
};

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  if (utils.isBrowser) {
    if (this.child.postMessage.length === 2) {
      data.__proto__ = Uint8Array.prototype;
      this.child.postMessage({ buf: data }, [data]);
    } else {
      this.child.postMessage(data.toString('hex'));
    }
    return true;
  }
  return this.child.stdin.write(data);
};

/**
 * Frame and send a packet.
 * @param {String} job
 * @param {String} cmd
 * @param {Array} items
 * @returns {Boolean}
 */

Worker.prototype.send = function send(job, cmd, items) {
  return this.write(this.framer.packet(job, cmd, items));
};

/**
 * Emit an event on the worker side.
 * @param {String} event
 * @param {...Object} arg
 * @returns {Boolean}
 */

Worker.prototype.sendEvent = function sendEvent() {
  var items = new Array(arguments.length);
  var i;

  for (i = 0; i < items.length; i++)
    items[i] = arguments[i];

  return this.send(0, 'event', items);
};

/**
 * Destroy the worker.
 */

Worker.prototype.destroy = function destroy() {
  if (utils.isBrowser) {
    this.child.terminate();
    this.emit('exit', -1, 'SIGTERM');
    return;
  }
  return this.child.kill('SIGTERM');
};

/**
 * Call a method for a worker to execute.
 * @param {Number} job - Job ID.
 * @param {String} method - Method name.
 * @param {Array} args - Arguments.
 * @param {Function} callback - Returns whatever
 * the worker method specifies.
 */

Worker.prototype.execute = function execute(method, args, timeout, callback) {
  var self = this;
  var job = this.uid++;
  var event, timer;

  if (job > 0xffffffff) {
    this.uid = 0;
    job = this.uid++;
  }

  event = 'response ' + job;

  function listener(err, result) {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    self.removeListener(event, listener);
    self.removeListener('error', listener);
    self.removeListener('exit', exitListener);
    callback(err, result);
  }

  function exitListener(code) {
    listener(new Error('Worker exited: ' + code));
  }

  this.once(event, listener);
  this.once('error', listener);
  this.once('exit', exitListener);

  if (timeout !== -1) {
    timer = setTimeout(function() {
      listener(new Error('Worker timed out.'));
    }, timeout);
  }

  this.send(job, method, args);
};

utils.inherits(Worker, EventEmitter);

/**
 * Represents the master process.
 * @exports Master
 * @constructor
 * @param {Object?} options
 */

function Master(options) {
  var self = this;

  if (!(this instanceof Master))
    return new Master();

  EventEmitter.call(this);

  this.framer = new Framer();
  this.parser = new Parser();
  this.options = options || {};

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
}

utils.inherits(Master, EventEmitter);

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
 * @param {Object?} options
 * @returns {Master}
 */

Master.listen = function listen(options) {
  var master = new Master(options);

  utils.log = master.log.bind(master);
  utils.error = utils.log;

  master.on('error', function(err) {
    master.sendEvent('worker error', fromError(err));
  });

  master.on('packet', function(packet) {
    var result;

    if (packet.cmd === 'event') {
      master.emit('event', packet.items);
      master.emit.apply(master, packet.items);
      return;
    }

    try {
      result = jobs[packet.cmd].apply(jobs, packet.items);
    } catch (e) {
      return master.send(packet.job, 'response', [fromError(e)]);
    }

    return master.send(packet.job, 'response', [null, result]);
  });

  bcoin.master = master;

  return master;
};

/**
 * Jobs to execute within the worker.
 * @memberof Workers
 * @const {Object}
 */

jobs = {};

/**
 * Execute tx.verify() on worker.
 * @see TX#verify
 * @param {TX} tx
 * @param {VerifyFlags} flags
 * @returns {Boolean}
 */

jobs.verify = function verify(tx, flags) {
  return tx.verify(flags);
};

/**
 * Execute Wallet.sign() on worker.
 * @see Wallet.sign
 * @param {KeyRing[]} addresses
 * @param {HDPrivateKey} master
 * @param {MTX} tx
 * @param {Number?} index
 * @param {SighashType?} type
 */

jobs.sign = function sign(addresses, master, tx, index, type) {
  var total = bcoin.wallet.sign(addresses, master, tx, index, type);
  var sigs = [];
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    sigs.push([input.script, input.witness]);
  }

  return [sigs, total];
};

/**
 * Mine a block on worker.
 * @param {Object} attempt - Naked {@link MinerBlock}.
 * @returns {Block}
 */

jobs.mine = function mine(attempt) {
  attempt.on('status', function(stat) {
    bcoin.master.sendEvent('status', stat);
  });
  return attempt.mineSync();
};

/**
 * Execute scrypt() on worker.
 * @see scrypt
 * @param {Buffer} passwd
 * @param {Buffer} salt
 * @param {Number} N
 * @param {Number} r
 * @param {Number} p
 * @param {Number} len
 * @returns {Buffer}
 */

jobs.scrypt = function scrypt(passwd, salt, N, r, p, len) {
  var scrypt = require('./scrypt');
  return scrypt(passwd, salt, N >>> 0, r >>> 0, p >>> 0, len);
};

/**
 * Framer
 * @constructor
 */

function Framer() {
  if (!(this instanceof Framer))
    return new Framer();

  EventEmitter.call(this);
}

utils.inherits(Framer, EventEmitter);

Framer.prototype.packet = function packet(job, cmd, items) {
  var payload = this.body(items);
  var packet = new Buffer(25 + payload.length + 1);

  assert(cmd.length < 12);
  assert(payload.length <= 0xffffffff);

  packet.writeUInt32LE(0xdeadbeef, 0, true);
  packet.writeUInt32LE(job, 4, true);
  packet.writeUInt8(cmd.length, 8, true);
  packet.write(cmd, 9, 'ascii');
  packet.writeUInt32LE(payload.length + 1, 21, true);
  payload.copy(packet, 25);
  packet[packet.length - 1] = 0x0a;

  return packet;
};

Framer.prototype.body = function body(items) {
  return Framer.item(items);
};

Framer.item = function _item(item, writer) {
  var p = BufferWriter(writer);
  var i, keys;

  switch (typeof item) {
    case 'string':
      p.writeU8(1);
      p.writeVarString(item, 'utf8');
      break;
    case 'number':
      p.writeU8(2);
      p.write32(item);
      break;
    case 'boolean':
      p.writeU8(3);
      p.writeU8(item ? 1 : 0);
      break;
    case 'object':
    case 'undefined':
      if (item == null) {
        p.writeU8(0);
      } else {
        if (item instanceof bcoin.block) {
          p.writeU8(40);
          item.toRaw(p);
        } else if (item instanceof bcoin.mtx) {
          p.writeU8(46);
          item.toExtended(true, p);
        } else if (item instanceof bcoin.tx) {
          p.writeU8(41);
          item.toExtended(true, p);
        } else if (item instanceof bcoin.coin) {
          p.writeU8(42);
          item.toExtended(p);
        } else if (item instanceof bcoin.chainentry) {
          p.writeU8(43);
          item.toRaw(p);
        } else if (item instanceof bcoin.mempoolentry) {
          p.writeU8(44);
          item.toRaw(p);
        } else if (item instanceof bcoin.minerblock) {
          p.writeU8(45);
          item.toRaw(p);
        } else if (item instanceof bcoin.keyring) {
          p.writeU8(47);
          item.toRaw(p);
        } else if (item instanceof bcoin.hd) {
          p.writeU8(48);
          p.writeBytes(item.toRaw());
        } else if (item instanceof bcoin.script) {
          p.writeU8(49);
          p.writeVarBytes(item.toRaw());
        } else if (item instanceof bcoin.witness) {
          p.writeU8(50);
          item.toRaw(p);
        } else if (bn.isBN(item)) {
          p.writeU8(10);
          p.writeVarBytes(item.toArrayLike(Buffer));
        } else if (Buffer.isBuffer(item)) {
          p.writeU8(4);
          p.writeVarBytes(item);
        } else if (Array.isArray(item)) {
          p.writeU8(5);
          p.writeVarint(item.length);
          for (i = 0; i < item.length; i++)
            Framer.item(item[i], p);
        } else {
          keys = Object.keys(item);
          p.writeU8(6);
          p.writeVarint(keys.length);
          for (i = 0; i < keys.length; i++) {
            p.writeVarString(keys[i], 'utf8');
            Framer.item(item[keys[i]], p);
          }
        }
      }
      break;
    default:
      throw new Error('Bad type.');
  }

  if (!writer)
    p = p.render();

  return p;
};

/**
 * Parser
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.waiting = 25;
  this.packet = null;
  this.pending = [];
  this.total = 0;
}

utils.inherits(Parser, EventEmitter);

Parser.prototype.feed = function feed(data) {
  var chunk;

  this.total += data.length;
  this.pending.push(data);

  while (this.total >= this.waiting) {
    chunk = this.read(this.waiting);
    this.parse(chunk);
  }
};

Parser.prototype.read = function read(size) {
  var pending, chunk, off, len;

  assert(this.total >= size, 'Reading too much.');

  if (size === 0)
    return new Buffer(0);

  pending = this.pending[0];

  if (pending.length > size) {
    chunk = pending.slice(0, size);
    this.pending[0] = pending.slice(size);
    this.total -= chunk.length;
    return chunk;
  }

  if (pending.length === size) {
    chunk = this.pending.shift();
    this.total -= chunk.length;
    return chunk;
  }

  chunk = new Buffer(size);
  off = 0;
  len = 0;

  while (off < chunk.length) {
    pending = this.pending[0];
    len = pending.copy(chunk, off);
    if (len === pending.length)
      this.pending.shift();
    else
      this.pending[0] = pending.slice(len);
    off += len;
  }

  assert.equal(off, chunk.length);

  this.total -= chunk.length;

  return chunk;
};

Parser.prototype.parse = function parse(data) {
  var packet;

  if (!this.packet) {
    try {
      packet = this.parseHeader(data);
    } catch (e) {
      this.emit('error', e);
      return;
    }

    this.packet = packet;
    this.waiting = packet.size;

    return;
  }

  packet = this.packet;

  this.waiting = 25;
  this.packet = null;

  try {
    packet.items = this.parseBody(data);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  if (data[data.length - 1] !== 0x0a) {
    this.emit('error', new Error('No trailing newline.'));
    return;
  }

  this.emit('packet', packet);
};

Parser.prototype.parseHeader = function parseHeader(data) {
  var magic, job, len, cmd, size;

  magic = data.readUInt32LE(0, true);

  if (magic !== 0xdeadbeef)
    throw new Error('Bad magic number: ' + magic.toString(16));

  job = data.readUInt32LE(4, true);

  len = data[8];
  cmd = data.toString('ascii', 9, 9 + len);

  size = data.readUInt32LE(21, true);

  return new Packet(job, cmd, size);
};

Parser.prototype.parseBody = function parseBody(data) {
  return Parser.parseItem(data);
};

Parser.parseItem = function parseItem(data) {
  var p = BufferReader(data);
  var i, count, items;

  switch (p.readU8()) {
    case 0:
      return null;
    case 1:
      return p.readVarString('utf8');
    case 2:
      return p.read32();
    case 3:
      return p.readU8() === 1;
    case 4:
      return p.readVarBytes();
    case 5:
      items = [];
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items.push(Parser.parseItem(p));
      return items;
    case 6:
      items = {};
      count = p.readVarint();
      for (i = 0; i < count; i++)
        items[p.readVarString('utf8')] = Parser.parseItem(p);
      return items;
    case 10:
      return new bn(p.readVarBytes());
    case 40:
      return bcoin.block.fromRaw(p);
    case 41:
      return bcoin.tx.fromExtended(p, true);
    case 42:
      return bcoin.coin.fromExtended(p);
    case 43:
      return bcoin.chainentry.fromRaw(null, p);
    case 44:
      return bcoin.mempoolentry.fromRaw(p);
    case 45:
      return bcoin.minerblock.fromRaw(p);
    case 46:
      return bcoin.mtx.fromExtended(p, true);
    case 47:
      return bcoin.keyring.fromRaw(p);
    case 48:
      return bcoin.hd.fromRaw(p.readBytes(82));
    case 49:
      return bcoin.script.fromRaw(p.readVarBytes());
    case 50:
      return bcoin.witness.fromRaw(p);
    default:
      throw new Error('Bad type.');
  }
};

/**
 * Packet
 * @constructor
 */

function Packet(job, cmd, size) {
  this.job = job;
  this.cmd = cmd;
  this.size = size;
  this.items = null;
}

/*
 * Helpers
 */

function getCores() {
  var os;

  if (utils.isBrowser)
    return 2;

  os = require('o' + 's');

  return os.cpus().length;
}

function toError(values) {
  var err = new Error(values[0]);
  err.stack = values[1];
  err.type = values[2];
  return err;
}

function fromError(err) {
  return [err.message, err.stack + '', err.type];
}

/*
 * Expose
 */

exports = Workers;

exports.Workers = Workers;
exports.Worker = Worker;
exports.Master = Master;
exports.Framer = Framer;
exports.Parser = Parser;
exports.listen = Master.listen;

module.exports = exports;
