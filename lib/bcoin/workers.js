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
 * @property {Number} uid
 */

function Workers(options) {
  if (!(this instanceof Workers))
    return new Workers(options);

  EventEmitter.call(this);

  this.uid = 0;
  this.size = Math.max(1, options.size || Workers.CORES);
  this.timeout = options.timeout || 60000;
  this.network = bcoin.network.get(options.network);
  this.children = [];
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
 * Cleanup all workers on exit.
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
      console.error(err.stack + '');
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
  var i, child;

  bcoin.debug('Spawning worker process: %d', id);

  child = new Worker(this, id);

  child.on('error', function(err) {
    bcoin.debug('Worker %d error: %s', child.id, err.message);
  });

  child.on('exit', function(code) {
    bcoin.debug('Worker %d exited: %s', child.id, code);
    if (self.children[child.id] === child)
      self.children[child.id] = null;
    i = Workers.children.indexOf(child);
    if (i !== -1)
      Workers.children.splice(i, 1);
  });

  child.on('packet', function(job, body) {
    if (body.name === 'event') {
      child.emit.apply(child, body.items);
      self.emit.apply(self, body.items);
      return;
    }
    if (body.name === 'response') {
      child.emit('response ' + job, body.items[0], body.items[1]);
      return;
    }
    self.emit('error', new Error('Unknown packet: ' + body.name));
  });

  Workers.children.push(child);

  Workers._bindExit();

  return child;
};

/**
 * Allocate a new worker, will not go above `size` option
 * and will automatically load balance the workers based
 * on job ID.
 * @param {Number} job
 * @returns {Worker}
 */

Workers.prototype.alloc = function alloc(job) {
  var id = job % this.size;
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
  var job = this.uid++;
  var child;

  if (job > 0xffffffff) {
    this.uid = 0;
    job = this.uid++;
  }

  if (!timeout)
    timeout = this.timeout;

  child = this.alloc(job);

  child.execute(job, method, args, timeout, callback);

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
 * @param {Workers} pool
 * @param {Number} id - Worker ID.
 * @property {Number} id
 */

function Worker(pool, id) {
  var self = this;
  var penv, cp;

  if (!(this instanceof Worker))
    return new Worker(pool, id);

  EventEmitter.call(this);

  this.id = id;
  this.pool = pool;
  this.framer = new Framer();
  this.parser = new Parser();
  this.setMaxListeners(utils.MAX_SAFE_INTEGER);

  penv = {
    BCOIN_WORKER_ID: id + '',
    BCOIN_WORKER_NETWORK: this.pool.network.type,
    BCOIN_WORKER_DEBUG: (bcoin.debugLogs || bcoin.debugFile) ? '1' : '0'
  };

  if (bcoin.isBrowser) {
    this.child = new global.Worker('/bcoin-worker.js');

    this.child.onerror = function onerror(err) {
      self.emit('error', err);
      self.emit('exit', 1, null);
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

    this.child.stderr.setEncoding('utf8');
    this.child.stderr.on('data', function(data) {
      bcoin.debug(data.trim());
    });
  }

  this.on('data', function(data) {
    self.parser.feed(data);
  });

  this.parser.on('error', function(e) {
    self.emit('error', e);
  });

  this.parser.on('packet', function(job, body) {
    self.emit('packet', job, body);
  });
}

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Worker.prototype.write = function write(data) {
  if (bcoin.isBrowser) {
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
 * @param {String} name
 * @param {Array} items
 * @returns {Boolean}
 */

Worker.prototype.send = function send(job, name, items) {
  return this.write(this.framer.packet(job, name, items));
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

Worker.prototype.execute = function execute(job, method, args, timeout, callback) {
  var self = this;
  var event = 'response ' + job;
  var timer;

  assert(job <= 0xffffffff);

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
 * @param {Number} id - Worker ID.
 * @param {Object?} options
 * @property {Number} id
 */

function Master(id, options) {
  var self = this;

  if (!(this instanceof Master))
    return new Master(id);

  EventEmitter.call(this);

  this.id = id;
  this.framer = new Framer();
  this.parser = new Parser();
  this.options = options || {};

  if (bcoin.isBrowser) {
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

  this.parser.on('packet', function(job, body) {
    self.emit('packet', job, body);
  });
}

utils.inherits(Master, EventEmitter);

/**
 * Send data to worker.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Master.prototype.write = function write(data) {
  if (bcoin.isBrowser) {
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
 * @param {String} name
 * @param {Array} items
 * @returns {Boolean}
 */

Master.prototype.send = function send(job, name, items) {
  return this.write(this.framer.packet(job, name, items));
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
 * Write a debug message, prefixing
 * it with the worker ID.
 * @param {...String} args
 */

Master.prototype.debug = function debug() {
  var i, args, msg;

  if (!this.options.debug)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  msg = utils.format(args, false);
  msg = utils.format(['Worker %d: %s', this.id, msg], false);

  if (bcoin.isBrowser) {
    console.error(msg);
    return;
  }

  process.stderr.write(msg + '\n');
};

/**
 * Write an error as a debug message.
 * @param {Error} err
 */

Master.prototype.error = function error(err) {
  if (!err)
    return;

  this.debug(err.message);
};

/**
 * Destroy the worker.
 */

Master.prototype.destroy = function destroy() {
  if (bcoin.isBrowser)
    return global.close();
  return process.exit(0);
};

/**
 * Listen for messages from master process (only if worker).
 * @param {Number} id - Worker id.
 * @param {Object?} options
 * @returns {Master}
 */

Master.listen = function listen(id, options) {
  var master = new Master(id, options);
  var debug = master.debug.bind(master);
  var error = master.error.bind(master);

  bcoin.debug = debug;
  bcoin.error = error;
  utils.print = debug;
  utils.error = debug;

  master.on('error', function(err) {
    bcoin.debug('Master error: %s', err.message);
  });

  master.on('packet', function(job, body) {
    var result;

    if (body.name === 'event') {
      master.emit.apply(master, body.items);
      return;
    }

    try {
      result = jobs[body.name].apply(jobs, body.items);
    } catch (e) {
      bcoin.debug(e.stack + '');
      return master.send(job, 'response', [{
        message: e.message,
        stack: e.stack + ''
      }]);
    }

    return master.send(job, 'response', [null, result]);
  });

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
 * Mine a block on worker.
 * @param {Object} attempt - Naked {@link MinerBlock}.
 * @returns {Block}
 */

jobs.mine = function mine(attempt) {
  attempt.on('status', function(stat) {
    bcoin.debug(
      'Miner: hashrate=%dkhs hashes=%d target=%d height=%d best=%s',
      stat.hashrate / 1000 | 0,
      stat.hashes,
      stat.target,
      stat.height,
      stat.best);
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
  return scrypt(passwd, salt, N, r, p, len);
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

Framer.prototype.packet = function packet(job, name, items) {
  var p = new BufferWriter();
  var payload = this.body(name, items);
  p.writeU32(0xdeadbeef);
  p.writeU32(job);
  p.writeU32(payload.length);
  p.writeBytes(payload);
  return p.render();
};

Framer.prototype.body = function body(name, items) {
  var p = new BufferWriter();

  if (name)
    p.writeVarString(name, 'ascii');
  else
    p.writeVarint(0);

  Framer.item(items, p);

  p.writeU8(0x0a);

  return p.render();
};

Framer.item = function _item(item, p) {
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
          bcoin.protocol.framer.witnessBlock(item, p);
        } else if (item instanceof bcoin.tx) {
          p.writeU8(41);
          bcoin.protocol.framer.extendedTX(item, true, p);
        } else if (item instanceof bcoin.coin) {
          p.writeU8(42);
          bcoin.protocol.framer.coin(item, true, p);
        } else if (item instanceof bcoin.chainentry) {
          p.writeU8(43);
          item.toRaw(p);
        } else if (item instanceof bcoin.mempoolentry) {
          p.writeU8(44);
          item.toRaw(p);
        } else if (item instanceof bcoin.minerblock) {
          p.writeU8(45);
          item.toRaw(p);
        } else if (bn.isBN(item)) {
          p.writeU8(50);
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
      assert(false, 'Bad type: ' + typeof item);
  }
};

/**
 * Parser
 * @constructor
 */

function Parser() {
  if (!(this instanceof Parser))
    return new Parser();

  EventEmitter.call(this);

  this.waiting = 12;
  this.header = null;
  this.pending = [];
  this.pendingTotal = 0;
}

utils.inherits(Parser, EventEmitter);

Parser.prototype.feed = function feed(data) {
  var chunk, header, body, rest;

  this.pendingTotal += data.length;
  this.pending.push(data);

  if (this.pendingTotal < this.waiting)
    return;

  chunk = Buffer.concat(this.pending);

  if (chunk.length > this.waiting) {
    rest = chunk.slice(this.waiting);
    chunk = chunk.slice(0, this.waiting);
  }

  if (!this.header) {
    this.header = this.parseHeader(chunk);
    this.waiting = this.header.size;
    this.pending.length = 0;
    this.pendingTotal = 0;

    if (this.header.magic !== 0xdeadbeef) {
      this.header = null;
      this.waiting = 12;
      this.emit('error', new Error('Bad magic number.'));
      return;
    }

    if (rest)
      this.feed(rest);

    return;
  }

  header = this.header;

  this.pending.length = 0;
  this.pendingTotal = 0;
  this.waiting = 12;
  this.header = null;

  try {
    body = this.parseBody(chunk);
  } catch (e) {
    this.emit('error', e);
    return;
  }

  this.emit('packet', header.job, body);

  if (rest)
    this.feed(rest);
};

Parser.prototype.parseHeader = function parseHeader(data) {
  return {
    magic: data.readUInt32LE(0, true),
    job: data.readUInt32LE(4, true),
    size: data.readUInt32LE(8, true)
  };
};

Parser.prototype.parseBody = function parseBody(data) {
  var p = new BufferReader(data, true);
  var name, items;

  name = p.readVarString('ascii');
  items = Parser.parseItem(p);

  assert(p.readU8() === 0x0a);

  return {
    name: name || null,
    items: items
  };
};

Parser.parseItem = function parseItem(p) {
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
    case 50:
      return new bn(p.readVarBytes());
    default:
      assert(false, 'Bad type.');
  }
};

/**
 * Helper to retrieve number of cores.
 * @memberof Workers
 * @returns {Number}
 */

function getCores() {
  var os;

  if (utils.isBrowser)
    return 2;

  os = require('o' + 's');

  return os.cpus().length;
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
