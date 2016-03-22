/**
 * workers.js - worker processes for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var utils = require('./utils');
var assert = utils.assert;
var BufferWriter = require('./writer');
var BufferReader = require('./reader');
var cp = require('child_process');
var workers = exports;

var HEADER_SIZE = 12;

/**
 * Master
 */

workers.MAX_WORKERS = +process.env.BCOIN_WORKERS || 30;
workers.TIMEOUT = 10000;
workers.children = {};
workers.uid = 0;

workers.spawn = function spawn(index) {
  var child;

  utils.debug('Spawning worker process: %d', index);

  child = cp.spawn(process.argv[0], [__filename], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: utils.merge({}, process.env, {
      BCOIN_WORKER: index + ''
    })
  });

  child.on('error', function(err) {
    utils.debug('Worker %d error: %s', index, err.message);
  });

  child.on('exit', function(code) {
    utils.debug('Worker %d exited: %s', index, code);
    if (workers.children[index] === child)
      delete workers.children[index];
  });

  child.on('close', function() {
    utils.debug('Worker %d closed', index);
    if (workers.children[index] === child)
      delete workers.children[index];
  });

  child.stdout.on('data', parser(function(id, body) {
    child.emit('completed ' + id, body.items[0], body.items[1]);
  }));

  return child;
};

// Load balance the workers based on job ID.
workers.alloc = function alloc(id) {
  var index = id % workers.MAX_WORKERS;
  if (!workers.children[index])
    workers.children[index] = workers.spawn(index);
  return workers.children[index];
};

workers.call = function call(method, args, callback) {
  var id = workers.uid++;
  var event, child, timeout;

  if (id > 0xffffffff) {
    workers.uid = 0;
    id = workers.uid++;
  }

  event = 'completed ' + id;
  child = workers.alloc(id);

  function listener(err, result) {
    clearTimeout(timeout);
    timeout = null;
    callback(err, result);
  }

  child.once(event, listener);

  timeout = setTimeout(function() {
    child.removeListener(event, listener);
    return callback(new Error('Worker timed out.'));
  }, workers.TIMEOUT);

  child.stdin.write(createPacket(id, method, args));
};

/**
 * Calls
 */

bcoin.tx.prototype.verifyAsync = function verifyAsync(index, force, flags, callback) {
  callback = utils.asyncify(callback);

  if (!force && this.ts !== 0)
    return callback(null, true);

  if (this.inputs.length === 0)
    return callback(null, false);

  if (this.isCoinbase())
    return callback(null, true);

  return workers.call('verify', [this, index, force, flags], callback);
};

/**
 * Child
 */

workers.listen = function listen() {
  bcoin.debug = function debug() {
    process.stderr.write('Worker %s: ', process.env.BCOIN_WORKER);
    return console.error.apply(console.error, arguments);
  };

  utils.debug = bcoin.debug;
  utils.print = bcoin.debug;

  process.stdin.on('data', parser(function(id, body) {
    var res;

    try {
      res = workers[body.name].apply(workers[body.name], body.items);
    } catch (e) {
      utils.debug(e.stack + '');
      return process.stdout.write(createPacket(id, null, [{
        message: e.message,
        stack: e.stack + ''
      }]));
    }

    return process.stdout.write(createPacket(id, null, [null, res]));
  }));
};

/**
 * Calls
 * The actual calls that are run
 * in a separate worker process.
 */

workers.verify = function verify(tx, index, force, flags) {
  tx = bcoin.tx.fromExtended(tx, true);
  return tx.verify(index, force, flags);
};

/**
 * Helpers
 */

function createPacket(id, name, items) {
  var p = new BufferWriter();
  var payload = createBody(name, items);
  p.writeU32(0xdeadbeef);
  p.writeU32(id);
  p.writeU32(payload.length);
  p.writeBytes(payload);
  return p.render();
}

function createBody(name, items) {
  var p = new BufferWriter();
  var i, item;

  if (name)
    p.writeVarString(name, 'ascii');
  else
    p.writeUIntv(0);

  p.writeUIntv(items.length);

  for (i = 0; i < items.length; i++) {
    item = items[i];
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
          if (item.toExtended)
            item = item.toExtended(true);
          if (Buffer.isBuffer(item)) {
            p.writeU8(5);
            p.writeVarBytes(item);
          } else {
            p.writeU8(4);
            p.writeVarString(JSON.stringify(item), 'utf8');
          }
        }
        break;
      default:
        assert(false, 'Bad type: ' + typeof item);
    }
  }

  p.writeU8(0x0a);

  return p.render();
}

function parseBody(data) {
  var p = new BufferReader(data, true);
  var name, count, i;
  var items = [];

  p.start();

  name = p.readVarString('ascii');
  count = p.readUIntv();

  for (i = 0; i < count; i++) {
    switch (p.readU8()) {
      case 0:
        items.push(null);
        break;
      case 1:
        items.push(p.readVarString('utf8'));
        break;
      case 2:
        items.push(p.read32());
        break;
      case 3:
        items.push(p.readU8() === 1);
        break;
      case 4:
        items.push(items.parse(p.readVarString('utf8')));
        break;
      case 5:
        items.push(p.readVarBytes());
        break;
    }
  }

  assert(p.readU8() === 0x0a);

  p.end();

  return {
    name: name || null,
    items: items
  };
}

function parseHeader(data) {
  return {
    magic: utils.readU32(data, 0),
    id: utils.readU32(data, 4),
    size: utils.readU32(data, 8)
  };
}

function parser(onPacket) {
  var waiting = HEADER_SIZE;
  var wait = 0;
  var buf = [];
  var read = 0;
  var header = null;

  return function parse(data) {
    var packet, rest;

    read += data.length;
    buf.push(data);

    if (read < waiting)
      return;

    buf = Buffer.concat(buf);

    if (buf.length > waiting) {
      packet = buf.slice(0, waiting);
      rest = buf.slice(waiting);
    } else {
      packet = buf;
    }

    if (!header) {
      header = parseHeader(packet);

      if (header.magic !== 0xdeadbeef) {
        buf = [];
        waiting = HEADER_SIZE;
        read = 0;
        utils.debug('Bad magic number: %d', header.magic);
        return;
      }

      buf = [];
      waiting = header.size;
      read = 0;

      if (rest)
        parse(rest);

      return;
    }

    try {
      packet = parseBody(packet);
    } catch (e) {
      utils.debug(e.stack + '');
      return;
    }

    onPacket(header.id, packet);

    buf = [];
    waiting = HEADER_SIZE;
    read = 0;
    header = null;

    if (rest)
      parse(rest);
  };
}

if (process.env.BCOIN_WORKER)
  workers.listen();
