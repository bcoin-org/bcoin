var assert = require('assert');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var constants = bcoin.protocol.constants;

// Browserify, I'm looking at you
try {
  var NodeBuffer = require('buf' + 'fer').Buffer;
} catch (e) {
}

function Peer(pool, socket, options) {
  if (!(this instanceof Peer))
    return new Peer(pool, socket, options);

  EventEmitter.call(this);

  this.pool = pool;
  this.socket = socket;
  this.parser = new bcoin.protocol.parser();
  this.framer = new bcoin.protocol.framer();
  this.chain = this.pool.chain;
  this.bloom = this.pool.bloom;
  this.version = null;
  this.destroyed = false;
  this.ack = false;

  this.options = options || {};
  this._broadcast = {
    timeout: this.options.broadcastTimeout || 30000,
    interval: this.options.broadcastInterval || 3000,
    map: {}
  };

  this._request = {
    timeout: this.options.requestTimeout || 10000,
    cont: {},
    skip: {},
    queue: []
  };

  this._ping = {
    timer: null,
    interval: this.options.pingInterval || 30000
  };

  this._init();
}
util.inherits(Peer, EventEmitter);
module.exports = Peer;

Peer.prototype._init = function init() {
  var self = this;
  this.socket.once('error', function(err) {
    self._error(err);
  });
  this.socket.once('close', function() {
    self._error('socket hangup');
  });
  this.socket.on('data', function(chunk) {
    self.parser.feed(chunk);
  });
  this.parser.on('packet', function(packet) {
    self._onPacket(packet);
  });
  this.parser.on('error', function(err) {
    self._error(err);
  });

  this._ping.timer = setInterval(function() {
    self._write(self.framer.ping([
      0xde, 0xad, 0xbe, 0xef,
      0xde, 0xad, 0xbe, 0xef
    ]));
  }, this._ping.interval);

  // Send hello
  this._write(this.framer.version());
  this._req('verack', function(err, payload) {
    if (err)
      return self._error(err);
    self.ack = true;
    self.emit('ack');
  });

  this.setMaxListeners(4000);
};

Peer.prototype.broadcast = function broadcast(items) {
  if (!Array.isArray(items))
    items = [ items ];

  var self = this;
  var result = items.map(function(item) {
    var key = item.hash('hex');
    var old = this._broadcast.map[key];
    if (old) {
      clearTimeout(old.timer);
      clearInterval(old.interval);
    }

    var inv =  this.framer.inv([{
      type: item.type,
      hash: item.hash()
    }])

    // Auto-cleanup broadcast map after timeout
    var entry = {
      e: new EventEmitter(),
      timeout: setTimeout(function() {
        entry.e.emit('timeout');
        clearInterval(entry.interval);
        delete self._broadcast.map[key];
      }, this._broadcast.timeout),

      // Retransmit
      interval: setInterval(function() {
        self._write(inv);
      }, this._broadcast.interval),

      type: item.type,
      value: item.render()
    };

    this._broadcast.map[key] = entry;

    return entry.e;
  }, this);

  this._write(this.framer.inv(items.map(function(item) {
    return {
      type: item.type,
      hash: item.hash()
    };
  })));

  return result;
};

Peer.prototype.updateWatch = function updateWatch() {
  if (this.ack)
    this._write(this.framer.filterLoad(this.bloom, 'none'));
};

Peer.prototype.destroy = function destroy() {
  if (this.destroyed)
    return;
  this.destroyed = true;
  this.socket.destroy();
  this.socket = null;
  this.emit('close');

  // Clean-up timeouts
  Object.keys(this._broadcast.map).forEach(function(key) {
    clearTimeout(this._broadcast.map[key].timer);
    clearInterval(this._broadcast.map[key].interval);
  }, this);

  clearInterval(this._ping.timer);
  this._ping.timer = null;

  for (var i = 0; i < this._request.queue.length; i++)
    clearTimeout(this._request.queue[i].timer);
};

// Private APIs

Peer.prototype._write = function write(chunk) {
  if (!this.socket)
    return;
  if (NodeBuffer)
    this.socket.write(new NodeBuffer(chunk));
  else
    this.socket.write(chunk);
};

Peer.prototype._error = function error(err) {
  if (this.destroyed)
    return;
  this.destroy();
  this.emit('error', typeof err === 'string' ? new Error(err) : err);
};

Peer.prototype._req = function _req(cmd, cb) {
  var self = this;
  var entry = {
    cmd: cmd,
    cb: cb,
    ontimeout: function() {
      var i = self._request.queue.indexOf(entry);
      if (i !== -1) {
        self._request.queue.splice(i, 1);
        cb(new Error('Timed out: ' + cmd), null);
      }
    },
    timer: null
  };
  entry.timer = setTimeout(entry.ontimeout, this._request.timeout)
  this._request.queue.push(entry);

  return entry;
};

Peer.prototype._res = function _res(cmd, payload) {
  for (var i = 0; i < this._request.queue.length; i++) {
    var entry = this._request.queue[i];
    if (!entry || entry.cmd && entry.cmd !== cmd)
      return false;

    var res = entry.cb(null, payload, cmd);

    if (res === this._request.cont) {
      assert(!entry.cmd);

      // Restart timer
      entry.timer = setTimeout(entry.ontimeout, this._request.timeout)
      return true;
    } else if (res !== this._request.skip) {
      this._request.queue.shift();
      clearTimeout(entry.timer);
      entry.timer = null;
      return true;
    }
  }

  return false;
};

Peer.prototype.getData = function getData(items) {
  this._write(this.framer.getData(items));
};

Peer.prototype._onPacket = function onPacket(packet) {
  var cmd = packet.cmd;
  var payload = packet.payload;

  if (cmd === 'version')
    return this._handleVersion(payload);
  else if (cmd === 'inv')
    return this._handleInv(payload);
  else if (cmd === 'getdata')
    return this._handleGetData(payload);
  else if (cmd === 'addr')
    return this._handleAddr(payload);
  else if (cmd === 'ping')
    return this._handlePing(payload);
  else if (cmd === 'pong')
    return this._handlePong(payload);

  if (cmd === 'merkleblock' || cmd === 'block')
    payload = bcoin.block(payload);
  else if (cmd === 'tx')
    payload = bcoin.tx(payload);
  if (this._res(cmd, payload)) {
    return;
  } else {
    this.emit(cmd, payload);
  }
};

Peer.prototype._handleVersion = function handleVersion(payload) {
  if (payload.v < constants.minVersion)
    return this._error('peer doesn\'t support required protocol version');

  // ACK
  this._write(this.framer.verack());
  this.version = payload;
};

Peer.prototype._handleGetData = function handleGetData(items) {
  items.forEach(function(item) {
    // Filter out not broadcasted things
    var hash = utils.toHex(item.hash);
    if (!this._broadcast.map[hash])
      return;

    var entry = this._broadcast.map[hash];
    this._write(this.framer.packet(entry.type, entry.value));
    entry.e.emit('request');
  }, this);
};

Peer.prototype._handleAddr = function handleAddr(addr) {
  // No-op for now
};

Peer.prototype._handlePing = function handlePing() {
  // No-op for now
};

Peer.prototype._handlePong = function handlePong() {
  // No-op for now
};

Peer.prototype._handleInv = function handleInv(items) {
  // Always request advertised TXs
  var txs = items.filter(function(item) {
    return item.type === 'tx';
  }).map(function(item) {
    if (item.type === 'tx')
      return item;
  });

  // Emit new blocks to schedule them between multiple peers
  var blocks = items.filter(function(item) {
    return item.type === 'block';
  }, this).map(function(item) {
    return item.hash;
  });
  this.emit('blocks', blocks);

  if (txs.length === 0)
    return;

  this.getData(txs);
};

Peer.prototype.loadBlocks = function loadBlocks(hashes, stop) {
  this._write(this.framer.getBlocks(hashes, stop));
};
