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

function Peer(socket, options) {
  if (!(this instanceof Peer))
    return new Peer(socket, options);

  EventEmitter.call(this);
  this.socket = socket;
  this.parser = new bcoin.protocol.parser();
  this.framer = new bcoin.protocol.framer();
  this.bloom = new bcoin.bloom(8 * 10 * 1024,
                               10,
                               (Math.random() * 0xffffffff) | 0),
  this.version = null;
  this.destroyed = false;

  this.options = options || {};
  this._broadcast = {
    timout: this.options.broadcastTimeout || 30000,
    map: {}
  };

  this._request = {
    timeout: this.options.requestTimeout || 30000,
    queue: []
  };

  this._ping = {
    timer: null,
    interval: this.options.pingInterval || 5000
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
    self.emit('ack');
  });
};

Peer.prototype.broadcast = function broadcast(items) {
  if (!Array.isArray(items))
    items = [ items ];

  var self = this;
  items.forEach(function(item) {
    var key = item.hash('hex');
    var old = this._broadcast.map[key];
    if (old)
      clearTimeout(old.timer);

    // Auto-cleanup broadcast map after timeout
    var entry = {
      timeout: setTimeout(function() {
        delete self._broadcast.map[key];
      }, this._broadcast.timout),
      value: item
    };

    this._broadcast.map[key] = entry;
  }, this);

  this._write(this.framer.inv(items));
};

Peer.prototype.watch = function watch(id) {
  this.bloom.add(id);
  this._write(this.framer.filterLoad(this.bloom, 'pubkeyOnly'));
};

Peer.prototype.loadBlocks = function loadBlocks() {
  if (this.loadingBlocks)
    return;
  this.loadingBlocks = true;
  this._write(this.framer.getBlocks([ constants.genesis ]));
};

Peer.prototype.destroy = function destroy() {
  if (this.destroyed)
    return;
  this.destroyed = true;
  this.socket.destroy();
  this.socket = null;

  // Clean-up timeouts
  Object.keys(this._broadcast.map).forEach(function(key) {
    clearTimeout(this._broadcast.map[key].timer);
  }, this);

  clearInterval(this._ping.timer);
  this._ping.timer = null;
};

// Private APIs

Peer.prototype._write = function write(chunk) {
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
      if (i !== -1)
        self.request.queue.splice(i, 1);
      cb(new Error('Timed out'), null);
    },
    timer: null
  };
  entry.timer = setTimeout(entry.ontimeout, this._request.timeout)
  this._request.queue.push(entry);
};

Peer.prototype._res = function _res(cmd, payload) {
  var entry = this._request.queue[0];
  if (!entry || entry.cmd && entry.cmd !== cmd)
    return;

  var res = entry.cb(null, payload, cmd);

  // If callback returns false - it hasn't finished processing responses
  if (res === false) {
    assert(!entry.cmd);

    // Restart timer
    entry.timer = setTimeout(entry.ontimeout, this._request.timeout)
  } else {
    this._request.queue.shift();
    clearTimeout(entry.timer);
    entry.timer = null;
  }
};

Peer.prototype._getData = function _getData(items, cb) {
  var map = {};
  var waiting = items.length;
  items.forEach(function(item) {
    map[utils.toHex(item.hash)] = {
      item: item,
      once: false,
      result: null
    };
  });

  var self = this;

  function markEntry(hash, result) {
    var entry = map[utils.toHex(hash)];
    if (!entry || entry.once) {
      done(new Error('Invalid notfound entry hash'));
      return false;
    }

    entry.once = true;
    entry.result = result;
    waiting--;
    return true;
  }

  this._write(this.framer.getData(items));
  // Process all incoming data, until all data is returned
  this._req(null, function(err, payload, cmd) {
    var ok = true;
    if (cmd === 'notfound') {
      ok = payload.every(function(item) {
        return markEntry(item.hash, null);
      });
    } else if (cmd === 'tx') {
      var tx = bcoin.tx(payload);
      ok = markEntry(tx.hash(), b);
    } else if (cmd === 'merkleblock') {
      var b = bcoin.block(payload);
      ok = markEntry(b.hash(), b);
    } else if (cmd === 'block') {
      var b = bcoin.block(payload);
      ok = markEntry(b.hash(), b);
    } else {
      done(new Error('Unknown packet in reply to getdata: ' + cmd));
      return;
    }
    if (!ok)
      return;

    if (waiting === 0)
      done();
    else
      return false;
  });

  function done(err) {
    if (err)
      return cb(err);

    cb(null, items.map(function(item) {
      return map[utils.toHex(item.hash)].result;
    }));
  }
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
  else
    return this._res(cmd, payload);
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

    var entry = this._broadcast.map[hash].value;
    this._write(entry.render(this.framer));
  }, this);
};

Peer.prototype._handleInv = function handleInv(items) {
  // Always request what advertised
  var req = items.filter(function(item) {
    return item.type === 'tx' || item.type === 'block';
  }).map(function(item) {
    if (item.type === 'tx')
      return item;
    if (item.type === 'block')
      return { type: 'filtered', hash: item.hash };
  });

  var self = this;
  this._getData(req, function(err, data) {
    if (err)
      return self._error(err);
    console.log(data.join(', '));
  });
};

Peer.prototype._handleMerkleBlock = function handleMerkleBlock(block) {
  console.log(utils.toHex(block.prevBlock));
};
