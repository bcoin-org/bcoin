/**
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Peer
 */

function Peer(pool, createConnection, options) {
  var self = this;

  if (!(this instanceof Peer))
    return new Peer(pool, createConnection, options);

  EventEmitter.call(this);

  this.options = options || {};
  this.pool = pool;
  this.socket = null;
  this.parser = new bcoin.protocol.parser();
  this.framer = new bcoin.protocol.framer();
  this.chain = this.pool.chain;
  this.bloom = this.pool.bloom;
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = this.options.ts || 0;

  this.host = null;
  this.port = 0;

  this.challenge = null;
  this.lastPong = 0;

  this.banScore = 0;
  this.orphans = 0;
  this.orphanTime = 0;

  this.socket = createConnection.call(pool, this, options);
  if (!this.socket)
    throw new Error('No socket');

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

  this._queue = [];

  Peer.uid.iaddn(1);

  this.id = Peer.uid.toString(10);

  this.setMaxListeners(10000);

  this._init();
}

inherits(Peer, EventEmitter);

Peer.uid = new bn(0);

Peer.prototype._init = function init() {
  var self = this;

  if (!this.host)
    this.host = this.socket.remoteAddress || this.socket._host || null;

  if (!this.port)
    this.port = this.socket.remotePort || 0;

  this.socket.once('connect', function() {
    self.ts = utils.now();
    self.connected = true;
    if (!self.host)
      self.host = self.socket.remoteAddress;
    if (!self.port)
      self.port = self.socket.remotePort;
    self.emit('connect');
  });

  this.socket.once('error', function(err) {
    self._error(err);
    self.pool.setMisbehavior(self, 100);
  });

  this.socket.once('close', function() {
    self._error('socket hangup');
    self.connected = false;
  });

  this.socket.on('data', function(chunk) {
    self.parser.feed(chunk);
  });

  this.parser.on('packet', function(packet) {
    self._onPacket(packet);
  });

  this.parser.on('error', function(err) {
    self._error(err);
    // Something is wrong here.
    // Ignore this peer.
    self.pool.setMisbehavior(self, 100);
  });

  if (this.pool.options.fullNode) {
    this.once('version', function() {
      utils.debug(
        'Sent version (%s): height=%s',
        self.host, this.pool.chain.height());
    });
  }

  this._ping.timer = setInterval(function() {
    self.challenge = utils.nonce();
    self._write(self.framer.ping({
      nonce: self.challenge
    }));
  }, this._ping.interval);

  this._req('verack', function(err, payload) {
    if (err) {
      self._error(err);
      self.destroy();
      return;
    }
    self.ack = true;
    self.emit('ack');
    self.ts = utils.now();
    self._write(self.framer.packet('getaddr', []));
    // if (self.pool.options.headers) {
    //   if (self.version && self.version.v > 70012)
    //     self._write(self.framer.packet('sendheaders', []));
    // }
  });

  // Send hello
  this._write(this.framer.version({
    height: this.pool.chain.height(),
    relay: this.options.relay
  }));
};

Peer.prototype.broadcast = function broadcast(items) {
  var self = this;
  var result;

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [ items ];

  result = items.map(function(item) {
    var key = item.hash('hex');
    var old = this._broadcast.map[key];
    if (old) {
      clearTimeout(old.timer);
      clearInterval(old.interval);
    }

    var inv =  this.framer.inv([{
      type: item.type,
      hash: item.hash()
    }]);

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
  if (this.pool.options.fullNode)
    return;

  if (this.ack)
    this._write(this.framer.filterLoad(this.bloom, 'none'));
};

Peer.prototype.destroy = function destroy() {
  var i;

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

  for (i = 0; i < this._request.queue.length; i++)
    clearTimeout(this._request.queue[i].timer);
};

Peer.prototype._write = function write(chunk) {
  var self = this;

  if (this.destroyed)
    return;

  this.socket.write(new Buffer(chunk));
};

Peer.prototype._error = function error(err) {
  if (this.destroyed)
    return;

  if (typeof err === 'string')
    err = new Error(err);

  err.message += ' (' + this.host + ')';

  this.destroy();
  this.emit('error', err);
};

Peer.prototype._req = function _req(cmd, cb) {
  var self = this;

  if (this.destroyed)
    return cb(new Error('Destroyed, sorry'));

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

  entry.timer = setTimeout(entry.ontimeout, this._request.timeout);

  this._request.queue.push(entry);

  return entry;
};

Peer.prototype._res = function _res(cmd, payload) {
  var i, entry, res;

  for (i = 0; i < this._request.queue.length; i++) {
    entry = this._request.queue[i];

    if (!entry || (entry.cmd && entry.cmd !== cmd))
      return false;

    res = entry.cb(null, payload, cmd);

    if (res === this._request.cont) {
      assert(!entry.cmd);

      // Restart timer
      if (!this.destroyed)
        entry.timer = setTimeout(entry.ontimeout, this._request.timeout);
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

  if (this.lastBlock && cmd !== 'tx')
    this._emitMerkle(this.lastBlock);

  if (cmd === 'version')
    return this._handleVersion(payload);

  if (cmd === 'inv')
    return this._handleInv(payload);

  if (cmd === 'headers')
    return this._handleHeaders(payload);

  if (cmd === 'getdata')
    return this._handleGetData(payload);

  if (cmd === 'addr')
    return this._handleAddr(payload);

  if (cmd === 'ping')
    return this._handlePing(payload);

  if (cmd === 'pong')
    return this._handlePong(payload);

  if (cmd === 'getaddr')
    return this._handleGetAddr();

  if (cmd === 'reject')
    return this._handleReject(payload);

  if (cmd === 'block') {
    payload.network = true;
    payload.relayedBy = this.host || '0.0.0.0';
    payload = bcoin.block(payload, 'block');
  } else if (cmd === 'merkleblock') {
    payload.network = true;
    payload.relayedBy = this.host || '0.0.0.0';
    payload = bcoin.block(payload, 'merkleblock');
    this.lastBlock = payload;
    return;
  } else if (cmd === 'tx') {
    payload.network = true;
    payload.relayedBy = this.host || '0.0.0.0';
    payload = bcoin.tx(payload, this.lastBlock);
    if (this.lastBlock) {
      if (payload.block) {
        this.lastBlock.txs.push(payload);
        return;
      } else {
        this._emitMerkle(this.lastBlock);
      }
    }
  }

  if (this._res(cmd, payload))
    return;

  this.emit(cmd, payload);
};

Peer.prototype._emitMerkle = function _emitMerkle(payload) {
  if (!this._res('merkleblock', payload))
    this.emit('merkleblock', payload);
  this.lastBlock = null;
};

Peer.prototype._handleVersion = function handleVersion(payload) {
  if (payload.v < constants.minVersion)
    return this._error('peer doesn\'t support required protocol version');

  // ACK
  this._write(this.framer.verack());
  this.version = payload;
  this.emit('version', payload);
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

Peer.prototype._handleAddr = function handleAddr(addrs) {
  var now = utils.now();

  addrs.forEach(function(addr) {
    var ip, address4, address6;

    if (addr.ts <= 100000000 || addr.ts > now + 10 * 60)
      addr.ts = now - 5 * 24 * 60 * 60;

    ip = addr.ipv4 !== '0.0.0.0'
      ? addr.ipv4
      : addr.ipv6;

    address4 = addr.ipv4 !== '0.0.0.0'
      ? addr.ipv4 + ':' + addr.port
      : null;

    address6 = '[' + addr.ipv6 + ']:' + addr.port;

    this.emit('addr', {
      date: new Date(addr.ts * 1000),
      ts: addr.ts,
      services: addr.services,
      ip: ip,
      ipv4: addr.ipv4,
      ipv6: addr.ipv6,
      host: ip,
      host4: addr.ipv4,
      host6: addr.ipv6,
      port: addr.port || network.port,
      address: address4 || address6,
      address4: address4,
      address6: address6
    });
  }, this);

  utils.debug(
    'Recieved %d peers (seeds=%d, peers=%d).',
    addrs.length,
    this.pool.seeds.length,
    this.pool.peers.all.length);
};

Peer.prototype._handlePing = function handlePing(data) {
  this._write(this.framer.pong({
    nonce: data.nonce
  }));
  this.emit('ping', data);
};

Peer.prototype._handlePong = function handlePong(data) {
  if (!this.challenge || this.challenge.cmp(data.nonce) !== 0)
    return this.emit('pong', false);

  this.lastPong = utils.now();

  return this.emit('pong', true);
};

Peer.prototype._handleGetAddr = function handleGetAddr() {
  var hosts = {};
  var peers;

  peers = this.pool.peers.all.map(function(peer) {
    var ip, version;

    if (!peer.socket || !peer.socket.remoteAddress)
      return;

    ip = peer.socket.remoteAddress;
    version = utils.isIP(ip);

    if (!version)
      return;

    if (hosts[ip])
      return;

    hosts[ip] = true;

    return {
      ts: peer.ts,
      services: peer.version ? peer.version.services : null,
      ipv4: version === 4 ? ip : null,
      ipv6: version === 6 ? ip : null,
      port: peer.socket.remotePort || network.port
    };
  }).filter(Boolean);

  return this._write(this.framer.addr(peers));
};

Peer.prototype._handleInv = function handleInv(items) {
  var req, i, block, hash;

  this.emit('inv', items);

  // Always request advertised TXs
  var txs = items.filter(function(item) {
    return item.type === 'tx';
  });

  // Emit new blocks to schedule them between multiple peers
  var blocks = items.filter(function(item) {
    return item.type === 'block';
  }, this).map(function(item) {
    return item.hash;
  });

  if (blocks.length === 1)
    this.bestHash = utils.toHex(blocks[0]);

  this.emit('blocks', blocks);

  if (txs.length === 0)
    return;

  this.emit('txs', txs.map(function(tx) {
    return tx.hash;
  }));

  this.getData(txs);
};

Peer.prototype._handleHeaders = function handleHeaders(headers) {
  var self = this;

  headers = headers.map(function(header) {
    header.prevBlock = utils.toHex(header.prevBlock);
    header.merkleRoot = utils.toHex(header.merkleRoot);
    header.hash = utils.toHex(utils.dsha256(header._raw));
    return header;
  });

  this.emit('headers', headers);
};

Peer.prototype._handleReject = function handleReject(payload) {
  var hash = utils.toHex(payload.data);
  var entry = this._broadcast.map[hash];

  this.emit('reject', payload);

  if (!entry)
    return;

  entry.e.emit('reject', payload);
};

Peer.prototype.loadHeaders = function loadHeaders(hashes, stop) {
  utils.debug(
    'Requesting headers packet from %s with getheaders',
    this.host);
  utils.debug('Height: %s, Hash: %s, Stop: %s',
    this.pool.chain.getHeight(hashes[0]),
    hashes ? utils.revHex(hashes[0]) : 0,
    stop ? utils.revHex(stop) : 0);
  this._write(this.framer.getHeaders(hashes, stop));
};

Peer.prototype.loadBlocks = function loadBlocks(hashes, stop) {
  utils.debug(
    'Requesting inv packet from %s with getblocks',
    this.host);
  utils.debug('Height: %s, Hash: %s, Stop: %s',
    this.pool.chain.getHeight(hashes[0]),
    hashes ? utils.revHex(hashes[0]) : 0,
    stop ? utils.revHex(stop) : 0);
  this._write(this.framer.getBlocks(hashes, stop));
};

Peer.prototype.loadItems = function loadItems(hashes, stop) {
  if (this.pool.options.headers)
    return this.loadHeaders(hashes, stop);
  return this.loadBlocks(hashes, stop);
};

Peer.prototype.loadMempool = function loadMempool() {
  utils.debug(
    'Requesting inv packet from %s with mempool',
    this.host);
  this._write(this.framer.mempool());
};

Peer.prototype.reject = function reject(details) {
  utils.debug(
    'Sending reject packet to %s',
    this.host);

  this._write(this.framer.reject(details));
};

/**
 * Expose
 */

module.exports = Peer;
