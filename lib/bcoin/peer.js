/**
 * peer.js - peer object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * Peer
 */

function Peer(pool, options) {
  if (!(this instanceof Peer))
    return new Peer(pool, options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.options = options;
  this.pool = pool;
  this.socket = null;
  this.host = null;
  this.port = 0;
  this._createSocket = this.options.createSocket;
  this.priority = this.options.priority;
  this.parser = new bcoin.protocol.parser();
  this.framer = new bcoin.protocol.framer();
  this.chain = this.pool.chain;
  this.bloom = this.pool.bloom;
  this.version = null;
  this.destroyed = false;
  this.ack = false;
  this.connected = false;
  this.ts = this.options.ts || 0;
  this.sendHeaders = false;
  this.haveWitness = false;

  this.challenge = null;
  this.lastPong = 0;

  this.banScore = 0;

  if (options.socket) {
    this.socket = options.socket;
    this.host = this.socket.remoteAddress;
    this.port = this.socket.remotePort;
    assert(this.host);
    assert(this.port != null);
  } else if (options.seed) {
    options.seed = utils.parseHost(options.seed);
    options.seed.port = options.seed.port || network.port;
    this.socket = this.createSocket(options.seed.port, options.seed.host);
  }

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

  this.queue = {
    block: [],
    tx: []
  };

  Peer.uid.iaddn(1);

  this.id = Peer.uid.toString(10);

  this.setMaxListeners(10000);

  this._init();
}

utils.inherits(Peer, EventEmitter);

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
    self.setMisbehavior(100);
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
    utils.debug(err.stack + '');
    self._error(err);
    // Something is wrong here.
    // Ignore this peer.
    self.setMisbehavior(100);
  });

  this.challenge = utils.nonce();

  this._ping.timer = setInterval(function() {
    if (self.options.witness && !self.haveWitness) {
      self._error('Peer does not support segregated witness.');
      self.setMisbehavior(100);
      return;
    }
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

    self._write(self.framer.packet('getaddr'));

    if (self.options.headers) {
      if (self.version && self.version.version > 70012)
        self._write(self.framer.packet('sendheaders'));
    }

    if (self.options.witness) {
      if (self.version && self.version.version >= 70012)
        self._write(self.framer.packet('havewitness'));
    }

    if (self.pool.chain.isFull())
      self.getMempool();
  });

  // Send hello
  this._write(this.framer.version({
    height: this.pool.chain.height,
    relay: this.options.relay
  }));
};

Peer.prototype.createSocket = function createSocket(port, host) {
  var self = this;
  var socket, net;

  assert(port != null);
  assert(host);

  this.host = host;
  this.port = port;

  if (this._createSocket) {
    socket = this._createSocket(port, host);
  } else if (bcoin.isBrowser) {
    throw new Error('Please include a `createSocket` callback.');
  } else {
    net = require('n' + 'et');
    socket = net.connect(port, host);
  }

  utils.debug(
    'Connecting to %s:%d (priority=%s)',
    host, port, this.priority);

  socket.on('connect', function() {
    utils.debug(
      'Connected to %s:%d (priority=%s)',
      host, port, self.priority);
  });

  return socket;
};

Peer.prototype.broadcast = function broadcast(items) {
  var self = this;
  var result = [];
  var payload = [];

  if (this.destroyed)
    return;

  if (!Array.isArray(items))
    items = [items];

  items.forEach(function(item) {
    var key = item.hash('hex');
    var old = this._broadcast.map[key];
    var type = item.type;
    var entry, packetType;

    if (old) {
      clearTimeout(old.timer);
      clearInterval(old.interval);
    }

    if (typeof type === 'string')
      type = constants.inv[type];

    // INV does not set the witness
    // mask (only GETDATA does this).
    type &= ~constants.invWitnessMask;

    if (type === constants.inv.block)
      packetType = 'block';
    else if (type === constants.inv.tx)
      packetType = 'tx';
    else if (type === constants.inv.filteredblock)
      packetType = 'merkleblock';
    else
      assert(false, 'Bad type.');

    // Auto-cleanup broadcast map after timeout
    entry = {
      e: new EventEmitter(),
      timeout: setTimeout(function() {
        entry.e.emit('timeout');
        clearInterval(entry.interval);
        delete self._broadcast.map[key];
      }, this._broadcast.timeout),

      // Retransmit
      interval: setInterval(function() {
        self._write(entry.inv);
      }, this._broadcast.interval),

      inv: this.framer.inv([{
        type: type,
        hash: item.hash()
      }]),

      packetType: packetType,
      type: type,
      hash: item.hash(),
      msg: item
    };

    this._broadcast.map[key] = entry;

    result.push(entry.e);

    payload.push({
      type: entry.type,
      hash: entry.hash
    });
  }, this);

  this._write(this.framer.inv(payload));

  return result;
};

Peer.prototype.updateWatch = function updateWatch() {
  if (!this.pool.options.spv)
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
  if (this.destroyed)
    return;

  this.socket.write(chunk);
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

  if (cmd === 'alert')
    return this._handleAlert(payload);

  if (cmd === 'block') {
    payload = bcoin.compactblock(payload);
  } else if (cmd === 'merkleblock') {
    payload = bcoin.merkleblock(payload);
    this.lastBlock = payload;
    return;
  } else if (cmd === 'tx') {
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

  if (cmd === 'sendheaders') {
    this.sendHeaders = true;
    return;
  }

  if (cmd === 'havewitness') {
    this.haveWitness = true;
    return;
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
  if (payload.version < constants.minVersion) {
    this._error('Peer doesn\'t support required protocol version.');
    this.setMisbehavior(100);
    return;
  }

  if (this.options.headers) {
    if (payload.version < 31800) {
      this._error('Peer doesn\'t support getheaders.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.network) {
    if (!payload.network) {
      this._error('Peer does not support network services.');
      this.setMisbehavior(100);
      return;
    }
  }

  if (this.options.spv) {
    if (!payload.bloom && payload.version < 70011) {
      this._error('Peer does not support bip37.');
      this.setMisbehavior(100);
      return;
    }
  }

  // if (this.options.witness) {
  //   if (!payload.witness) {
  //     this._error('Peer does not support segregated witness service.');
  //     this.setMisbehavior(100);
  //     return;
  //   }
  // }

  if (payload.witness)
    this.haveWitness = true;

  // ACK
  this._write(this.framer.verack());
  this.version = payload;
  this.emit('version', payload);
};

Peer.prototype._handleGetData = function handleGetData(items) {
  items.forEach(function(item) {
    // Filter out not broadcasted things
    var hash = utils.toHex(item.hash);
    var entry = this._broadcast.map[hash];
    var isWitness = item.type & constants.invWitnessMask;
    var value;

    if (!entry)
      return;

    if ((item.type & ~constants.invWitnessMask) !== entry.type) {
      utils.debug(
        'Peer %s requested an existing item with the wrong type.',
        this.host);
      return;
    }

    if (isWitness) {
      if (!entry.witnessValue)
        entry.witnessValue = entry.msg.renderWitness();
      value = entry.witnessValue;
    } else {
      if (!entry.value)
        entry.value = entry.msg.renderNormal();
      value = entry.value;
    }

    utils.debug(
      'Peer %s requested %s:%s as a %s packet.',
      this.host,
      entry.packetType,
      utils.revHex(utils.toHex(entry.hash)),
      isWitness ? 'witness' : 'normal');

    if (entry.value && entry.witnessValue)
      delete entry.msg;

    this._write(this.framer.packet(entry.packetType, value));

    entry.e.emit('request');
  }, this);
};

Peer.prototype._handleAddr = function handleAddr(addrs) {
  var now = utils.now();

  addrs.forEach(function(addr) {
    var ts = addr.ts;
    var host = addr.ipv4 !== '0.0.0.0'
      ? addr.ipv4
      : addr.ipv6;

    if (ts <= 100000000 || ts > now + 10 * 60)
      ts = now - 5 * 24 * 60 * 60;

    this.emit('addr', {
      ts: ts,
      services: addr.services,
      host: host,
      port: addr.port || network.port,
      network: addr.network,
      bloom: addr.bloom,
      getutxo: addr.getutxo,
      witness: addr.witness,
      headers: addr.version >= 31800,
      spv: addr.bloom && addr.version >= 70011
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
  var blocks = [];
  var txs = [];
  var item, i;

  this.emit('inv', items);

  for (i = 0; i < items.length; i++) {
    item = items[i];
    if (item.type === constants.inv.tx)
      txs.push(item.hash);
    else if (item.type === constants.inv.block)
      blocks.push(item.hash);
  }

  if (blocks.length > 0)
    this.emit('blocks', blocks);

  if (txs.length > 0)
    this.emit('txs', txs);
};

Peer.prototype._handleHeaders = function handleHeaders(headers) {
  headers = headers.map(function(header) {
    return new bcoin.headers(header);
  });

  this.emit('headers', headers);
};

Peer.prototype._handleReject = function handleReject(payload) {
  var hash, entry;

  this.emit('reject', payload);

  if (!payload.data)
    return;

  hash = utils.toHex(payload.data);
  entry = this._broadcast.map[hash];

  if (!entry)
    return;

  entry.e.emit('reject', payload);
};

Peer.prototype._handleAlert = function handleAlert(details) {
  var hash = utils.dsha256(details.payload);
  var signature = details.signature;

  if (!bcoin.ec.verify(hash, signature, network.alertKey)) {
    utils.debug('Peer %s sent a phony alert packet.', this.host);
    // Let's look at it because why not?
    utils.debug(details);
    this.setMisbehavior(100);
    return;
  }

  this.emit('alert', details);
};

Peer.prototype.getHeaders = function getHeaders(hashes, stop) {
  utils.debug(
    'Requesting headers packet from %s with getheaders',
    this.host);

  utils.debug('Height: %s, Hash: %s, Stop: %s',
    this.pool.chain.getHeight(hashes[0]),
    hashes ? utils.revHex(hashes[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this._write(this.framer.getHeaders(hashes, stop));
};

Peer.prototype.getBlocks = function getBlocks(hashes, stop) {
  utils.debug(
    'Requesting inv packet from %s with getblocks',
    this.host);

  utils.debug('Height: %s, Hash: %s, Stop: %s',
    this.pool.chain.getHeight(hashes[0]),
    hashes ? utils.revHex(hashes[0]) : 0,
    stop ? utils.revHex(stop) : 0);

  this._write(this.framer.getBlocks(hashes, stop));
};

Peer.prototype.getMempool = function getMempool() {
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

Peer.prototype.isMisbehaving = function isMisbehaving() {
  return this.pool.isMisbehaving(this.host);
};

Peer.prototype.setMisbehavior = function setMisbehavior(score) {
  return this.pool.setMisbehavior(this, score);
};

Peer.prototype.sendReject = function sendReject(obj, code, reason, score) {
  return this.pool.reject(this, obj, code, reason, score);
};

/**
 * Expose
 */

module.exports = Peer;
