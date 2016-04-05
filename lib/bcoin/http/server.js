/**
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../../bcoin');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var HTTPServer = require('./http');
var utils = require('../utils');
var assert = utils.assert;

/**
 * NodeServer
 */

function NodeServer(options) {
  if (!options)
    options = {};

  this.options = options;
  this.node = options.node;

  assert(this.node, 'HTTP requires a Node.');

  this.walletdb = this.node.walletdb;
  this.pool = this.node.pool;
  this.loaded = false;

  this.server = new HTTPServer(options);
  this.io = null;

  this._init();
}

utils.inherits(NodeServer, EventEmitter);

NodeServer.prototype._init = function _init() {
  var self = this;

  this.use(function(req, res, next, send) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,HEAD,PUT,PATCH,POST,DELETE');

    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      return res.end();
    }

    res.setHeader('X-Bcoin-Network', network.type);
    res.setHeader('X-Bcoin-Version', constants.userAgent);

    next();
  });

  this.use(function(req, res, next, send) {
    var params = utils.merge({}, req.query, req.body, req.params);
    var options = {};

    if (params.id) {
      assert(params.id !== '!all');
      options.id = params.id;
    }

    if (params.hash) {
      if (utils.isInt(params.hash))
        options.height = params.hash >>> 0;
      else
        options.hash = utils.revHex(params.hash);
    }

    if (params.index != null)
      options.index = params.index >>> 0;

    if (params.height != null)
      options.height = params.height >>> 0;

    if (params.start != null)
      options.start = params.start >>> 0;

    if (params.end != null)
      options.end = params.end >>> 0;

    if (params.limit != null)
      options.limit = params.limit >>> 0;

    if (params.changeDepth)
      options.changeDepth = params.changeDepth >>> 0;

    if (params.receiveDepth)
      options.receiveDepth = params.receiveDepth >>> 0;

    if (params.address) {
      params.addresses = params.address;
      options.address = params.address;
    }

    if (params.value)
      options.value = utils.satoshi(params.value);

    if (params.addresses) {
      if (typeof params.addresses === 'string')
        options.addresses = params.addresses.split(',');
      else
        options.addresses = params.addresses;
    }

    if (params.tx) {
      try {
        options.tx = bcoin.tx.fromRaw(params.tx, 'hex');
      } catch (e) {
        return next(e);
      }
    }

    if (params.now)
      options.now = params.now >>> 0;

    if (params.age)
      options.age = params.age >>> 0;

    if (params.key)
      params.keys = params.key;

    if (params.keys) {
      if (typeof params.keys === 'string')
        options.keys = params.keys.split(',');
      else
        options.keys = params.keys;
    }

    if (params.passphrase)
      options.passphrase = params.passphrase;

    if (params.bin)
      options.bin = true;

    req.options = options;

    next();
  });

  this.get('/', function(req, res, next, send) {
    send(200, {
      version: constants.userAgent,
      network: network.type
    });
  });

  // UTXO by address
  this.get('/coin/address/:address', function(req, res, next, send) {
    self.node.getCoinsByAddress(req.options.addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // UTXO by id
  this.get('/coin/:hash/:index', function(req, res, next, send) {
    self.node.getCoin(req.options.hash, req.options.index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Bulk read UTXOs
  this.post('/coin/address', function(req, res, next, send) {
    self.node.getCoinsByAddress(req.options.addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // TX by hash
  this.get('/tx/:hash', function(req, res, next, send) {
    self.node.getTX(req.options.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      send(200, tx.toJSON());
    });
  });

  // TX by address
  this.get('/tx/address/:address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Bulk read TXs
  this.post('/tx/address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Block by hash/height
  this.get('/block/:hash', function(req, res, next, send) {
    var hash = req.options.hash || req.options.height;
    self.node.getFullBlock(hash, function(err, block) {
      if (err)
        return next(err);

      if (!block)
        return send(404);

      send(200, block.toJSON());
    });
  });

  // Get wallet
  this.get('/wallet/:id', function(req, res, next, send) {
    self.walletdb.getJSON(req.options.id, function(err, json) {
      if (err)
        return next(err);

      if (!json)
        return send(404);

      send(200, json);
    });
  });

  // Create/get wallet
  this.post(['/wallet', '/wallet/:id'], function(req, res, next, send) {
    self.walletdb.create(req.options, function(err, wallet) {
      var json;

      if (err)
        return next(err);

      if (!wallet)
        return send(404);

      json = wallet.toJSON();
      wallet.destroy();

      send(200, json);
    });
  });

  // Send TX
  this.post('/wallet/:id/send', function(req, res, next, send) {
    var id = req.options.id;
    var passphrase = req.options.passphrase;
    self.walletdb.get(id, passphrase, function(err, wallet) {
      if (err)
        return next(err);

      if (!wallet)
        return send(404);

      wallet.createTX({
        address: req.options.address,
        value: req.options.value
      }, function(err, tx) {
        wallet.destroy();

        if (err)
          return next(err);

        self.pool.sendTX(tx, function(err) {
          if (err)
            return next(err);

          send(200, tx.toJSON());
        });
      });
    });
  });

  // Zap Wallet TXs
  this.post('/wallet/:id/zap', function(req, res, next, send) {
    var id = req.options.id;
    var now = req.options.now;
    var age = req.options.age;

    self.walletdb.zapWallet(id, now, age, function(err, wallet) {
      if (err)
        return next(err);

      send(200, {
        success: true
      });
    });
  });

  // Update wallet / sync address depth
  this.put('/wallet/:id', function(req, res, next, send) {
    var id = req.options.id;
    var receive = req.options.receiveDepth;
    var change = req.options.changeDepth;

    self.walletdb.setDepth(id, receive, change, function(err) {
      if (err)
        return next(err);

      send(200, {
        success: true
      });
    });
  });

  // Add key
  this.put('/wallet/:id/key', function(req, res, next, send) {
    self.walletdb.addKey(req.options.id, req.options.keys, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Remove key
  this.del('/wallet/:id/key', function(req, res, next, send) {
    self.walletdb.removeKey(req.options.id, req.options.keys, function(err) {
      if (err)
        return next(err);

      if (!json)
        return send(404);

      send(200, { success: true });
    });
  });

  // Wallet Balance
  this.get('/wallet/:id/balance', function(req, res, next, send) {
    self.walletdb.getBalance(req.options.id, function(err, balance) {
      if (err)
        return next(err);

      if (!balance)
        return send(404);

      send(200, {
        confirmed: utils.btc(balance.confirmed),
        unconfirmed: utils.btc(balance.unconfirmed)
      });
    });
  });

  // Wallet UTXOs
  this.get('/wallet/:id/coin', function(req, res, next, send) {
    self.walletdb.getCoins(req.options.id, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // Wallet TX
  this.get('/wallet/:id/coin/:hash/:index', function(req, res, next, send) {
    var hash = req.options.hash;
    var index = req.options.index;
    self.walletdb.getCoin(hash, index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Wallet TXs
  this.get('/wallet/:id/tx/all', function(req, res, next, send) {
    self.walletdb.getAll(req.options.id, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Wallet Pending TXs
  this.get('/wallet/:id/tx/pending', function(req, res, next, send) {
    self.walletdb.getPending(req.options.id, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/range', function(req, res, next, send) {
    self.walletdb.getRange(req.options.id, req.options, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/last', function(req, res, next, send) {
    var id = req.options.id;
    var limit = req.options.limit;
    self.walletdb.getRange(id, limit, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  // Wallet TX
  this.get('/wallet/:id/tx/:hash', function(req, res, next, send) {
    self.walletdb.getTX(req.options.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      send(200, tx.toJSON());
    });
  });

  // Broadcast TX
  this.post('/broadcast', function(req, res, next, send) {
    self.pool.sendTX(tx, function(err) {
      if (err)
        return callback(err);

      send(200, {
        success: true
      });
    });
  });

  // Mempool snapshot
  this.get('/mempool', function(req, res, next, send) {
    self.node.mempool.getAll(function(err, txs) {
      if (err)
        return callback(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) {
        return tx.toJSON();
      }));
    });
  });

  this.server.on('error', function(err) {
    self.emit('error', err);
  });

  this._initIO();

  if (this.options.port != null)
    this.listen(this.options.port, this.options.host);
};

NodeServer.prototype.open = function open(callback) {
  if (this.loaded)
    return utils.nextTick(callback);

  this.once('open', callback);
};

NodeServer.prototype.close =
NodeServer.prototype.destroy = function destroy(callback) {
  this.server.close(callback);
};

NodeServer.prototype._initIO = function _initIO() {
  var self = this;

  if (!this.server.io)
    return;

  this.server.on('websocket', function(socket) {
    socket.on('error', function(err) {
      self.emit('error', err);
    });

    self.emit('websocket', socket);

    socket.emit('version', {
      version: constants.userAgent,
      network: network.type
    });
  });

  this.walletdb.on('tx', function(tx, map) {
    tx = tx.toJSON();
    map.all.forEach(function(id) {
      self.server.io.to(id).emit('tx', tx);
    });
    self.server.io.to('!all').emit('tx', tx, map);
  });

  this.walletdb.on('confirmed', function(tx, map) {
    tx = tx.toJSON();
    map.all.forEach(function(id) {
      self.server.io.to(id).emit('confirmed', tx);
    });
    self.server.io.to('!all').emit('confirmed', tx, map);
  });

  this.walletdb.on('updated', function(tx, map) {
    tx = tx.toJSON();
    map.all.forEach(function(id) {
      self.server.io.to(id).emit('updated', tx);
    });
    self.server.io.to('!all').emit('updated', tx, map);
  });

  this.walletdb.on('balance', function(balance, id) {
    var json = {
      confirmed: utils.btc(balance.confirmed),
      unconfirmed: utils.btc(balance.unconfirmed)
    };
    self.server.io.to(id).emit('balance', json);
    self.server.io.to('!all').emit('balance', json, id);
  });

  this.walletdb.on('balances', function(balances) {
    var json = {};
    Object.keys(balances).forEach(function(id) {
      json[id] = {
        confirmed: utils.btc(balances[id].confirmed),
        unconfirmed: utils.btc(balances[id].unconfirmed)
      };
    });
    self.server.io.to('!all').emit('balances', json);
  });
};

NodeServer.prototype.use = function use(path, callback) {
  return this.server.use(path, callback);
};

NodeServer.prototype.get = function get(path, callback) {
  return this.server.get(path, callback);
};

NodeServer.prototype.post = function post(path, callback) {
  return this.server.post(path, callback);
};

NodeServer.prototype.put = function put(path, callback) {
  return this.server.put(path, callback);
};

NodeServer.prototype.del = function del(path, callback) {
  return this.server.del(path, callback);
};

NodeServer.prototype.listen = function listen(port, host, callback) {
  var self = this;
  return this.server.listen(port, host, function(err) {
    if (err) {
      if (callback)
        return callback(err);
      return self.emit('error', err);
    }

    self.loaded = true;
    self.emit('open');

    if (callback)
      callback();
  });
};

/**
 * Expose
 */

module.exports = NodeServer;
