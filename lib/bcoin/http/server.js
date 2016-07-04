/*!
 * server.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var EventEmitter = require('events').EventEmitter;
var constants = bcoin.protocol.constants;
var http = require('./');
var HTTPBase = http.base;
var utils = require('../utils');
var assert = utils.assert;

/**
 * HTTPServer
 * @exports HTTPServer
 * @constructor
 * @param {Object} options
 * @param {Fullnode} options.node
 * @see HTTPBase
 * @emits HTTPServer#websocket
 */

function HTTPServer(options) {
  if (!(this instanceof HTTPServer))
    return new HTTPServer(options);

  if (!options)
    options = {};

  this.options = options;
  this.node = options.node;

  assert(this.node, 'HTTP requires a Node.');

  this.network = this.node.network;
  this.walletdb = this.node.walletdb;
  this.mempool = this.node.mempool;
  this.pool = this.node.pool;
  this.logger = options.logger || this.node.logger;
  this.loaded = false;

  options.sockets = true;

  this.server = new HTTPBase(options);

  this._init();
}

utils.inherits(HTTPServer, EventEmitter);

/**
 * Initialize routes.
 * @private
 */

HTTPServer.prototype._init = function _init() {
  var self = this;

  this.server.on('request', function(req, res) {
    self.logger.debug('Request from %s path=%s',
      req.socket.remoteAddress, req.pathname);
  });

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

    res.setHeader('X-Bcoin-Version', constants.USER_VERSION);
    res.setHeader('X-Bcoin-Agent', constants.USER_AGENT);
    res.setHeader('X-Bcoin-Network', self.network.type);
    res.setHeader('X-Bcoin-Height', self.node.chain.height + '');
    res.setHeader('X-Bcoin-Tip', utils.revHex(self.node.chain.tip.hash));

    next();
  });

  this.use(function(req, res, next, send) {
    var params = utils.merge({}, req.params, req.query, req.body);
    var options = {};

    self.logger.debug('Params:');
    self.logger.debug(params);

    if (params.id) {
      assert(params.id !== '!all');
      options.id = params.id;
    }

    if (params.hash) {
      if (params.hash.length !== 64)
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

    if (params.address) {
      params.addresses = params.address;
      options.address = params.address;
    }

    if (params.rate)
      options.rate = utils.satoshi(params.rate);

    if (params.subtractFee)
      options.subtractFee = params.subtractFee;

    if (Array.isArray(params.outputs)) {
      options.outputs = params.outputs.map(function(output) {
        return {
          address: output.address,
          script: decodeScript(output.script),
          value: utils.satoshi(output.value)
        };
      });
    }

    if (params.addresses) {
      if (typeof params.addresses === 'string')
        options.addresses = params.addresses.split(',');
      else
        options.addresses = params.addresses;
    }

    if (params.tx) {
      try {
        if (typeof params.tx === 'object')
          options.tx = bcoin.tx.fromJSON(params.tx);
        else
          options.tx = bcoin.tx.fromRaw(params.tx, 'hex');
      } catch (e) {
        return next(e);
      }
    }

    if (typeof params.account === 'string')
      options.account = params.account || null;
    else if (typeof params.account === 'number')
      options.account = params.account;

    if (params.name)
      options.name = params.name;

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

    req.options = options;

    next();
  });

  function decodeScript(script) {
    if (!script)
      return;
    if (typeof script === 'string')
      return new bcoin.script(new Buffer(script, 'hex'));
    return new bcoin.script(script);
  }

  this.get('/', function(req, res, next, send) {
    send(200, {
      version: constants.USER_VERSION,
      agent: constants.USER_AGENT,
      network: self.network.type,
      height: self.node.chain.height,
      tip: utils.revHex(self.node.chain.tip.hash),
      peers: self.node.pool.peers.all.length,
      progress: self.node.chain.getProgress()
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

      self.node.fillHistory(tx, function(err) {
        if (err)
          return next(err);

        send(200, tx.toJSON());
      });
    });
  });

  // TX by address
  this.get('/tx/address/:address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Bulk read TXs
  this.post('/tx/address', function(req, res, next, send) {
    self.node.getTXByAddress(req.options.addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
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

  // Mempool snapshot
  this.get('/mempool', function(req, res, next, send) {
    self.node.mempool.getHistory(function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.node.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Broadcast TX
  this.post('/broadcast', function(req, res, next, send) {
    self.node.sendTX(req.options.tx, function(err) {
      if (err)
        return next(err);

      send(200, {
        success: true
      });
    });
  });

  // Get wallet
  this.get('/wallet/:id', function(req, res, next, send) {
    self.walletdb.getInfo(req.options.id, function(err, wallet) {
      if (err)
        return next(err);

      if (!wallet)
        return send(404);

      send(200, wallet.toJSON());
    });
  });

  // Create/get wallet
  this.post('/wallet/:id?', function(req, res, next, send) {
    var json;
    self.walletdb.ensure(req.options, function(err, wallet) {
      if (err)
        return next(err);

      if (!wallet)
        return send(404);

      json = wallet.toJSON();
      wallet.destroy();

      send(200, json);
    });
  });

  // List accounts
  this.get('/wallet/:id/account', function(req, res, next, send) {
    self.walletdb.getAccounts(req.options.id, function(err, accounts) {
      if (err)
        return next(err);

      if (accounts.length === 0)
        return send(404);

      send(200, accounts);
    });
  });

  // Create/get account
  this.post('/wallet/:id/account/:account?', function(req, res, next, send) {
    var id = req.options.id;
    var options = req.options;
    options.name = options.account || options.name;
    self.walletdb.ensureAccount(id, options, function(err, account) {
      if (err)
        return next(err);

      if (!account)
        return send(404);

      send(200, account.toJSON());
    });
  });

  // Send TX
  this.post('/wallet/:id/send', function(req, res, next, send) {
    var id = req.options.id;
    var options = req.options;

    self.walletdb.createTX(id, options, function(err, tx) {
      if (err)
        return next(err);

      self.walletdb.sign(id, tx, options, function(err) {
        if (err)
          return next(err);

        self.node.sendTX(tx, function(err) {
          if (err)
            return next(err);

          send(200, tx.toJSON());
        });
      });
    });
  });

  // Create TX
  this.post('/wallet/:id/create', function(req, res, next, send) {
    var id = req.options.id;
    var options = req.options;

    self.walletdb.createTX(id, options, function(err, tx) {
      if (err)
        return next(err);

      self.walletdb.sign(id, tx, options, function(err) {
        if (err)
          return next(err);

        send(200, tx.toJSON());
      });
    });
  });

  // Sign TX
  this.post('/wallet/:id/sign', function(req, res, next, send) {
    var id = req.options.id;
    var options = req.options;
    var tx = req.options.tx;

    self.walletdb.sign(id, tx, options, function(err) {
      if (err)
        return next(err);

      send(200, tx.toJSON());
    });
  });

  // Fill TX
  this.post('/wallet/:id/fill', function(req, res, next, send) {
    var tx = req.options.tx;

    self.walletdb.fillHistory(tx, function(err) {
      if (err)
        return next(err);

      send(200, tx.toJSON());
    });
  });

  // Zap Wallet TXs
  this.post('/wallet/:id/zap', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    var age = req.options.age;

    self.walletdb.zap(id, account, age, function(err) {
      if (err)
        return next(err);

      send(200, {
        success: true
      });
    });
  });

  // Add key
  this.put('/wallet/:id/key', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    var keys = req.options.keys;
    self.walletdb.addKey(id, account, keys, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Remove key
  this.del('/wallet/:id/key', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    var keys = req.options.keys;
    self.walletdb.removeKey(id, account, keys, function(err) {
      if (err)
        return next(err);

      send(200, { success: true });
    });
  });

  // Create address
  this.post('/wallet/:id/address', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    self.walletdb.createAddress(id, account, false, function(err, address) {
      if (err)
        return next(err);

      send(200, address.toJSON());
    });
  });

  // Wallet Balance
  this.get('/wallet/:id/balance', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    self.walletdb.getBalance(id, account, function(err, balance) {
      if (err)
        return next(err);

      if (!balance)
        return send(404);

      send(200, {
        confirmed: utils.btc(balance.confirmed),
        unconfirmed: utils.btc(balance.unconfirmed),
        total: utils.btc(balance.total)
      });
    });
  });

  // Wallet UTXOs
  this.get('/wallet/:id/coin', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    self.walletdb.getCoins(id, account, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) {
        return coin.toJSON();
      }));
    });
  });

  // Wallet Coin
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
  this.get('/wallet/:id/tx/history', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    self.walletdb.getHistory(id, account, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.walletdb.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet Pending TXs
  this.get('/wallet/:id/tx/unconfirmed', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    self.walletdb.getUnconfirmed(id, account, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.walletdb.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/range', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    var options = req.options;
    self.walletdb.getRange(id, account, options, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.walletdb.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/last', function(req, res, next, send) {
    var id = req.options.id;
    var account = req.options.account;
    var limit = req.options.limit;
    self.walletdb.getRange(id, account, limit, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      utils.forEachSerial(txs, function(tx, next) {
        self.walletdb.fillHistory(tx, next);
      }, function(err) {
        if (err)
          return next(err);

        send(200, txs.map(function(tx) {
          return tx.toJSON();
        }));
      });
    });
  });

  // Wallet TX
  this.get('/wallet/:id/tx/:hash', function(req, res, next, send) {
    self.walletdb.getTX(req.options.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      self.walletdb.fillHistory(tx, function(err) {
        if (err)
          return next(err);
        send(200, tx.toJSON());
      });
    });
  });

  this.server.on('error', function(err) {
    self.emit('error', err);
  });

  this._initIO();
};

/**
 * Initialize websockets.
 * @private
 */

HTTPServer.prototype._initIO = function _initIO() {
  var self = this;

  if (!this.server.io)
    return;

  this.server.on('websocket', function(socket) {
    socket.on('error', function(err) {
      self.emit('error', err);
    });

    socket.on('join', function(id) {
      socket.join(id);
    });

    socket.on('leave', function(id) {
      socket.leave(id);
    });

    self.emit('websocket', socket);

    socket.emit('version', {
      version: constants.USER_AGENT,
      network: self.network.type
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
      unconfirmed: utils.btc(balance.unconfirmed),
      total: utils.btc(balance.total)
    };
    self.server.io.to(id).emit('balance', json);
    self.server.io.to('!all').emit('balance', json, id);
  });

  this.walletdb.on('balances', function(balances) {
    var json = {};
    Object.keys(balances).forEach(function(id) {
      json[id] = {
        confirmed: utils.btc(balances[id].confirmed),
        unconfirmed: utils.btc(balances[id].unconfirmed),
        total: utils.btc(balances[id].total)
      };
    });
    self.server.io.to('!all').emit('balances', json);
  });

  this.walletdb.on('address', function(receive, change, map) {
    if (receive) {
      receive = receive.map(function(address) {
        return address.toJSON();
      });
    }

    if (change) {
      change = change.map(function(address) {
        return address.toJSON();
      });
    }

    map.all.forEach(function(id) {
      self.server.io.to(id).emit('address', receive, change, map);
    });

    self.server.io.to('!all').emit('address', receive, change, map);
  });
};

/**
 * Open the server, wait for socket.
 * @param {Function} callback
 */

HTTPServer.prototype.open = function open(callback) {
  this.server.open(callback);
};

/**
 * Close the server, wait for server socket to close.
 * @param {Function} callback
 */

HTTPServer.prototype.close = function close(callback) {
  this.server.close(callback);
};

/**
 * @see HTTPBase#use
 */

HTTPServer.prototype.use = function use(path, callback) {
  return this.server.use(path, callback);
};

/**
 * @see HTTPBase#get
 */

HTTPServer.prototype.get = function get(path, callback) {
  return this.server.get(path, callback);
};

/**
 * @see HTTPBase#post
 */

HTTPServer.prototype.post = function post(path, callback) {
  return this.server.post(path, callback);
};

/**
 * @see HTTPBase#put
 */

HTTPServer.prototype.put = function put(path, callback) {
  return this.server.put(path, callback);
};

/**
 * @see HTTPBase#del
 */

HTTPServer.prototype.del = function del(path, callback) {
  return this.server.del(path, callback);
};

/**
 * @see HTTPBase#listen
 */

HTTPServer.prototype.listen = function listen(port, host, callback) {
  var self = this;
  return this.server.listen(port, host, function(err, address) {
    if (err) {
      if (callback)
        return callback(err);
      return self.emit('error', err);
    }

    self.logger.info('HTTP server listening on %s (port=%d).',
      address.address, address.port);

    self.loaded = true;
    self.emit('open');

    if (callback)
      callback();
  });
};

/*
 * Expose
 */

module.exports = HTTPServer;
