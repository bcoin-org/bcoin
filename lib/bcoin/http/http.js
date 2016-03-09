/**
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var StringDecoder = require('string_decoder').StringDecoder;
var url = require('url');
var engine;

try {
  engine = require('engine.io');
} catch (e) {
  ;
}

var bcoin = require('../bcoin');
var bn = require('bn.js');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * HTTPServer
 */

function HTTPServer(node, options) {
  var self = this;

  if (!options)
    options = {};

  this.options = options;
  this.node = node;

  this.routes = {
    get: [],
    post: [],
    put: [],
    del: []
  };

  this.server = options.key
    ? require('https').createServer(options)
    : require('http').createServer();

  this._init();
}

utils.inherits(HTTPServer, EventEmitter);

HTTPServer.prototype._init = function _init() {
  var self = this;

  this._initRouter();
  this._initEngine();

  this.server.on('connection', function(socket) {
    socket.on('error', function(err) {
      try {
        socket.destroy();
      } catch (e) {
        ;
      }
    });
  });

  this.get('/', function(req, res, next, send) {
    send(200, {
      version: require('../../package.json').version,
      network: self.node.network.type
    });
  });

  // UTXO by address
  this.get('/coin/address/:address', function(req, res, next, send) {
    var addresses = req.params.address.split(',');
    self.node.getCoinByAddress(addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) { return coin.toJSON(); }));
    });
  });

  // UTXO by id
  this.get('/coin/:hash/:index', function(req, res, next, send) {
    req.params.hash = utils.revHex(req.params.hash);
    self.node.getCoin(req.params.hash, +req.params.index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Bulk read UTXOs
  this.post('/coin/address', function(req, res, next, send) {
    self.node.getCoinByAddress(req.body.addresses, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) { return coin.toJSON(); }));
    });
  });

  // TX by hash
  this.get('/tx/:hash', function(req, res, next, send) {
    req.params.hash = utils.revHex(req.params.hash);
    self.node.getTX(req.params.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      send(200, tx.toJSON());
    });
  });

  // TX by address
  this.get('/tx/address/:address', function(req, res, next, send) {
    var addresses = req.params.address.split(',');
    self.node.getTXByAddress(addresses, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Bulk read TXs
  this.post('/tx/address', function(req, res, next, send) {
    self.node.getTXByAddress(req.params.addresses, function(err, txs) {
      if (err)
        return next(err);
      if (!txs.length)
        return send(404);
      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Block by hash/height
  this.get('/block/:hash', function(req, res, next, send) {
    var hash = req.params.hash;

    if (utils.isInt(hash))
      hash = +hash;
    else
      hash = utils.revHex(hash);

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
    self.node.walletdb.getJSON(req.params.id, function(err, json) {
      if (err)
        return next(err);

      if (!json)
        return send(404);

      send(200, json);
    });
  });

  // Create/get wallet
  this.post('/wallet/:id', function(req, res, next, send) {
    req.body.id = req.params.id;
    self.node.walletdb.create(req.body, function(err, wallet) {
      var wallet;

      if (err)
        return next(err);

      if (!wallet)
        return send(404);

      json = wallet.toJSON();
      wallet.destroy();

      send(200, json);
    });
  });

  // Update wallet / sync address depth
  this.put('/wallet/:id', function(req, res, next, send) {
    var id = req.params.id;
    var receive = req.body.receiveDepth >>> 0;
    var change = req.body.changeDepth >>> 0;
    self.node.walletdb.setDepth(id, receive, change, function(err) {
      if (err)
        return next(err);

      if (!json)
        return send(404);

      send(200, { success: true });
    });
  });

  // Wallet Balance
  this.get('/wallet/:id/balance', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;
    self.node.walletdb.getBalance(req.params.id, function(err, balance) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, { balance: utils.btc(balance) });
    });
  });

  // Wallet UTXOs
  this.get('/wallet/:id/coin', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;
    self.node.walletdb.getCoins(req.params.id, function(err, coins) {
      if (err)
        return next(err);

      if (!coins.length)
        return send(404);

      send(200, coins.map(function(coin) { return coin.toJSON(); }));
    });
  });

  // Wallet TX
  this.get('/wallet/:id/coin/:hash/:index', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;
    self.node.walletdb.getCoin(req.params.hash, +req.params.index, function(err, coin) {
      if (err)
        return next(err);

      if (!coin)
        return send(404);

      send(200, coin.toJSON());
    });
  });

  // Wallet TXs
  this.get('/wallet/:id/tx/all', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;
    self.node.walletdb.getAll(req.params.id, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Wallet Pending TXs
  this.get('/wallet/:id/tx/pending', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;
    self.node.walletdb.getPending(req.params.id, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/range', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;

    var options = {
      start: +req.query.start,
      end: +req.query.end,
      limit: +req.query.limit
    };

    self.node.walletdb.getTimeRange(req.params.id, options, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Wallet TXs within time range
  this.get('/wallet/:id/tx/last', function(req, res, next, send) {
    var id = req.params.id;
    if (id === '_all')
      id = null;

    self.node.walletdb.getTimeRange(id, +req.query.limit, function(err, txs) {
      if (err)
        return next(err);

      if (!txs.length)
        return send(404);

      send(200, txs.map(function(tx) { return tx.toJSON(); }));
    });
  });

  // Wallet TX
  this.get('/wallet/:id/tx/:hash', function(req, res, next, send) {
    self.node.walletdb.getTX(req.params.hash, function(err, tx) {
      if (err)
        return next(err);

      if (!tx)
        return send(404);

      send(200, tx.toJSON());
    });
  });

  this.post('/broadcast', function(req, res, next, send) {
    self.node.pool.broadcast(bcoin.tx.fromRaw(req.body.tx, 'hex'));
    send(200, { success: true });
  });
};

HTTPServer.prototype._initEngine = function _initEngine() {
  var self = this;

  if (!engine)
    return;

  this.clients = [];

  this.engine = new engine.Server();

  this.engine.attach(this.server);

  this.engine.on('connection', function(socket) {
    var s = new Socket(self, socket);

    socket.on('message', function(data) {
      s.parse(data);
    });

    socket.on('close', function() {
      s.destroy();
    });

    socket.on('error', function(err) {
      self.emit('error', err);
    });

    s.on('error', function(err) {
      self.emit('error', err);
    });
  });
};

HTTPServer.prototype.listen = function listen(port, host, callback) {
  var self = this;
  this.server.listen(port, host, function(err) {
    var address;

    if (err)
      throw err;

    address = self.server.address();

    utils.debug('Listening - host=%s port=%d',
      address.address, address.port);

    if (callback)
      callback();
  });
};

HTTPServer.prototype._initRouter = function _initRouter() {
  var self = this;

  this.server.on('request', function(req, res) {
    function _send(code, msg) {
      send(res, code, msg);
    }

    function done(err) {
      if (err) {
        send(res, 400, { error: err.stack + '' });
        try {
          req.destroy();
          req.socket.destroy();
        } catch (e) {
          ;
        }
      }
    }

    try {
      parsePath(req);
    } catch (e) {
      done(e);
    }

    utils.debug('Request from %s path=%s',
      req.socket.remoteAddress, req.pathname);

    parseBody(req, function(err) {
      var method, routes, i;

      if (err)
        return done(err);

      method = (req.method || 'GET').toLowerCase();
      routes = self.routes[method];
      i = 0;

      if (!routes)
        return done(new Error('No routes found.'));

      (function next(err) {
        var route, path, callback, compiled, matched;

        if (err)
          return done(err);

        if (i === routes.length)
          return done(new Error('Route not found.'));

        route = routes[i++];
        path = route.path;
        callback = route.callback;

        if (!route.regex) {
          compiled = compilePath(path);
          route.regex = compiled.regex;
          route.map = compiled.map;
        }

        matched = route.regex.exec(req.pathname);

        if (!matched)
          return next();

        req.params = {};
        matched.slice(1).forEach(function(item, i) {
          if (route.map[i])
            req.params[route.map[i]] = item;
          req.params[i] = item;
        });

        // Avoid stack overflows
        utils.nextTick(function() {
          try {
            callback(req, res, next, _send);
          } catch (e) {
            done(e);
          }
        });
      })();
    });
  });
};

HTTPServer.prototype.get = function get(path, callback) {
  this.routes.get.push({ path: path, callback: callback });
};

HTTPServer.prototype.post = function post(path, callback) {
  this.routes.post.push({ path: path, callback: callback });
};

HTTPServer.prototype.put = function put(path, callback) {
  this.routes.put.push({ path: path, callback: callback });
};

HTTPServer.prototype.del = function del(path, callback) {
  this.routes.del.push({ path: path, callback: callback });
};

HTTPServer.prototype.sendWebhook = function sendWebhook(msg, callback) {
  var request, body, secret, hmac;

  callback = utils.ensure(callback);

  if (!this.options.webhook)
    return callback();

  try {
    request = require('request');
  } catch (e) {
    return callback(e);
  }

  body = new Buffer(JSON.stringify(msg) + '\n', 'utf8');
  secret = new Buffer(this.options.webhook.secret || '', 'utf8');
  hmac = utils.sha512hmac(body, secret);

  request({
    method: 'POST',
    uri: this.options.webhook.endpoint,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': body.length + '',
      'X-Bcoin-Hmac': hmac.toString('hex')
    },
    body: body
  }, function(err, res, body) {
    if (err)
      return callback(err);
    return callback();
  });
};

/**
 * Helpers
 */

function send(res, code, msg) {
  if (!msg)
    msg = { error: 'No message.' };

  try {
    res.statusCode = code;
    msg = JSON.stringify(msg, null, 2) + '\n';
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', Buffer.byteLength(msg) + '');
    res.write(msg);
    res.end();
  } catch (e) {
    utils.debug('Write failed: %s', e.message);
  }
}

function compilePath(path) {
  var map = [];

  if (path instanceof RegExp)
    return { regex: path, map: map };

  var regex = path
    .replace(/([^\/]+)\?/g, '(?:$1)?')
    .replace(/\.(?!\+)/g, '\\.')
    .replace(/\*/g, '.*?')
    .replace(/%/g, '\\')
    .replace(/:(\w+)/g, function(__, name) {
      map.push(name);
      return '([^/]+)';
    }
  );

  regex = new RegExp('^' + regex + '$');

  return {
    map: map,
    regex: regex
  };
}

function parseBody(req, callback) {
  var decode = new StringDecoder('utf8');
  var total = 0;
  var body = '';

  req.body = {};

  if (req.method === 'GET')
    return callback();

  req.on('data', function(data) {
    total += data.length;

    if (total > 20 * 1024 * 1024)
      return callback(new Error('Overflow.'));

    body += decode.write(data);
  });

  req.on('error', function(err) {
    try {
      req.destroy();
      req.socket.destroy();
    } catch (e) {
      ;
    }
    callback(err);
  });

  req.on('end', function() {
    try {
      if (body)
        req.body = JSON.parse(body);
    } catch (e) {
      return callback(e);
    }
    callback();
  });
}

function parsePairs(str, del, eq) {
  var out, s, i, parts;

  if (!str)
    return {};

  if (!del)
    del = '&';

  if (!eq)
    eq = '=';

  out = {};
  s = str.split(del);

  for (i = 0; i < s.length; i++) {
    parts = s[i].split(eq);
    if (parts[0]) {
      parts[0] = unescape(parts[0]);
      parts[1] = parts[1] ? unescape(parts[1]) : '';
      out[parts[0]] = parts[1];
    }
  }

  return out;
}

function parsePath(req) {
  var uri = url.parse(req.url);
  var pathname = uri.pathname || '/';

  if (pathname[pathname.length - 1] === '/')
    pathname = pathname.slice(0, -1);

  pathname = unescape(pathname);

  req.path = pathname;

  if (req.path[0] === '/')
    req.path = req.path.substring(1);

  req.path = req.path.split('/');

  if (!req.path[0])
    req.path = [];

  req.pathname = pathname || '/';

  if (req.url.indexOf('//') !== -1) {
    req.url = req.url.replace(/^([^:\/]+)?\/\/[^\/]+/, '');
    if (!req.url)
      req.url = '/';
  }

  if (!req.query) {
    req.query = uri.query
      ? parsePairs(uri.query, '&')
      : {};
  }
}

function escape(str) {
  return encodeURIComponent(str).replace(/%20/g, '+');
}

function unescape(str) {
  try {
    str = decodeURIComponent(str).replace(/\+/g, ' ');
  } finally {
    return str.replace(/\0/g, '');
  }
}

function Socket(server, socket) {
  this.server = server;
  this.engine = server.engine;
  this.node = server.node;
  this.walletdb = server.node.walletdb;
  this.socket = socket;
  this.listeners = {};
  this._init();
}

Socket.prototype._init = function _init() {
  this.server.clients.push(this);
};

Socket.prototype.parse = function parse(msg) {
  var size, off, header, payload;

  size = utils.readIntv(msg, 0);
  off = size.off;
  size = size.r;

  if (off + size > msg.length)
    return this.send({ event: 'error', msg: 'Size larger than message.' });

  try {
    header = JSON.parse(msg.slice(off, off + size).toString('utf8'));
    off += size;
  } catch (e) {
    return this.send({ event: 'error', msg: 'Header malformed.' });
  }

  payload = data.slice(off);

  try {
    return this._handle(header, payload);
  } catch (e) {
    return this.send({ event: 'error', msg: e.message + '' });
  }
};

Socket.prototype._handle = function _handle(header, payload) {
  if (header.cmd === 'handshake')
    return this._handleHandshake(header, payload);

  if (header.cmd === 'listen')
    return this._handleListen(header, payload);

  if (header.cmd === 'unlisten')
    return this._handleUnlisten(header, payload);

  if (header.event)
    return this.emit(header.event, header, payload);

  throw new Error('Not a valid command.');
};

Socket.prototype.destroy = function destroy() {
  this.remove();
  this.cleanup();
  return this.clients.destroy();
};

Socket.prototype.remove = function remove() {
  var i = this.server.clients.indexOf(this);
  if (i !== -1)
    this.server.clients.splice(i, 1);
};

Socket.prototype.cleanup = function cleanup() {
  Object.keys(this.listeners).forEach(function(id) {
    this.unlistenWallet(id);
  }, this);
};

Socket.prototype.unlistenWallet = function unlistenWallet(id) {
  this.listeners[id].forEach(function(listener) {
    this.walletdb.removeListener(listener[0], listener[1]);
  }, this);

  delete this.listeners[id];
};

Socket.prototype._listenWallet = function _listenWallet(id, event, listener) {
  if (!this.listeners[id])
    this.listeners[id] = [];

  this.listeners[id].push([event, listener]);
  this.walletdb.on(event, listener);
};

Socket.prototype.listenWallet = function listenWallet(event, id, listener) {
  if (id === '_all') {
    this._listenWallet(id, 'tx', function(tx, map) {
      self.send({ event: 'tx', map: map, id: id, _payload: tx.toExtended() });
    });

    this._listenWallet(id, 'updated', function(tx, map) {
      self.send({ event: 'updated', map: map, id: id, _payload: tx.toExtended() });
    });

    this._listenWallet(id, 'confirmed', function(tx, map) {
      self.send({ event: 'confirmed', map: map, id: id, _payload: tx.toExtended() });
    });

    this._listenWallet(id, 'unconfirmed', function(tx, map) {
      self.send({ event: 'unconfirmed', map: map, id: id, _payload: tx.toExtended() });
    });

    this._listenWallet(id, 'balances', function(balances) {
      Object.keys(balances).forEach(function(key) {
        balances[key] = utils.btc(balances[key]);
      });
      self.send({ event: 'balances', id: id, balances: balances });
    });

    return;
  }

  this._listenWallet(id, id + ' tx', function(tx) {
    self.send({ event: 'tx', id: id, _payload: tx.toExtended() });
  });

  this._listenWallet(id, id + ' updated', function(tx) {
    self.send({ event: 'updated', id: id, _payload: tx.toExtended() });
  });

  this._listenWallet(id, id + ' confirmed', function(tx) {
    self.send({ event: 'confirmed', id: id, _payload: tx.toExtended() });
  });

  this._listenWallet(id, id + ' unconfirmed', function(tx) {
    self.send({ event: 'unconfirmed', id: id, _payload: tx.toExtended() });
  });

  this._listenWallet(id, id + ' balance', function(balance) {
    self.send({ event: 'balance', id: id, balance: utils.btc(balance) });
  });
};

Socket.prototype._onListen = function _onListen(header, payload) {
  var self = this;
  var id = header.id;

  if (typeof id !== 'string')
    throw new Error('Wallet ID is not a string.');

  if (id.length > 1000)
    throw new Error('Wallet ID too large.');

  if (!/^[a-zA-Z0-9]+$/.test(id))
    throw new Error('Wallet ID must be alphanumeric.');

  if (this.listeners[id])
    throw new Error('Already listening.');

  this.listenWallet(id);
};

Socket.prototype._onUnlisten = function _onUnlisten(header, payload) {
  var self = this;
  var id = header.id;

  if (typeof id !== 'string')
    throw new Error('Wallet ID is not a string.');

  if (id.length > 1000)
    throw new Error('Wallet ID too large.');

  if (!/^[a-zA-Z0-9]+$/.test(id))
    throw new Error('Wallet ID must be alphanumeric.');

  if (!this.listeners[id])
    throw new Error('Not listening.');

  this.unlistenWallet(id);
};

Socket.prototype._handleHandshake = function _handleHandshake(header, payload) {
  if (this._activated)
    throw new Error('Handshake already completed.');

  if (payload.length > 0)
    throw new Error('Unexpected payload.');

  this._activated = true;
};

Socket.prototype.send = function send(data) {
  var header, payload, size, msg;

  if (data._payload) {
    payload = data._payload;
    delete data._payload;
  } else {
    payload = new Buffer([]);
  }

  assert(Buffer.isBuffer(payload));

  header = new Buffer(JSON.stringify(data), 'utf8');

  size = new Buffer(utils.sizeIntv(header.length));
  utils.writeIntv(size, header.length, 0);

  msg = Buffer.concat([size, header, payload]);

  return this.socket.send(msg);
};

/**
 * Expose
 */

module.exports = HTTPServer;
