/*!
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var AsyncObject = require('../utils/async');
var util = require('../utils/util');
var URL = require('url');
var co = require('../utils/co');

/**
 * HTTPBase
 * @exports HTTPBase
 * @constructor
 * @param {Object?} options
 * @emits HTTPBase#websocket
 */

function HTTPBase(options) {
  if (!(this instanceof HTTPBase))
    return new HTTPBase(options);

  if (!options)
    options = {};

  AsyncObject.call(this);

  this.options = options;
  this.io = null;

  this.routes = new Routes();
  this.stack = [];

  this.keyLimit = 100;
  this.bodyLimit = 20 << 20;

  this.server = options.key
    ? require('https').createServer(options)
    : require('http').createServer();

  this._init();
}

util.inherits(HTTPBase, AsyncObject);

/**
 * Initialize server.
 * @private
 */

HTTPBase.prototype._init = function _init() {
  var self = this;

  this._initRouter();
  this._initIO();

  this.server.on('connection', function(socket) {
    socket.on('error', function(err) {
      var str;

      if (err.message === 'Parse Error') {
        str = 'http_parser.execute failure (';
        str += 'parsed=' + (err.bytesParsed || -1);
        str += ' code=' + err.code;
        str += ')';
        err = new Error(str);
      }

      self.emit('error', err);

      try {
        socket.destroy();
      } catch (e) {
        ;
      }
    });
  });

  this.server.on('error', function(err) {
    self.emit('error', err);
  });
};

/**
 * Initialize router.
 * @private
 */

HTTPBase.prototype._initRouter = function _initRouter() {
  var self = this;
  this.server.on('request', co(function* (req, res) {
    try {
      yield self.handleRequest(req, res);
    } catch (e) {
      if (!res.sent)
        res.error(e);

      self.emit('error', e);
    }
  }));
};

/**
 * Handle a request.
 * @private
 * @param {ServerRequest} req
 * @param {ServerResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleRequest = co(function* handleRequest(req, res) {
  var i, routes, route, params;

  initRequest(req, res, this.keyLimit);

  this.emit('request', req, res);

  req.body = yield this.parseBody(req);

  routes = this.routes.getHandlers(req.method);

  if (!routes)
    throw new Error('No routes found for method: ' + req.method);

  for (i = 0; i < routes.length; i++) {
    route = routes[i];
    params = route.match(req.pathname);

    if (!params)
      continue;

    req.params = params;

    if (yield this.handleStack(req, res))
      return;

    if (yield route.call(req, res))
      return;
  }

  throw new Error('No routes found for path: ' + req.pathname);
});

/**
 * Parse request body.
 * @private
 * @param {ServerRequest} req
 * @returns {Promise}
 */

HTTPBase.prototype.parseBody = co(function* parseBody(req) {
  var body = Object.create(null);
  var data;

  if (req.method === 'GET')
    return body;

  data = yield this.readBody(req, 'utf8');

  if (!data)
    return body;

  switch (req.contentType) {
    case 'json':
      body = JSON.parse(data);
      break;
    case 'form':
      body = parsePairs(data, this.keyLimit);
      break;
    default:
      break;
  }

  return body;
});

/**
 * Handle middleware stack.
 * @private
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @returns {Promise}
 */

HTTPBase.prototype.handleStack = co(function* handleStack(req, res) {
  var i, route;

  for (i = 0; i < this.stack.length; i++) {
    route = this.stack[i];

    if (!route.hasPrefix(req.pathname))
      continue;

    if (yield route.call(req, res))
      return true;
  }

  return false;
});

/**
 * Read and buffer request body.
 * @param {ServerRequest} req
 * @param {String} enc
 * @returns {Promise}
 */

HTTPBase.prototype.readBody = function readBody(req, enc) {
  var self = this;
  return new Promise(function(resolve, reject) {
    return self._readBody(req, enc, resolve, reject);
  });
};

/**
 * Read and buffer request body.
 * @private
 * @param {ServerRequest} req
 * @param {String} enc
 * @param {Function} resolve
 * @param {Function} reject
 */

HTTPBase.prototype._readBody = function _readBody(req, enc, resolve, reject) {
  var self = this;
  var StringDecoder = require('string_decoder').StringDecoder;
  var decode = new StringDecoder(enc);
  var hasData = false;
  var total = 0;
  var body = '';
  var timer;

  timer = setTimeout(function() {
    timer = null;
    cleanup();
    reject(new Error('Request body timed out.'));
  }, 10 * 1000);

  function cleanup() {
    req.removeListener('data', onData);
    req.removeListener('error', onError);
    req.removeListener('end', onEnd);

    if (timer != null)
      clearTimeout(timer);
  }

  function onData(data) {
    total += data.length;
    hasData = true;

    if (total > self.bodyLimit) {
      reject(new Error('Request body overflow.'));
      return;
    }

    body += decode.write(data);
  }

  function onError(err) {
    cleanup();
    reject(err);
  }

  function onEnd() {
    cleanup();

    if (hasData) {
      resolve(body);
      return;
    }

    resolve(null);
  }

  req.on('data', onData);
  req.on('error', onError);
  req.on('end', onEnd);
};

/**
 * Initialize websockets.
 * @private
 */

HTTPBase.prototype._initIO = function _initIO() {
  var self = this;
  var IOServer;

  if (!this.options.sockets)
    return;

  try {
    IOServer = require('socket.io');
  } catch (e) {
    ;
  }

  if (!IOServer)
    return;

  this.io = new IOServer({
    transports: ['websocket']
  });

  this.io.attach(this.server);

  this.io.on('connection', function(socket) {
    self.emit('websocket', socket);
  });
};

/**
 * Open the server.
 * @alias HTTPBase#open
 * @returns {Promise}
 */

HTTPBase.prototype._open = function open() {
  assert(typeof this.options.port === 'number', 'Port required.');
  return this.listen(this.options.port, this.options.host);
};

/**
 * Close the server.
 * @alias HTTPBase#close
 * @returns {Promise}
 */

HTTPBase.prototype._close = function close() {
  var self = this;

  return new Promise(function(resolve, reject) {
    if (self.io) {
      self.server.once('close', resolve);
      self.io.close();
      return;
    }

    self.server.close(function(err) {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
};

/**
 * Add a middleware to the stack.
 * @param {String?} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.use = function use(path, handler, ctx) {
  if (!handler) {
    handler = path;
    path = null;
  }
  this.stack.push(new Route(ctx, path, handler));
};

/**
 * Add a GET route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.get = function get(path, handler, ctx) {
  this.routes.get.push(new Route(ctx, path, handler));
};

/**
 * Add a POST route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.post = function post(path, handler, ctx) {
  this.routes.post.push(new Route(ctx, path, handler));
};

/**
 * Add a PUT route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.put = function put(path, handler, ctx) {
  this.routes.put.push(new Route(ctx, path, handler));
};

/**
 * Add a DELETE route.
 * @param {String} path
 * @param {Function} handler
 * @param {Object?} ctx
 */

HTTPBase.prototype.del = function del(path, handler, ctx) {
  this.routes.del.push(new Route(ctx, path, handler));
};

/**
 * Get server address.
 * @returns {Object}
 */

HTTPBase.prototype.address = function address() {
  return this.server.address();
};

/**
 * Listen on port and host.
 * @param {Number} port
 * @param {String} host
 * @returns {Promise}
 */

HTTPBase.prototype.listen = function listen(port, host) {
  var self = this;
  return new Promise(function(resolve, reject) {
    var addr;

    self.server.listen(port, host, function(err) {
      if (err)
        return reject(err);

      addr = self.address();

      self.emit('listening', addr);

      resolve(addr);
    });
  });
};

/**
 * Route
 * @constructor
 */

function Route(ctx, path, handler) {
  if (!(this instanceof Route))
    return new Route(ctx, path, handler);

  this.ctx = null;
  this.path = null;
  this.handler = null;

  this.regex = /^/;
  this.map = [];
  this.compiled = false;

  if (ctx) {
    assert(typeof ctx === 'object');
    this.ctx = ctx;
  }

  if (path) {
    if (path instanceof RegExp) {
      this.regex = path;
    } else {
      assert(typeof path === 'string');
      assert(path.length > 0);
      this.path = path;
    }
  }

  assert(typeof handler === 'function');
  this.handler = handler;
}

Route.prototype.compile = function compile() {
  var path = this.path;
  var map = this.map;

  if (this.compiled)
    return;

  this.compiled = true;

  if (!path)
    return;

  path = path.replace(/(\/[^\/]+)\?/g, '(?:$1)?');
  path = path.replace(/\.(?!\+)/g, '\\.');
  path = path.replace(/\*/g, '.*?');
  path = path.replace(/%/g, '\\');

  path = path.replace(/:(\w+)/g, function(str, name) {
    map.push(name);
    return '([^/]+)';
  });

  this.regex = new RegExp('^' + path + '$');
};

Route.prototype.match = function match(pathname) {
  var i, match, item, params, key;

  this.compile();

  assert(this.regex);

  match = this.regex.exec(pathname);

  if (!match)
    return;

  params = Object.create(null);

  for (i = 1; i < match.length; i++) {
    item = match[i];
    key = this.map[i - 1];

    if (key)
      params[key] = item;

    params[i] = item;
  }

  return params;
};

Route.prototype.hasPrefix = function hasPrefix(pathname) {
  if (!this.path)
    return true;

  return pathname.indexOf(this.path) === 0;
};

Route.prototype.call = co(function* call(req, res) {
  yield this.handler.call(this.ctx, req, res);
  return res.sent;
});

/**
 * Routes
 * @constructor
 */

function Routes() {
  if (!(this instanceof Routes))
    return new Routes();

  this.get = [];
  this.post = [];
  this.put = [];
  this.del = [];
}

Routes.prototype.getHandlers = function getHandlers(method) {
  if (!method)
    return;

  method = method.toUpperCase();

  switch (method) {
    case 'GET':
      return this.get;
    case 'POST':
      return this.post;
    case 'PUT':
      return this.put;
    case 'DEL':
      return this.del;
    default:
      return;
  }
};

/*
 * Helpers
 */

function nop() {}

function initRequest(req, res, limit) {
  req.on('error', nop);

  assert(req.contentType == null);
  assert(req.pathname == null);
  assert(req.path == null);
  assert(req.query == null);
  assert(req.params == null);
  assert(req.body == null);

  req.contentType = parseType(req.headers['content-type']);
  req.pathname = '';
  req.path = [];
  req.query = Object.create(null);
  req.params = Object.create(null);
  req.body = Object.create(null);

  assert(req.options == null);
  assert(req.username == null);
  assert(req.password == null);
  assert(req.admin == null);
  assert(req.wallet == null);

  req.options = Object.create(null);
  req.username = null;
  req.password = null;
  req.admin = false;
  req.wallet = null;

  assert(res.sent == null);
  assert(res.send == null);
  assert(res.error == null);

  res.sent = false;
  res.send = makeSend(res);
  res.error = makeSendError(req, res);

  parsePath(req, limit);
}

function makeSend(res) {
  return function send(code, msg, type) {
    return sendResponse(res, code, msg, type);
  };
}

function sendResponse(res, code, msg, type) {
  var len;

  if (res.sent)
    return;

  assert(typeof code === 'number', 'Code must be a number.');

  if (msg == null)
    msg = { error: 'No message.' };

  if (msg && typeof msg === 'object' && !Buffer.isBuffer(msg)) {
    msg = JSON.stringify(msg, null, 2) + '\n';
    if (!type)
      type = 'json';
    assert(type === 'json', 'Bad type passed with json object.');
  }

  if (!type)
    type = typeof msg === 'string' ? 'txt' : 'bin';

  res.statusCode = code;
  res.setHeader('Content-Type', getType(type));
  res.sent = true;

  if (typeof msg === 'string') {
    len = Buffer.byteLength(msg, 'utf8');
    res.setHeader('Content-Length', len + '');
    try {
      res.write(msg, 'utf8');
      res.end();
    } catch (e) {
      ;
    }
    return;
  }

  if (Buffer.isBuffer(msg)) {
    res.setHeader('Content-Length', msg.length + '');
    try {
      res.write(msg);
      res.end();
    } catch (e) {
      ;
    }
    return;
  }

  assert(false, 'Bad object passed to send.');
}

function makeSendError(req, res) {
  return function error(err) {
    return sendError(req, res, err);
  };
}

function sendError(req, res, err) {
  var code, msg;

  if (res.sent)
    return;

  code = err.statusCode;
  msg = err.message;

  if (!code)
    code = 400;

  if (typeof msg !== 'string')
    msg += '';

  res.send(code, { error: msg });

  try {
    req.destroy();
    req.socket.destroy();
  } catch (e) {
    ;
  }
}

function parsePairs(str, limit) {
  var parts = str.split('&');
  var data = Object.create(null);
  var i, index, pair, key, value;

  assert(!limit || parts.length <= limit, 'Too many keys in querystring.');

  for (i = 0; i < parts.length; i++) {
    pair = parts[i];
    index = pair.indexOf('=');

    if (index === -1) {
      key = pair;
      value = '';
    } else {
      key = pair.substring(0, index);
      value = pair.substring(index + 1);
    }

    key = unescape(key);

    if (key.length === 0)
      continue;

    value = unescape(value);

    if (value.length === 0)
      continue;

    data[key] = value;
  }

  return data;
}

function parsePath(req, limit) {
  var uri = URL.parse(req.url);
  var pathname = uri.pathname;
  var query = Object.create(null);
  var path, parts, url;

  if (pathname) {
    pathname = pathname.replace(/\/{2,}/g, '/');

    if (pathname[0] !== '/')
      pathname = '/' + pathname;

    if (pathname.length > 1) {
      if (pathname[pathname.length - 1] === '/')
        pathname = pathname.slice(0, -1);
    }

    pathname = unescape(pathname);
  } else {
    pathname = '/';
  }

  assert(pathname.length > 0);
  assert(pathname[0] === '/');

  if (pathname.length > 1)
    assert(pathname[pathname.length - 1] !== '/');

  path = pathname;

  if (path[0] === '/')
    path = path.substring(1);

  parts = path.split('/');

  if (parts.length === 1) {
    if (parts[0].length === 0)
      parts = [];
  }

  url = pathname;

  if (uri.search && uri.search.length > 1) {
    assert(uri.search[0] === '?');
    url += uri.search;
  }

  if (uri.hash && uri.hash.length > 1) {
    assert(uri.hash[0] === '#');
    url += uri.hash;
  }

  if (uri.query)
    query = parsePairs(uri.query, limit);

  req.url = url;
  req.pathname = pathname;
  req.path = parts;
  req.query = query;
}

function unescape(str) {
  str = decodeURIComponent(str);
  str = str.replace(/\+/g, ' ');
  str = str.replace(/\0/g, '');
  return str;
}

function getType(type) {
  switch (type) {
    case 'json':
      return 'application/json';
    case 'form':
      return 'application/x-www-form-urlencoded; charset=utf-8';
    case 'html':
      return 'text/html; charset=utf-8';
    case 'js':
      return 'application/javascript; charset=utf-8';
    case 'css':
      return 'text/css; charset=utf-8';
    case 'txt':
      return 'text/plain; charset=utf-8';
    case 'bin':
      return 'application/octet-stream';
    default:
      throw new Error('Unknown type: ' + type);
  }
}

function parseType(type) {
  type = type || '';
  type = type.split(';')[0];
  type = type.toLowerCase();
  type = type.trim();

  switch (type) {
    case 'text/x-json':
    case 'application/json':
      return 'json';
    case 'application/x-www-form-urlencoded':
      return 'form';
    case 'text/html':
    case 'application/xhtml+xml':
      return 'html';
    case 'text/javascript':
    case 'application/javascript':
      return 'js';
    case 'text/css':
      return 'css';
    case 'text/plain':
      return 'txt';
    case 'application/octet-stream':
      return 'bin';
    default:
      return 'bin';
  }
}

/*
 * Expose
 */

module.exports = HTTPBase;
