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

  this.server.on('request', function(req, res) {
    var i, j, routes, route, match, item;

    function send(code, msg, type) {
      sendResponse(res, code, msg, type);
    }

    function done(err) {
      if (err) {
        send(err.statusCode || 400, { error: err.message + '' });

        try {
          req.destroy();
          req.socket.destroy();
        } catch (e) {
          ;
        }

        self.emit('error', err);
      }
    }

    try {
      parsePath(req, 100);
    } catch (e) {
      return done(e);
    }

    self.emit('request', req, res);

    i = 0;
    routes = self.routes.getHandlers(req.method);

    if (!routes)
      return done(new Error('No routes found.'));

    parseBody(req, function(err) {
      if (err)
        return done(err);

      (function next(err) {
        if (err)
          return done(err);

        if (i === routes.length)
          return done(new Error('Route not found.'));

        route = routes[i++];
        match = route.match(req.pathname);

        if (!match)
          return next();

        req.params = {};

        for (j = 0; j < match.length; j++) {
          item = match[j];
          if (route.map[j])
            req.params[route.map[j]] = item;
          req.params[j] = item;
        }

        self.handleStack(req, res, send, function(err) {
          if (err)
            return done(err);

          // Avoid stack overflows
          util.nextTick(function() {
            try {
              route.call(req, res, send, next);
            } catch (e) {
              done(e);
            }
          });
        });
      })();
    });
  });
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

HTTPBase.prototype._close = function close(callback) {
  var self = this;

  return new Promise(function(resolve, reject) {
    if (self.io) {
      self.server.once('close', resolve);
      self.io.close();
      return;
    }

    self.server.close(function(err) {
      if (err)
        return reject(err);
      resolve();
    });
  });
};

/**
 * Handle middleware stack.
 * @private
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @param {Function} send
 * @returns {Promise}
 */

HTTPBase.prototype.handleStack = function handleStack(req, res, send, callback) {
  var self = this;
  var i = 0;
  var route;

  (function next(err) {
    if (err)
      return callback(err);

    if (i === self.stack.length)
      return callback();

    route = self.stack[i++];

    util.nextTick(function() {
      if (!route.hasPrefix(req.pathname))
        return next();

      try {
        route.call(req, res, send, next);
      } catch (e) {
        next(e);
      }
    });
  })();
};

/**
 * Add a middleware to the stack.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.use = function use(path, callback, ctx) {
  var i;

  if (!callback) {
    callback = path;
    path = null;
  }

  if (Array.isArray(path)) {
    for (i = 0; i < path.length; i++)
      this.use(path[i], callback, ctx);
    return;
  }

  this.stack.push(new Route(ctx, path, callback));
};

/**
 * Add a GET route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.get = function get(path, callback, ctx) {
  var i;

  if (Array.isArray(path)) {
    for (i = 0; i < path.length; i++)
      this.get(path[i], callback, ctx);
    return;
  }

  assert(typeof path === 'string');
  assert(path.length > 0);

  this.routes.get.push(new Route(ctx, path, callback));
};

/**
 * Add a POST route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.post = function post(path, callback, ctx) {
  var i;

  if (Array.isArray(path)) {
    for (i = 0; i < path.length; i++)
      this.post(path[i], callback, ctx);
    return;
  }

  assert(typeof path === 'string');
  assert(path.length > 0);

  this.routes.post.push(new Route(ctx, path, callback));
};

/**
 * Add a PUT route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.put = function put(path, callback, ctx) {
  var i;

  if (Array.isArray(path)) {
    for (i = 0; i < path.length; i++)
      this.put(path[i], callback, ctx);
    return;
  }

  assert(typeof path === 'string');
  assert(path.length > 0);

  this.routes.put.push(new Route(ctx, path, callback));
};

/**
 * Add a DELETE route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.del = function del(path, callback, ctx) {
  var i;

  if (Array.isArray(path)) {
    for (i = 0; i < path.length; i++)
      this.del(path[i], callback, ctx);
    return;
  }

  assert(typeof path === 'string');
  assert(path.length > 0);

  this.routes.del.push(new Route(ctx, path, callback));
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
 * @param {String?} host
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

function Route(ctx, path, callback) {
  if (!(this instanceof Route))
    return new Route(ctx, path, callback);

  this.ctx = null;
  this.path = null;
  this.callback = null;

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
      this.path = path;
    }
  }

  assert(typeof callback === 'function');
  this.callback = callback;
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
  var match;

  assert(this.path);

  this.compile();

  match = this.regex.exec(pathname);

  if (!match)
    return;

  return match.slice(1);
};

Route.prototype.hasPrefix = function hasPrefix(pathname) {
  if (!this.path)
    return true;

  return pathname.indexOf(this.path) === 0;
};

Route.prototype.call = function call(req, res, send, next) {
  this.callback.call(this.ctx, req, res, send, next);
};

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

function sendResponse(res, code, msg, type) {
  var len;

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

function parseBody(req, callback) {
  var StringDecoder = require('string_decoder').StringDecoder;
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

function parsePairs(str, limit) {
  var parts = str.split('&');
  var data = {};
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
  var query = {};
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
  req.params = {};
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

/*
 * Expose
 */

module.exports = HTTPBase;
