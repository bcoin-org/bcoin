/*!
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var AsyncObject = require('../utils/async');
var util = require('../utils/util');
var assert = require('assert');
var url = require('url');

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

  this.routes = {
    get: [],
    post: [],
    put: [],
    del: []
  };

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
    function _send(code, msg, type) {
      send(res, code, msg, type);
    }

    function done(err) {
      if (err) {
        send(res, err.statusCode || 400, { error: err.message + '' });
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
      parsePath(req);
    } catch (e) {
      return done(e);
    }

    self.emit('request', req, res);

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

        self._handle(req, res, _send, function(err) {
          if (err)
            return done(err);

          // Avoid stack overflows
          util.nextTick(function() {
            try {
              callback.call(route.ctx, req, res, _send, next);
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
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @param {Function} _send
 * @returns {Promise}
 * @private
 */

HTTPBase.prototype._handle = function _handle(req, res, _send, callback) {
  var self = this;
  var i = 0;
  var handler;

  (function next(err) {
    if (err)
      return callback(err);

    if (i === self.stack.length)
      return callback();

    handler = self.stack[i++];

    util.nextTick(function() {
      if (handler.path && req.pathname.indexOf(handler.path) !== 0)
        return next();

      try {
        handler.callback.call(handler.ctx, req, res, _send, next);
      } catch (e) {
        next(e);
      }
    });
  })();
};

/**
 * Middleware and route callback.
 * @callback RouteCallback
 * @param {HTTPRequest} req
 * @param {HTTPResponse} res
 * @param {Function} next
 * @param {Function} send
 */

/**
 * Add a middleware to the stack.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.use = function use(path, callback, ctx) {
  if (!callback) {
    callback = path;
    path = null;
  }

  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.use(path, callback, ctx);
    }, this);
    return;
  }

  this.stack.push({ ctx: ctx, path: path, callback: callback });
};

/**
 * Add a GET route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.get = function get(path, callback, ctx) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.get(path, callback, ctx);
    }, this);
    return;
  }
  this.routes.get.push({ ctx: ctx, path: path, callback: callback });
};

/**
 * Add a POST route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.post = function post(path, callback, ctx) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.post(path, callback, ctx);
    }, this);
    return;
  }
  this.routes.post.push({ ctx: ctx, path: path, callback: callback });
};

/**
 * Add a PUT route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.put = function put(path, callback, ctx) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.put(path, callback, ctx);
    }, this);
    return;
  }
  this.routes.put.push({ ctx: ctx, path: path, callback: callback });
};

/**
 * Add a DELETE route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.del = function del(path, callback, ctx) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.del(path, callback, ctx);
    }, this);
    return;
  }
  this.routes.del.push({ ctx: ctx, path: path, callback: callback });
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

/*
 * Helpers
 */

function send(res, code, msg, type) {
  var len;

  if (!msg)
    msg = { error: 'No message.' };

  try {
    res.statusCode = code;

    if (msg && typeof msg === 'object' && !Buffer.isBuffer(msg)) {
      msg = JSON.stringify(msg, null, 2) + '\n';
      type = 'json';
    }

    if (type === 'html')
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
    else if (type === 'text')
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    else if (type === 'json')
      res.setHeader('Content-Type', 'application/json');
    else if (type === 'js')
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    else if (type === 'binary')
      res.setHeader('Content-Type', 'application/octet-stream');

    len = typeof msg === 'string'
      ? Buffer.byteLength(msg, 'utf8')
      : msg.length;

    res.setHeader('Content-Length', len + '');
    res.write(msg);
    res.end();
  } catch (e) {
    ;
  }
}

function compilePath(path) {
  var map = [];

  if (path instanceof RegExp)
    return { regex: path, map: map };

  var regex = path
    .replace(/(\/[^\/]+)\?/g, '(?:$1)?')
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

function parsePairs(str) {
  var parts = str.split('&');
  var data = {};
  var i, index, pair, key, value;

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

function unescape(str) {
  try {
    str = decodeURIComponent(str).replace(/\+/g, ' ');
  } finally {
    return str.replace(/\0/g, '');
  }
}

/*
 * Expose
 */

module.exports = HTTPBase;
