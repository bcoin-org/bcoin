/*!
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var utils = require('../utils');

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

utils.inherits(HTTPBase, EventEmitter);

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

  this.io = new IOServer();

  this.io.attach(this.server);

  this.io.on('connection', function(socket) {
    self.emit('websocket', socket);
  });
};

HTTPBase.prototype._initRouter = function _initRouter() {
  var self = this;

  this.server.on('request', function(req, res) {
    function _send(code, msg, type) {
      send(res, code, msg, type);
    }

    function done(err) {
      if (err) {
        send(res, 400, { error: err.message + '' });
        try {
          req.destroy();
          req.socket.destroy();
        } catch (e) {
          self.emit('error', e);
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
          utils.nextTick(function() {
            try {
              callback(req, res, next, _send);
            } catch (e) {
              done(e);
            }
          });
        });
      })();
    });
  });
};

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

    utils.nextTick(function() {
      if (handler.path && req.pathname.indexOf(handler.path) === -1)
        return next();

      try {
        handler.callback(req, res, next, _send);
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

HTTPBase.prototype.use = function use(path, callback) {
  if (!callback) {
    callback = path;
    path = null;
  }

  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.use(path, callback);
    }, this);
    return;
  }

  this.stack.push({ path: path, callback: callback });
};

/**
 * Add a GET route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.get = function get(path, callback) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.get(path, callback);
    }, this);
    return;
  }
  this.routes.get.push({ path: path, callback: callback });
};

/**
 * Add a POST route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.post = function post(path, callback) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.post(path, callback);
    }, this);
    return;
  }
  this.routes.post.push({ path: path, callback: callback });
};

/**
 * Add a PUT route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.put = function put(path, callback) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.put(path, callback);
    }, this);
    return;
  }
  this.routes.put.push({ path: path, callback: callback });
};

/**
 * Add a DELETE route.
 * @param {String?} path
 * @param {RouteCallback} callback
 */

HTTPBase.prototype.del = function del(path, callback) {
  if (Array.isArray(path)) {
    path.forEach(function(path) {
      this.del(path, callback);
    }, this);
    return;
  }
  this.routes.del.push({ path: path, callback: callback });
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
 * @param {Function} callback
 */

HTTPBase.prototype.listen = function listen(port, host, callback) {
  var self = this;
  this.server.listen(port, host, function(err) {
    if (!callback) {
      if (err)
        throw err;
      return;
    }

    if (err)
      return callback(err);

    return callback(null, self.address());
  });
};

/**
 * Close the the server.
 * @param {Function} callback
 */

HTTPBase.prototype.close = function close(callback) {
  this.server.close(callback);
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
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    else if (type === 'js')
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    else if (type === 'binary')
      res.setHeader('Content-Type', 'application/octet-stream; charset=utf-8');

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
  var url = require('url');
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
