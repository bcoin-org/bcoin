/**
 * http.js - http server for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var EventEmitter = require('events').EventEmitter;
var bcoin = require('../../bcoin');
var utils = bcoin.utils;

/**
 * HTTPServer
 */

function HTTPServer(options) {
  if (!(this instanceof HTTPServer))
    return new HTTPServer(options);

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

utils.inherits(HTTPServer, EventEmitter);

HTTPServer.prototype._init = function _init() {
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

HTTPServer.prototype._initIO = function _initIO() {
  var self = this;
  var io;

  try {
    io = require('socket.io');
  } catch (e) {
    ;
  }

  if (!io)
    return;

  this.io = new io.Server();

  this.io.attach(this.server);

  this.io.on('connection', function(socket) {
    self.emit('websocket', socket);
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

HTTPServer.prototype._handle = function _handle(req, res, _send, callback) {
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

HTTPServer.prototype.use = function use(path, callback) {
  if (!callback) {
    callback = path;
    path = null;
  }

  this.stack.push({ path: path, callback: callback });
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

/**
 * Helpers
 */

function send(res, code, msg) {
  if (!msg)
    msg = { error: 'No message.' };

  try {
    res.statusCode = code;
    if (typeof msg === 'object') {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      msg = JSON.stringify(msg, null, 2) + '\n';
    }
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

/**
 * Expose
 */

module.exports = HTTPServer;
