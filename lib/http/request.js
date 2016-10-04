/*!
 * request.js - http request for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* jshint -W069 */

/**
 * @module request
 */

var Stream = require('stream').Stream;
var assert = require('assert');

// Spoof by default
var USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
  + ' AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36';

/**
 * Make an HTTP request.
 * @param {Object} options
 * @param {String} options.uri
 * @param {Object?} options.query
 * @param {Object?} options.body
 * @param {Object?} options.json
 * @param {Object?} options.form
 * @param {String?} options.type - One of `"json"`,
 * `"form"`, `"text"`, or `"binary"`.
 * @param {String?} options.agent - User agent string.
 * @param {Object?} [options.strictSSL=true] - Whether to accept bad certs.
 * @param {Object?} options.method - HTTP method.
 * @param {Object?} options.auth
 * @param {String?} options.auth.username
 * @param {String?} options.auth.password
 * @param {String?} options.expect - Type to expect (see options.type).
 * Error will be returned if the response is not of this type.
 * @param {Number?} options.limit - Byte limit on response.
 * @param {Function?} callback - Will return a stream if not present.
 */

function request(options, callback, stream) {
  var qs = require('querystring');
  var url = require('url');
  var uri = options.uri;
  var query = options.query;
  var body = options.body;
  var json = options.json;
  var form = options.form;
  var type = options.type;
  var http, req, opt;

  if (callback)
    return request._buffer(options, callback);

  if (json && typeof json === 'object') {
    body = json;
    json = true;
  }

  if (form && typeof form === 'object') {
    body = qs.stringify(form);
    form = true;
  }

  if (typeof uri !== 'object') {
    if (!/:\/\//.test(uri))
      uri = 'http://' + uri;
    uri = url.parse(uri);
  }

  if (uri.protocol === 'https:')
    http = require('https');
  else
    http = require('http');

  if (uri.search)
    query = qs.parse(uri.search);

  if (query && typeof query !== 'string')
    query = qs.stringify(query);

  if (query)
    query = '?' + query;
  else
    query = '';

  opt = {
    host: uri.hostname,
    port: uri.port || (uri.protocol === 'https:' ? 443 : 80),
    path: uri.pathname + query,
    headers: {
      'User-Agent': options.agent || USER_AGENT
    },
    rejectUnauthorized: options.strictSSL !== false
  };

  if (body) {
    if (!type) {
      if (form)
        type = 'form';
      else if (json || (typeof body === 'object' && !Buffer.isBuffer(body)))
        type = 'json';
      else if (typeof body === 'string')
        type = 'text';
      else
        type = 'binary';
    }

    if (type === 'json' && typeof body === 'object')
      body = JSON.stringify(body);
    else if (type === 'form' && typeof body === 'object')
      body = qs.stringify(body);

    if (type === 'form')
      type = 'application/x-www-form-urlencoded; charset=utf-8';
    else if (type === 'json')
      type = 'application/json; charset=utf-8';
    else if (type === 'text')
      type = 'text/plain; charset=utf-8';
    else if (type === 'binary')
      type = 'application/octet-stream';

    if (typeof body === 'string')
      body = new Buffer(body, 'utf8');

    assert(Buffer.isBuffer(body));

    opt.headers['Content-Type'] = type;
    opt.headers['Content-Length'] = body.length + '';

    opt.method = options.method || 'POST';
  } else {
    opt.method = options.method || 'GET';
  }

  if (options.auth)
    uri.auth = options.auth.username + ':' + options.auth.password;

  if (uri.auth) {
    opt.headers['Authorization'] =
      'Basic ' + new Buffer(uri.auth, 'utf8').toString('base64');
  }

  opt.method = opt.method.toUpperCase();

  req = http.request(opt);

  if (!stream)
    stream = new ReqStream(options);

  stream.req = req;

  req.on('response', function(res) {
    var called = false;
    var type = res.headers['content-type'];

    if (res.headers['location']) {
      if (++stream._redirects > stream.maxRedirects)
        return done(new Error('Too many redirects.'));
      options.uri = res.headers['location'];
      return request(options, null, stream);
    }

    if (/\/json/i.test(type))
      type = 'json';
    else if (/form-urlencoded/i.test(type))
      type = 'form';
    else if (/text\/plain/i.test(type))
      type = 'text';
    else if (/\/x?html/i.test(type))
      type = 'html';
    else
      type = 'binary';

    stream.res = res;
    stream.headers = res.headers;
    stream.type = type;

    if (options.expect && type !== options.expect)
      return done(new Error('Wrong content-type for response.'));

    stream.emit('headers', res.headers);
    stream.emit('type', type);
    stream.emit('response', res);

    function done(err) {
      if (called)
        return;

      called = true;

      if (res.socket)
        res.socket.removeListener('end', done);

      stream.finish();

      if (err) {
        stream.destroy();
        stream.emit('error', err);
        return;
      }

      stream.emit('end');
      stream.emit('close');
    }

    res.on('data', function(data) {
      stream.emit('data', data);
    });

    res.on('error', done);

    res.on('end', done);

    // An agent socket's `end` sometimes
    // won't be emitted on the response.
    if (res.socket)
      res.socket.on('end', done);
  });

  req.on('error', function(err) {
    stream.destroy();
    stream.emit('error', err);
  });

  if (body)
    req.write(body);

  req.end();

  return stream;
}

request._buffer = function(options, callback) {
  var qs = require('querystring');
  var StringDecoder = require('string_decoder').StringDecoder;
  var stream = request(options);
  var total = 0;
  var called = false;
  var decoder, body;

  function done(err) {
    if (called)
      return;

    called = true;

    if (err)
      return callback(err);

    if (stream.type === 'binary') {
      body = Buffer.concat(body);
    } else if (stream.type === 'json') {
      try {
        body = JSON.parse(body);
      } catch (e) {
        return callback(e);
      }
    } else if (stream.type === 'form') {
      try {
        body = qs.parse(body);
      } catch (e) {
        return callback(e);
      }
    }

    callback(null, stream.res, body, stream.type);
  }

  stream.on('type', function(type) {
    if (type !== 'binary') {
      decoder = new StringDecoder('utf8');
      body = '';
    } else {
      body = [];
    }
  });

  stream.on('data', function(data) {
    total += data.length;

    if (options.limit && total > options.limit) {
      stream.destroy();
      return done();
    }

    if (decoder)
      body += decoder.write(data);
    else
      body.push(data);
  });

  stream.on('error', done);

  stream.on('end', done);

  return stream;
};

request.promise = function promise(options) {
  return new Promise(function(resolve, reject) {
    request(options, function(err, res, body) {
      if (err)
        return reject(err);
      res.body = body;
      resolve(res);
    });
  });
};

/*
 * ReqStream
 */

function ReqStream(options) {
  if (!(this instanceof ReqStream))
    return new ReqStream(options);

  Stream.call(this);

  this.req = null;
  this.res = null;
  this.headers = null;
  this.type = null;
  this._redirects = 0;
  this.maxRedirects = options.maxRedirects || 5;
  this.timeout = options.timeout;
  this._timeout = null;

  this._init();
}

ReqStream.prototype._init = function _init() {
  var self = this;
  if (this.timeout) {
    this._timeout = setTimeout(function() {
      self.emit('error', new Error('Request timed out.'));
      self.destroy();
    }, this.timeout);
  }
};

ReqStream.prototype.__proto__ = Stream.prototype;

ReqStream.prototype.destroy = function destroy() {
  try {
    this.req.abort();
  } catch (e) {
    ;
  }

  try {
    this.res.destroy();
  } catch (e) {
    ;
  }

  try {
    this.res.socket.destroy();
  } catch (e) {
    ;
  }

  this.finish();
};

ReqStream.prototype.finish = function finish() {
  if (this._timeout != null) {
    clearTimeout(this._timeout);
    this._timeout = null;
  }
};

/*
 * Expose
 */

module.exports = request;
