/*!
 * request.js - http request for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const EventEmitter = require('events');
const URL = require('url');
const qs = require('querystring');
const fetch = global.fetch;
const FetchHeaders = global.Headers;

/*
 * Constants
 */

const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1)'
  + ' AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36';

/**
 * Request Options
 * @constructor
 * @ignore
 * @param {Object} options
 */

function RequestOptions(options) {
  if (!(this instanceof RequestOptions))
    return new RequestOptions(options);

  this.uri = 'http://localhost:80/';
  this.host = 'localhost';
  this.path = '/';
  this.port = 80;
  this.ssl = false;
  this.method = 'GET';
  this.strictSSL = true;
  this.agent = USER_AGENT;

  this.type = null;
  this.expect = null;
  this.query = null;
  this.body = null;
  this.auth = null;
  this.limit = 10 << 20;
  this.timeout = 5000;
  this.buffer = false;

  if (options)
    this.fromOptions(options);
}

RequestOptions.prototype.setURI = function setURI(uri) {
  assert(typeof uri === 'string');

  if (!/:\/\//.test(uri))
    uri = (this.ssl ? 'https://' : 'http://') + uri;

  uri = URL.parse(uri);

  assert(uri.protocol === 'http:' || uri.protocol === 'https:');

  this.uri = uri;
  this.ssl = uri.protocol === 'https:';

  if (uri.search)
    this.query = qs.parse(uri.search);

  this.host = uri.hostname;
  this.path = uri.pathname;
  this.port = uri.port || (this.ssl ? 443 : 80);

  if (uri.auth) {
    const parts = uri.auth.split(':');
    this.auth = {
      username: parts[0] || '',
      password: parts[1] || ''
    };
  }
};

RequestOptions.prototype.fromOptions = function fromOptions(options) {
  if (typeof options === 'string')
    options = { uri: options };

  if (options.ssl != null) {
    assert(typeof options.ssl === 'boolean');
    this.ssl = options.ssl;
  }

  if (options.uri != null)
    this.setURI(options.uri);

  if (options.url != null)
    this.setURI(options.url);

  if (options.method != null) {
    assert(typeof options.method === 'string');
    this.method = options.method.toUpperCase();
  }

  if (options.strictSSL != null) {
    assert(typeof options.strictSSL === 'boolean');
    this.strictSSL = options.strictSSL;
  }

  if (options.agent != null) {
    assert(typeof options.agent === 'string');
    this.agent = options.agent;
  }

  if (options.auth != null) {
    assert(typeof options.auth === 'object');
    assert(typeof options.auth.username === 'string');
    assert(typeof options.auth.password === 'string');
    this.auth = options.auth;
  }

  if (options.query != null) {
    if (typeof options.query === 'string') {
      this.query = qs.stringify(options.query);
    } else {
      assert(typeof options.query === 'object');
      this.query = options.query;
    }
  }

  if (options.json != null) {
    assert(typeof options.json === 'object');
    this.body = Buffer.from(JSON.stringify(options.json), 'utf8');
    this.type = 'json';
  }

  if (options.form != null) {
    assert(typeof options.form === 'object');
    this.body = Buffer.from(qs.stringify(options.form), 'utf8');
    this.type = 'form';
  }

  if (options.type != null) {
    assert(typeof options.type === 'string');
    assert(getType(options.type));
    this.type = options.type;
  }

  if (options.expect != null) {
    assert(typeof options.expect === 'string');
    assert(getType(options.expect));
    this.expect = options.expect;
  }

  if (options.body != null) {
    if (typeof options.body === 'string') {
      this.body = Buffer.from(options.body, 'utf8');
    } else {
      assert(Buffer.isBuffer(options.body));
      this.body = options.body;
    }
  }

  if (options.timeout != null) {
    assert(typeof options.timeout === 'number');
    this.timeout = options.timeout;
  }

  if (options.limit != null) {
    assert(typeof options.limit === 'number');
    this.limit = options.limit;
  }

  if (options.buffer != null) {
    assert(typeof options.buffer === 'boolean');
    this.buffer = options.buffer;
  }
};

RequestOptions.prototype.isExpected = function isExpected(type) {
  if (!this.expect)
    return true;

  return this.expect === type;
};

RequestOptions.prototype.isOverflow = function isOverflow(hdr) {
  if (!hdr)
    return false;

  if (!this.buffer)
    return false;

  const length = parseInt(hdr, 10);

  if (!isFinite(length))
    return true;

  return length > this.limit;
};

RequestOptions.prototype.getHeaders = function getHeaders() {
  const headers = new FetchHeaders();

  headers.append('User-Agent', this.agent);

  if (this.type)
    headers.append('Content-Type', getType(this.type));

  if (this.body)
    headers.append('Content-Length', this.body.length.toString(10));

  if (this.auth) {
    const auth = `${this.auth.username}:${this.auth.password}`;
    const data = Buffer.from(auth, 'utf8');
    headers.append('Authorization', `Basic ${data.toString('base64')}`);
  }

  return headers;
};

RequestOptions.prototype.toURL = function toURL() {
  let url = '';

  if (this.ssl)
    url += 'https://';
  else
    url += 'http://';

  url += this.host;
  url += ':' + this.port;
  url += this.path;

  if (this.query)
    url += '?' + qs.stringify(this.query);

  return url;
};

RequestOptions.prototype.toHTTP = function toHTTP() {
  return {
    method: this.method,
    headers: this.getHeaders(),
    body: this.body.buffer,
    mode: 'cors',
    credentials: 'include',
    cache: 'no-cache',
    redirect: 'follow',
    referrer: 'no-referrer'
  };
};

/**
 * Response
 * @constructor
 * @ignore
 */

function Response() {
  this.statusCode = 0;
  this.headers = Object.create(null);
  this.type = 'bin';
  this.body = null;
}

Response.fromFetch = function fromFetch(response) {
  const res = new Response();

  res.statusCode = response.status;

  for (const [key, value] of response.headers.entries())
    res.headers[key.toLowerCase()] = value;

  const contentType = res.headers['content-type'];

  res.type = parseType(contentType);

  return res;
};

/**
 * Make an HTTP request.
 * @private
 * @param {Object} options
 * @returns {Promise}
 */

async function _request(options) {
  if (typeof fetch !== 'function')
    throw new Error('Fetch API not available.');

  const opt = new RequestOptions(options);
  const response = await fetch(opt.toURL(), opt.toHTTP());
  const res = Response.fromFetch(response);

  if (!opt.isExpected(res.type))
    throw new Error('Wrong content-type for response.');

  const length = res.headers['content-length'];

  if (opt.isOverflow(length))
    throw new Error('Response exceeded limit.');

  if (opt.buffer) {
    switch (res.type) {
      case 'bin': {
        const data = await response.arrayBuffer();
        res.body = Buffer.from(data.buffer);
        if (opt.limit && res.body.length > opt.limit)
          throw new Error('Response exceeded limit.');
        break;
      }
      case 'json': {
        res.body = await response.json();
        break;
      }
      case 'form': {
        const data = await response.formData();
        res.body = Object.create(null);
        for (const [key, value] of data.entries())
          res.body[key] = value;
        break;
      }
      default: {
        res.body = await response.text();
        if (opt.limit && res.body.length > opt.limit)
          throw new Error('Response exceeded limit.');
        break;
      }
    }
  } else {
    res.body = await response.arrayBuffer();
  }

  return res;
}

/**
 * Make an HTTP request.
 * @alias module:http.request
 * @param {Object} options
 * @param {String} options.uri
 * @param {Object?} options.query
 * @param {Object?} options.body
 * @param {Object?} options.json
 * @param {Object?} options.form
 * @param {String?} options.type - One of `"json"`,
 * `"form"`, `"text"`, or `"bin"`.
 * @param {String?} options.agent - User agent string.
 * @param {Object?} [options.strictSSL=true] - Whether to accept bad certs.
 * @param {Object?} options.method - HTTP method.
 * @param {Object?} options.auth
 * @param {String?} options.auth.username
 * @param {String?} options.auth.password
 * @param {String?} options.expect - Type to expect (see options.type).
 * Error will be returned if the response is not of this type.
 * @param {Number?} options.limit - Byte limit on response.
 * @returns {Promise}
 */

async function request(options) {
  if (typeof options === 'string')
    options = { uri: options };

  options.buffer = true;

  return _request(options);
}

request.stream = function stream(options) {
  const s = new EventEmitter();

  s.write = (data) => {
    options.body = data;
    return true;
  };

  s.end = () => {
    _request(options).then((res) => {
      s.emit('headers', res.headers);
      s.emit('type', res.type);
      s.emit('response', res);
      s.emit('data', res.body);
      s.emit('end');
      s.emit('close');
    }).catch((err) => {
      s.emit('error', err);
    });
    return true;
  };

  return s;
};

/*
 * Helpers
 */

function parseType(hdr) {
  let type = hdr || '';
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
    case 'text/xml':
    case 'application/xml':
      return 'xml';
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

function getType(type) {
  switch (type) {
    case 'json':
      return 'application/json; charset=utf-8';
    case 'form':
      return 'application/x-www-form-urlencoded; charset=utf-8';
    case 'html':
      return 'text/html; charset=utf-8';
    case 'xml':
      return 'application/xml; charset=utf-8';
    case 'js':
      return 'application/javascript; charset=utf-8';
    case 'css':
      return 'text/css; charset=utf-8';
    case 'txt':
      return 'text/plain; charset=utf-8';
    case 'bin':
      return 'application/octet-stream';
    default:
      throw new Error(`Unknown type: ${type}.`);
  }
}

/*
 * Expose
 */

module.exports = request;
