/*!
 * request.js - request object for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const mime = require('./mime');
const {parseURL} = require('./util');

/**
 * Request
 */

class Request extends EventEmitter {
  /**
   * Create a request.
   * @constructor
   * @ignore
   */

  constructor(req, res, url) {
    super();
    this.req = null;
    this.res = null;
    this.socket = null;
    this.method = 'GET';
    this.headers = Object.create(null);
    this.type = 'bin';
    this.url = '/';
    this.pathname = '/';
    this.path = [];
    this.trailing = false;
    this.original = null;
    this.username = null;
    this.query = Object.create(null);
    this.params = Object.create(null);
    this.body = Object.create(null);
    this.cookies = Object.create(null);
    this.hasBody = false;
    this.readable = true;
    this.writable = false;
    this.admin = false;
    this.wallet = null;
    this.init(req, res, url);
  }

  init(req, res, url) {
    assert(req);
    assert(res);

    this.req = req;
    this.res = res;
    this.socket = req.socket;
    this.method = req.method;
    this.headers = req.headers;
    this.type = mime.ext(req.headers['content-type']);
    this.parse(url);

    req.on('error', (err) => {
      this.emit('error', err);
    });

    req.on('data', (data) => {
      this.emit('data', data);
    });

    req.on('end', () => {
      this.emit('end');
    });
  }

  parse(url) {
    const uri = parseURL(url);
    this.original = uri;
    this.url = uri.url;
    this.pathname = uri.pathname;
    this.path = uri.path;
    this.query = uri.query;
    this.trailing = uri.trailing;
  }

  navigate(url) {
    const uri = parseURL(url);
    this.url = uri.url;
    this.pathname = uri.pathname;
    this.path = uri.path;
    this.query = uri.query;
  }

  prefix() {
    if (this.trailing)
      return '';

    const original = this.original;

    if (this.path.length > 0)
      return this.path[this.path.length - 1] + '/';

    if (original.path.length > 0)
      return original.path[original.path.length - 1] + '/';

    return '';
  }

  pipe(dest) {
    return this.req.pipe(dest);
  }

  pause() {
    return this.req.pause();
  }

  resume() {
    return this.req.resume();
  }

  destroy() {
    return this.req.destroy();
  }
}

/*
 * Expose
 */

module.exports = Request;
