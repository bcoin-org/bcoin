/*!
 * router.js - router for bweb
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bweb
 */

'use strict';

const assert = require('bsert');
const Route = require('./route');
const Hook = require('./hook');

/**
 * Router
 */

class Router {
  /**
   * Create a router.
   * @constructor
   */

  constructor() {
    this._get = [];
    this._post = [];
    this._put = [];
    this._del = [];
    this._patch = [];
    this.hooks = [];
  }

  /**
   * Get method handlers.
   * @private
   * @param {String} method
   * @returns {Promise}
   */

  _handlers(method) {
    assert(typeof method === 'string');
    switch (method.toUpperCase()) {
      case 'GET':
        return this._get;
      case 'POST':
        return this._post;
      case 'PUT':
        return this._put;
      case 'DELETE':
        return this._del;
      case 'PATCH':
        return this._patch;
      default:
        return null;
    }
  }

  /**
   * Handle route stack.
   * @private
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async handle(req, res) {
    const routes = this._handlers(req.method);

    if (!routes)
      return false;

    let err = null;

    for (const route of routes) {
      const params = route.match(req.pathname);

      if (!params)
        continue;

      req.params = params;

      if (err) {
        if (route.arity !== 3)
          continue;

        await route.handler(err, req, res);

        if (res.sent)
          return true;

        continue;
      }

      if (route.arity !== 2)
        continue;

      if (await this._handleHooks(req, res))
        return true;

      try {
        await route.handler(req, res);
        if (res.sent)
          return true;
      } catch (e) {
        err = e;
      }
    }

    if (err)
      throw err;

    return false;
  }

  /**
   * Handle hook stack.
   * @private
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise}
   */

  async _handleHooks(req, res) {
    let err = null;

    for (const hook of this.hooks) {
      if (!hook.isPrefix(req.pathname))
        continue;

      if (err) {
        if (hook.arity !== 3)
          continue;

        await hook.handler(err, req, res);

        if (res.sent)
          return true;

        continue;
      }

      if (hook.arity !== 2)
        continue;

      try {
        await hook.handler(req, res);
        if (res.sent)
          return true;
      } catch (e) {
        err = e;
      }
    }

    if (err)
      throw err;

    return false;
  }

  /**
   * Add a hook to the stack.
   * @param {String?} path
   * @param {Function} handler
   */

  hook(path, handler) {
    if (!handler) {
      handler = path;
      path = '/';
    }
    this.hooks.push(new Hook(path, handler));
  }

  /**
   * Add a GET route.
   * @param {String} path
   * @param {Function} handler
   */

  get(path, handler) {
    this._get.push(new Route(path, handler));
  }

  /**
   * Add a POST route.
   * @param {String} path
   * @param {Function} handler
   */

  post(path, handler) {
    this._post.push(new Route(path, handler));
  }

  /**
   * Add a PUT route.
   * @param {String} path
   * @param {Function} handler
   */

  put(path, handler) {
    this._put.push(new Route(path, handler));
  }

  /**
   * Add a DELETE route.
   * @param {String} path
   * @param {Function} handler
   */

  del(path, handler) {
    this._del.push(new Route(path, handler));
  }

  /**
   * Add a PATCH route.
   * @param {String} path
   * @param {Function} handler
   */

  patch(path, handler) {
    this._patch.push(new Route(path, handler));
  }
}

/**
 * Expose
 */

module.exports = Router;
