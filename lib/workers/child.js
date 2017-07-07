/*!
 * child.js - child processes for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const EventEmitter = require('events');
const path = require('path');
const cp = require('child_process');
const util = require('../utils/util');

const children = new Set();
let exitBound = false;

/**
 * Represents a child process.
 * @alias module:workers.Child
 * @constructor
 * @param {String} file
 * @param {Object} env
 */

function Child(file, env) {
  if (!(this instanceof Child))
    return new Child(file, env);

  EventEmitter.call(this);

  children.add(this);
  bindExit();

  this.init(file, env);
}

util.inherits(Child, EventEmitter);

/**
 * Test whether child process support is available.
 * @returns {Boolean}
 */

Child.hasSupport = function hasSupport() {
  return true;
};

/**
 * Initialize child process (node.js).
 * @private
 */

Child.prototype.init = function init(file, env) {
  let bin = process.argv[0];
  let filename = path.resolve(__dirname, file);
  let environ = Object.assign({}, process.env, env);
  let options = { stdio: 'pipe', env: environ };

  this.child = cp.spawn(bin, [filename], options);

  this.child.unref();
  this.child.stdin.unref();
  this.child.stdout.unref();
  this.child.stderr.unref();

  this.child.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.on('exit', (code, signal) => {
    children.delete(this);
    this.emit('exit', code == null ? -1 : code, signal);
  });

  this.child.on('close', () => {
    children.delete(this);
    this.emit('exit', -1, null);
  });

  this.child.stdin.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stdout.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stderr.on('error', (err) => {
    this.emit('error', err);
  });

  this.child.stdout.on('data', (data) => {
    this.emit('data', data);
  });
};

/**
 * Send data to child process.
 * @param {Buffer} data
 * @returns {Boolean}
 */

Child.prototype.write = function write(data) {
  return this.child.stdin.write(data);
};

/**
 * Destroy the child process.
 */

Child.prototype.destroy = function destroy() {
  this.child.kill('SIGTERM');
};

/*
 * Helpers
 */

function bindExit() {
  let onSighup, onSigint, onSigterm, onError;

  if (exitBound)
    return;

  exitBound = true;

  onSighup = () => {
    process.exit(1 | 0x80);
  };

  onSigint = () => {
    process.exit(2 | 0x80);
  };

  onSigterm = () => {
    process.exit(15 | 0x80);
  };

  onError = (err) => {
    if (err && err.stack)
      console.error(err.stack + '');
    else
      console.error(err + '');

    process.exit(1);
  };

  process.once('exit', () => {
    for (let child of children)
      child.destroy();
  });

  if (process.listenerCount('SIGHUP') === 0)
    process.once('SIGHUP', onSighup);

  if (process.listenerCount('SIGINT') === 0)
    process.once('SIGINT', onSigint);

  if (process.listenerCount('SIGTERM') === 0)
    process.once('SIGTERM', onSigterm);

  if (process.listenerCount('uncaughtException') === 0)
    process.once('uncaughtException', onError);

  process.on('newListener', (name) => {
    switch (name) {
      case 'SIGHUP':
        process.removeListener(name, onSighup);
        break;
      case 'SIGINT':
        process.removeListener(name, onSigint);
        break;
      case 'SIGTERM':
        process.removeListener(name, onSigterm);
        break;
      case 'uncaughtException':
        process.removeListener(name, onError);
        break;
    }
  });
}

/*
 * Expose
 */

module.exports = Child;
