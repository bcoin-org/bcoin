/*!
 * logger.js - basic logger for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils');
var assert = require('assert');
var fs;

if (!utils.isBrowser)
  fs = require('f' + 's');

/**
 * Basic stdout and file logger.
 * @exports Logger
 * @constructor
 * @param {(String|Object)?} options/level
 * @param {String?} options.level
 * @param {Boolean} [options.colors=true]
 */

function Logger(options) {
  if (!(this instanceof Logger))
    return new Logger(options);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { level: options };

  this.level = Logger.levels.warning;
  this.colors = options.colors !== false;
  this.file = options.file;
  this.stream = null;
  this.closed = false;

  if (!process.stdout || !process.stdout.isTTY)
    this.colors = false;

  if (options.level != null)
    this.setLevel(options.level);
}

/**
 * Available log levels.
 * @enum {Number}
 */

Logger.levels = {
  none: 0,
  error: 1,
  warning: 2,
  info: 3,
  debug: 4
};

/**
 * Default CSI colors.
 * @enum {String}
 */

Logger.colors = {
  error: '1;31',
  warning: '1;33',
  info: '94',
  debug: '90'
};

/**
 * Open the logger.
 */

Logger.prototype.open = function open() {
  this.closed = false;
};

/**
 * Destroy the write stream.
 */

Logger.prototype.close = function close() {
  if (!this.stream)
    return;

  try {
    this.stream.destroy();
  } catch (e) {
    ;
  }

  this.closed = true;
  this.stream = null;
};

/**
 * Set or reset the log level.
 * @param {String} level
 */

Logger.prototype.setLevel = function setLevel(level) {
  level = Logger.levels[level];
  assert(level != null, 'Invalid log level.');
  this.level = level;
};

/**
 * Output a log to the `error` log level.
 * @param {String|Object|Error} err
 * @param {...Object} args
 */

Logger.prototype.error = function error(err) {
  var i, args;

  if (this.level < Logger.levels.error)
    return;

  if (err instanceof Error)
    return this._error(err);

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log('error', args);
};

/**
 * Output a log to the `warning` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.warning = function warning() {
  var i, args;

  if (this.level < Logger.levels.warning)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log('warning', args);
};

/**
 * Output a log to the `info` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.info = function info() {
  var i, args;

  if (this.level < Logger.levels.info)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log('info', args);
};

/**
 * Output a log to the `debug` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.debug = function debug() {
  var i, args;

  if (this.level < Logger.levels.debug)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log('debug', args);
};

/**
 * Output a log to the desired log level.
 * Note that this bypasses the level check.
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.log = function log(level, args) {
  var prefix, color, msg;

  if (this.closed)
    return;

  assert(Logger.levels[level] != null, 'Invalid log level.');

  prefix = '[' + level + '] ';

  if (utils.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? utils.format(args, false)
      : args[0];

    msg = prefix + msg;

    if (level === 'error')
      console.error(msg);
    else
      console.log(msg);

    return;
  }

  if (this.colors) {
    color = Logger.colors[level];
    prefix = '\x1b[' + color + 'm' + prefix + '\x1b[m';
  }

  msg = prefix + utils.format(args, this.colors);

  if (level === 'error')
    process.stderr.write(msg + '\n');
  else
    process.stdout.write(msg + '\n');

  if (this.file) {
    if (this.colors)
      msg = prefix + utils.format(args, false);
    this.write(msg);
  }
};

/**
 * Write a string to the output stream (usually a file).
 * @param {String} msg
 */

Logger.prototype.write = function write(msg) {
  if (!fs)
    return;

  if (this.closed)
    return;

  if (!this.stream) {
    utils.mkdir(this.file, true);
    this.stream = fs.createWriteStream(this.file, { flags: 'a' });
    this.stream.on('error', function() {});
  }

  this.stream.write(process.pid + ' (' + utils.date() + '): ' + msg + '\n');
};

/**
 * Helper to parse an error into a nicer
 * format. Call's `log` internally.
 * @private
 * @param {Error} err
 */

Logger.prototype._error = function error(err) {
  var msg;

  if (utils.isBrowser) {
    console.error(err);
    return;
  }

  msg = (err.message + '').replace(/^ *Error: */, '');

  this.log('error', [msg]);

  if (this.file)
    this.write(err.stack + '');
};

/**
 * Log the current memory usage.
 */

Logger.prototype.memory = function memory() {
  var mem;

  if (!process.memoryUsage)
    return;

  mem = process.memoryUsage();

  this.debug('Memory: rss=%dmb, js-heap=%d/%dmb native-heap=%dmb',
    utils.mb(mem.rss),
    utils.mb(mem.heapUsed),
    utils.mb(mem.heapTotal),
    utils.mb(mem.rss - mem.heapTotal));
};

/*
 * Expose
 */

module.exports = Logger;
