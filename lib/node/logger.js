/*!
 * logger.js - basic logger for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var util = require('../utils/util');
var assert = require('assert');
var fs = require('fs');

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
  this.console = options.console !== false;
  this.file = options.file;
  this.stream = options.stream;
  this.closed = false;

  assert(!this.file || typeof this.file === 'string', 'Bad file.');
  assert(!this.stream || typeof this.stream.write === 'function', 'Bad stream.');

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
  debug: 4,
  spam: 5
};

/**
 * Default CSI colors.
 * @enum {String}
 */

Logger.colors = {
  error: '1;31',
  warning: '1;33',
  info: '94',
  debug: '90',
  spam: '90'
};

/**
 * Open the logger.
 */

Logger.prototype.open = function open() {
  this.closed = false;
  if (this.stream)
    this.stream.open();
};

/**
 * Destroy the write stream.
 */

Logger.prototype.close = function close() {
  if (!this.stream)
    return;

  try {
    this.stream.close();
  } catch (e) {
    ;
  }

  this.closed = true;
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
 * Output a log to the `spam` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.spam = function spam() {
  var i, args;

  if (this.level < Logger.levels.spam)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log('spam', args);
};

/**
 * Output a log to the desired log level.
 * Note that this bypasses the level check.
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.log = function log(level, args) {
  if (this.closed)
    return;

  assert(Logger.levels[level] != null, 'Invalid log level.');

  this.writeConsole(level, args);
  this.writeStream(level, args);
};

/**
 * Write log to the console.
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.writeConsole = function writeConsole(level, args) {
  var prefix, msg, color;

  if (!this.console)
    return;

  prefix = '[' + level + '] ';

  if (util.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? util.format(args, false)
      : args[0];

    msg = prefix + msg;

    return level === 'error'
      ? console.error(msg)
      : console.log(msg);
  }

  if (this.colors) {
    color = Logger.colors[level];
    prefix = '\x1b[' + color + 'm' + prefix + '\x1b[m';
  }

  msg = prefix + util.format(args, this.colors);

  return level === 'error'
    ? process.stderr.write(msg + '\n')
    : process.stdout.write(msg + '\n');
};

/**
 * Write a string to the output stream (usually a file).
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.writeStream = function writeStream(level, args) {
  var prefix, msg;

  if (this.closed)
    return;

  if (!this.stream) {
    if (!this.file)
      return;

    if (fs.unsupported)
      return;

    util.mkdir(this.file, true);

    this.stream = fs.createWriteStream(this.file, { flags: 'a' });
    this.stream.on('error', function() {});
  }

  prefix = '[' + level + '] ';
  msg = prefix + util.format(args, false);
  msg = '(' + util.date() + '): ' + msg + '\n';

  if (!util.isBrowser)
    msg = process.pid + ' ' + msg;

  this.stream.write(msg);
};

/**
 * Helper to parse an error into a nicer
 * format. Call's `log` internally.
 * @private
 * @param {Error} err
 */

Logger.prototype._error = function error(err) {
  var msg;

  if (this.closed)
    return;

  if (util.isBrowser && this.console)
    console.error(err);

  msg = (err.message + '').replace(/^ *Error: */, '');

  this.log('error', [msg]);

  if (this.level >= Logger.levels.debug) {
    if (this.stream)
      this.stream.write(err.stack + '\n');
  }
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
    util.mb(mem.rss),
    util.mb(mem.heapUsed),
    util.mb(mem.heapTotal),
    util.mb(mem.rss - mem.heapTotal));
};

/*
 * Default
 */

Logger.global = new Logger('none');

/*
 * Expose
 */

module.exports = Logger;
