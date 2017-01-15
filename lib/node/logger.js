/*!
 * logger.js - basic logger for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var fs = require('fs');
var util = require('../utils/util');

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

  this.level = Logger.levels.NONE;
  this.colors = Logger.HAS_TTY;
  this.console = true;
  this.filename = null;
  this.stream = null;
  this.closed = false;
  this.lastFail = 0;

  this.init(options);
}

/**
 * Whether stdout is a tty FD.
 * @const {Boolean}
 */

Logger.HAS_TTY = !!(process.stdout && process.stdout.isTTY);

/**
 * Available log levels.
 * @enum {Number}
 */

Logger.levels = {
  NONE: 0,
  ERROR: 1,
  WARNING: 2,
  INFO: 3,
  DEBUG: 4,
  SPAM: 5
};

/**
 * Available log levels.
 * @const {String[]}
 * @default
 */

Logger.levelsByVal = [
  'none',
  'error',
  'warning',
  'info',
  'debug',
  'spam'
];

/**
 * Default CSI colors.
 * @const {String[]}
 * @default
 */

Logger.colors = [
  '0',
  '1;31',
  '1;33',
  '94',
  '90',
  '90'
];

/**
 * Initialize the logger.
 * @private
 * @param {Object} options
 */

Logger.prototype.init = function init(options) {
  if (!options)
    return;

  if (typeof options === 'string') {
    this.setLevel(options);
    return;
  }

  if (options.level != null) {
    assert(typeof options.level === 'string');
    this.setLevel(options.level);
  }

  if (options.colors != null && Logger.HAS_TTY) {
    assert(typeof options.colors === 'boolean');
    this.colors = options.colors;
  }

  if (options.console != null) {
    assert(typeof options.console === 'boolean');
    this.console = options.console;
  }

  if (options.filename != null) {
    assert(typeof options.filename === 'string', 'Bad file.');
    this.filename = options.filename;
  }

  if (options.stream != null) {
    assert(typeof options.stream === 'object', 'Bad stream.');
    assert(typeof options.stream.write === 'function', 'Bad stream.');
    this.stream = options.stream;
  }
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
 * Set the log file location.
 * @param {String} filename
 */

Logger.prototype.setFile = function setFile(filename) {
  assert(typeof filename === 'string');
  assert(!this.stream, 'Log stream has already been created.');
  this.filename = filename;
};

/**
 * Set or reset the log level.
 * @param {String} level
 */

Logger.prototype.setLevel = function setLevel(name) {
  var level = Logger.levels[name.toUpperCase()];
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

  if (this.level < Logger.levels.ERROR)
    return;

  if (err instanceof Error)
    return this._error(err);

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log(Logger.levels.ERROR, args);
};

/**
 * Output a log to the `warning` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.warning = function warning() {
  var i, args;

  if (this.level < Logger.levels.WARNING)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log(Logger.levels.WARNING, args);
};

/**
 * Output a log to the `info` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.info = function info() {
  var i, args;

  if (this.level < Logger.levels.INFO)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log(Logger.levels.INFO, args);
};

/**
 * Output a log to the `debug` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.debug = function debug() {
  var i, args;

  if (this.level < Logger.levels.DEBUG)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log(Logger.levels.DEBUG, args);
};

/**
 * Output a log to the `spam` log level.
 * @param {String|Object} obj
 * @param {...Object} args
 */

Logger.prototype.spam = function spam() {
  var i, args;

  if (this.level < Logger.levels.SPAM)
    return;

  args = new Array(arguments.length);

  for (i = 0; i < args.length; i++)
    args[i] = arguments[i];

  this.log(Logger.levels.SPAM, args);
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

  if (this.level < level)
    return;

  this.writeConsole(level, args);
  this.writeStream(level, args);
};

/**
 * Write log to the console.
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.writeConsole = function writeConsole(level, args) {
  var name = Logger.levelsByVal[level];
  var prefix, msg, color;

  assert(name, 'Invalid log level.');

  if (!this.console)
    return;

  prefix = '[' + name + '] ';

  if (util.isBrowser) {
    msg = typeof args[0] !== 'object'
      ? util.format(args, false)
      : args[0];

    msg = prefix + msg;

    return level === Logger.levels.ERROR
      ? console.error(msg)
      : console.log(msg);
  }

  if (this.colors) {
    color = Logger.colors[level];
    prefix = '\x1b[' + color + 'm' + prefix + '\x1b[m';
  }

  msg = prefix + util.format(args, this.colors);

  return level === Logger.levels.ERROR
    ? process.stderr.write(msg + '\n')
    : process.stdout.write(msg + '\n');
};

/**
 * Create or get the current file stream.
 * @returns {Object}
 */

Logger.prototype.getStream = function getStream() {
  var self = this;

  if (this.closed)
    return;

  if (!this.filename)
    return;

  if (fs.unsupported)
    return;

  if (this.stream)
    return this.stream;

  if (this.lastFail > util.now() - 10)
    return;

  this.lastFail = 0;

  util.mkdir(this.filename, true);

  this.stream = fs.createWriteStream(this.filename, { flags: 'a' });

  this.stream.on('error', function(err) {
    self.writeConsole(Logger.levels.WARNING, 'Log file stream died!');
    self.writeConsole(Logger.levels.ERROR, err.message);

    try {
      self.stream.close();
    } catch (e) {
      ;
    }

    // Retry in ten seconds.
    self.stream = null;
    self.lastFail = util.now();
  });
};

/**
 * Write a string to the output stream (usually a file).
 * @param {String} level
 * @param {Object[]} args
 */

Logger.prototype.writeStream = function writeStream(level, args) {
  var name = Logger.levelsByVal[level];
  var stream = this.getStream();
  var prefix, msg;

  assert(name, 'Invalid log level.');

  if (!stream)
    return;

  prefix = '[' + name + '] ';
  msg = prefix + util.format(args, false);
  msg = '(' + util.date() + '): ' + msg + '\n';

  if (!util.isBrowser)
    msg = process.pid + ' ' + msg;

  stream.write(msg);
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

  this.log(Logger.levels.ERROR, [msg]);

  if (this.level >= Logger.levels.DEBUG) {
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

Logger.global = new Logger();

/*
 * Expose
 */

module.exports = Logger;
