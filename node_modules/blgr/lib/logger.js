/*!
 * logger.js - basic logger for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const format = require('./format');
const fs = require('./fs');

/**
 * Logger
 */

class Logger {
  /**
   * Create a logger.
   * @constructor
   * @param {(String|Object)?} options/level
   * @param {String?} options.level
   * @param {Boolean} [options.colors=true]
   */

  constructor(options) {
    this.level = Logger.levels.NONE;
    this.colors = Logger.HAS_TTY;
    this.console = true;
    this.shrink = true;
    this.closed = true;
    this.closing = false;
    this.filename = null;
    this.stream = null;
    this.contexts = Object.create(null);

    if (options)
      this.set(options);
  }

  /**
   * Set logger options.
   * @param {Object} options
   */

  set(options) {
    assert(options);
    assert(this.closed);

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

    if (options.shrink != null) {
      assert(typeof options.shrink === 'boolean');
      this.shrink = options.shrink;
    }

    if (options.filename != null) {
      assert(typeof options.filename === 'string', 'Bad file.');
      this.filename = options.filename;
    }
  }

  /**
   * Open the logger.
   * @method
   * @returns {Promise}
   */

  async open() {
    if (!this.filename) {
      this.closed = false;
      return;
    }

    if (this.stream) {
      this.closed = false;
      return;
    }

    if (fs.unsupported) {
      this.closed = false;
      return;
    }

    if (this.shrink)
      await this.truncate();

    this.stream = await openStream(this.filename);
    this.stream.once('error', this.handleError.bind(this));
    this.closed = false;
  }

  /**
   * Destroy the write stream.
   * @method
   * @returns {Promise}
   */

  async close() {
    if (this.timer != null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (fs.unsupported) {
      this.closed = true;
      this.stream = null;
      return;
    }

    if (this.stream) {
      try {
        this.closing = true;
        await closeStream(this.stream);
      } finally {
        this.closing = false;
      }
      this.stream = null;
    }

    this.closed = true;
  }

  /**
   * Truncate the log file to the last 20mb.
   * @method
   * @private
   * @returns {Promise}
   */

  async truncate() {
    if (!this.filename)
      return;

    if (fs.unsupported)
      return;

    assert(!this.stream);

    let stat;
    try {
      stat = await fs.stat(this.filename);
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    const maxSize = Logger.MAX_FILE_SIZE;

    if (stat.size <= maxSize + (maxSize / 10))
      return;

    this.debug('Truncating log file to %dmb.', mb(maxSize));

    const fd = await fs.open(this.filename, 'r+');
    const data = Buffer.allocUnsafe(maxSize);

    await fs.read(fd, data, 0, maxSize, stat.size - maxSize);
    await fs.ftruncate(fd, maxSize);
    await fs.write(fd, data, 0, maxSize, 0);
    await fs.close(fd);
  }

  /**
   * Handle write stream error.
   * @param {Error} err
   */

  handleError(err) {
    try {
      this.stream.close();
    } catch (e) {
      ;
    }

    this.stream = null;
    this.retry();
  }

  /**
   * Try to reopen the logger.
   * @method
   * @private
   * @returns {Promise}
   */

  async reopen() {
    if (this.stream)
      return;

    if (this.closed)
      return;

    if (fs.unsupported)
      return;

    try {
      this.stream = await openStream(this.filename);
    } catch (e) {
      this.retry();
      return;
    }

    this.stream.once('error', e => this.handleError(e));
  }

  /**
   * Try to reopen the logger after a timeout.
   * @method
   * @private
   * @returns {Promise}
   */

  retry() {
    if (this.timer != null)
      return;

    this.timer = setTimeout(() => {
      this.timer = null;
      this.reopen();
    }, 10000);
  }

  /**
   * Set the log file location.
   * @param {String} filename
   */

  setFile(filename) {
    assert(typeof filename === 'string');
    assert(!this.stream, 'Log stream has already been created.');
    this.filename = filename;
  }

  /**
   * Set or reset the log level.
   * @param {String} level
   */

  setLevel(name) {
    const level = Logger.levels[name.toUpperCase()];
    assert(level != null, 'Invalid log level.');
    this.level = level;
  }

  /**
   * Output a log to the `error` log level.
   * @param {String|Object|Error} err
   * @param {...Object} args
   */

  error(...args) {
    if (this.level < Logger.levels.ERROR)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.ERROR, null, err);
      return;
    }

    this.log(Logger.levels.ERROR, null, args);
  }

  /**
   * Output a log to the `warning` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  warning(...args) {
    if (this.level < Logger.levels.WARNING)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.WARNING, null, err);
      return;
    }

    this.log(Logger.levels.WARNING, null, args);
  }

  /**
   * Output a log to the `info` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  info(...args) {
    if (this.level < Logger.levels.INFO)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.INFO, null, err);
      return;
    }

    this.log(Logger.levels.INFO, null, args);
  }

  /**
   * Output a log to the `debug` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  debug(...args) {
    if (this.level < Logger.levels.DEBUG)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.DEBUG, null, err);
      return;
    }

    this.log(Logger.levels.DEBUG, null, args);
  }

  /**
   * Output a log to the `spam` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  spam(...args) {
    if (this.level < Logger.levels.SPAM)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.SPAM, null, err);
      return;
    }

    this.log(Logger.levels.SPAM, null, args);
  }

  /**
   * Output a log to the desired log level.
   * Note that this bypasses the level check.
   * @param {String} level
   * @param {String|null} module
   * @param {Object[]} args
   */

  log(level, module, args) {
    if (this.closed)
      return;

    if (this.level < level)
      return;

    this.writeConsole(level, module, args);
    this.writeStream(level, module, args);
  }

  /**
   * Create logger context.
   * @param {String} module
   * @returns {LoggerContext}
   */

  context(module) {
    let ctx = this.contexts[module];

    if (!ctx) {
      ctx = new LoggerContext(this, module);
      this.contexts[module] = ctx;
    }

    return ctx;
  }

  /**
   * Write log to the console.
   * @param {String} level
   * @param {String|null} module
   * @param {Object[]} args
   */

  writeConsole(level, module, args) {
    const name = Logger.levelsByVal[level];

    assert(name, 'Invalid log level.');

    if (!this.console)
      return false;

    if (!process.stdout) {
      let msg = `[${name}] `;

      if (module)
        msg += `(${module}) `;

      if (args.length > 0) {
        const [obj] = args;
        if (obj && typeof obj === 'object') {
          return level === Logger.levels.ERROR
            ? console.error(msg, obj)
            : console.log(msg, obj);
        }
      }

      msg += format(args, false);

      if (level === Logger.levels.ERROR)
        console.error(msg);
      else
        console.log(msg);

      return true;
    }

    let msg;
    if (this.colors) {
      const color = Logger.styles[level];
      assert(color);

      msg = `\x1b[${color}m[${name}]\x1b[m `;
    } else {
      msg = `[${name}] `;
    }

    if (module)
      msg += `(${module}) `;

    msg += format(args, this.colors);
    msg += '\n';

    return level === Logger.levels.ERROR
      ? process.stderr.write(msg)
      : process.stdout.write(msg);
  }

  /**
   * Write a string to the output stream (usually a file).
   * @param {String} level
   * @param {String|null} module
   * @param {Object[]} args
   */

  writeStream(level, module, args) {
    const name = Logger.prefixByVal[level];

    assert(name, 'Invalid log level.');

    if (!this.stream)
      return;

    if (this.closing)
      return;

    const date = new Date().toISOString().slice(0, -5) + 'Z';

    let msg = `[${name}:${date}] `;

    if (module)
      msg += `(${module}) `;

    msg += format(args, false);
    msg += '\n';

    this.stream.write(msg);
  }

  /**
   * Helper to parse an error into a nicer
   * format. Call's `log` internally.
   * @private
   * @param {Number} level
   * @param {String|null} module
   * @param {Error} err
   */

  logError(level, module, err) {
    if (this.closed)
      return;

    if (fs.unsupported && this.console) {
      if (level <= Logger.levels.WARNING)
        console.error(err);
    }

    let msg = String(err.message).replace(/^ *Error: */, '');

    if (level !== Logger.levels.ERROR)
      msg = `Error: ${msg}`;

    this.log(level, module, [msg]);

    if (level <= Logger.levels.WARNING) {
      if (this.stream)
        this.stream.write(err.stack + '\n');
    }
  }

  /**
   * Get the current memory usage.
   * @returns {Object}
   */

  memoryUsage() {
    if (!process.memoryUsage) {
      return {
        total: 0,
        jsHeap: 0,
        jsHeapTotal: 0,
        nativeHeap: 0,
        external: 0
      };
    }

    const mem = process.memoryUsage();

    return {
      total: mb(mem.rss),
      jsHeap: mb(mem.heapUsed),
      jsHeapTotal: mb(mem.heapTotal),
      nativeHeap: mb(mem.rss - mem.heapTotal),
      external: mb(mem.external)
    };
  }

  /**
   * Log the current memory usage.
   * @param {String|null} module
   */

  memory(module) {
    const mem = this.memoryUsage();

    this.log(Logger.levels.DEBUG, module, [
      'Memory: rss=%dmb, js-heap=%d/%dmb native-heap=%dmb',
      mem.total,
      mem.jsHeap,
      mem.jsHeapTotal,
      mem.nativeHeap
    ]);
  }
}

/**
 * Logger Context
 */

class LoggerContext {
  /**
   * Create a logger context.
   * @constructor
   * @ignore
   * @param {Logger} logger
   * @param {String} module
   */

  constructor(logger, module) {
    assert(typeof module === 'string');

    this.logger = logger;
    this.module = module;
  }

  /**
   * Open the logger.
   * @returns {Promise}
   */

  open() {
    return this.logger.open();
  }

  /**
   * Destroy the write stream.
   * @returns {Promise}
   */

  close() {
    return this.logger.close();
  }

  /**
   * Set the log file location.
   * @param {String} filename
   */

  setFile(filename) {
    this.logger.setFile(filename);
  }

  /**
   * Set or reset the log level.
   * @param {String} level
   */

  setLevel(name) {
    this.logger.setLevel(name);
  }

  /**
   * Output a log to the `error` log level.
   * @param {String|Object|Error} err
   * @param {...Object} args
   */

  error(...args) {
    if (this.logger.level < Logger.levels.ERROR)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.ERROR, err);
      return;
    }

    this.log(Logger.levels.ERROR, args);
  }

  /**
   * Output a log to the `warning` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  warning(...args) {
    if (this.logger.level < Logger.levels.WARNING)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.WARNING, err);
      return;
    }

    this.log(Logger.levels.WARNING, args);
  }

  /**
   * Output a log to the `info` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  info(...args) {
    if (this.logger.level < Logger.levels.INFO)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.INFO, err);
      return;
    }

    this.log(Logger.levels.INFO, args);
  }

  /**
   * Output a log to the `debug` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  debug(...args) {
    if (this.logger.level < Logger.levels.DEBUG)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.DEBUG, err);
      return;
    }

    this.log(Logger.levels.DEBUG, args);
  }

  /**
   * Output a log to the `spam` log level.
   * @param {String|Object} obj
   * @param {...Object} args
   */

  spam(...args) {
    if (this.logger.level < Logger.levels.SPAM)
      return;

    const err = args[0];

    if (err instanceof Error) {
      this.logError(Logger.levels.SPAM, err);
      return;
    }

    this.log(Logger.levels.SPAM, args);
  }

  /**
   * Output a log to the desired log level.
   * Note that this bypasses the level check.
   * @param {String} level
   * @param {Object[]} args
   */

  log(level, args) {
    this.logger.log(level, this.module, args);
  }

  /**
   * Create logger context.
   * @param {String} module
   * @returns {LoggerContext}
   */

  context(module) {
    return new LoggerContext(this.logger, module);
  }

  /**
   * Helper to parse an error into a nicer
   * format. Call's `log` internally.
   * @private
   * @param {Number} level
   * @param {Error} err
   */

  logError(level, err) {
    this.logger.logError(level, this.module, err);
  }

  /**
   * Get the current memory usage.
   * @returns {Object}
   */

  memoryUsage() {
    return this.logger.memoryUsage();
  }

  /**
   * Log the current memory usage.
   */

  memory() {
    this.logger.memory(this.module);
  }
}

/**
 * Whether stdout is a tty FD.
 * @const {Boolean}
 */

Logger.HAS_TTY = Boolean(process.stdout && process.stdout.isTTY);

/**
 * Maximum file size.
 * @const {Number}
 * @default
 */

Logger.MAX_FILE_SIZE = 20 << 20;

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
 * Available log levels.
 * @const {String[]}
 * @default
 */

Logger.prefixByVal = [
  'N',
  'E',
  'W',
  'I',
  'D',
  'S'
];

/**
 * Default CSI colors.
 * @const {String[]}
 * @default
 */

Logger.styles = [
  '0',
  '1;31',
  '1;33',
  '94',
  '90',
  '90'
];

/*
 * Default
 */

Logger.global = new Logger();

/*
 * Helpers
 */

function mb(num) {
  return Math.floor(num / (1 << 20));
}

function openStream(filename) {
  return new Promise((resolve, reject) => {
    const stream = fs.createWriteStream(filename, { flags: 'a' });

    const cleanup = () => {
      /* eslint-disable */
      stream.removeListener('error', onError);
      stream.removeListener('open', onOpen);
      /* eslint-enable */
    };

    const onError = (err) => {
      try {
        stream.close();
      } catch (e) {
        ;
      }
      cleanup();
      reject(err);
    };

    const onOpen = () => {
      cleanup();
      resolve(stream);
    };

    stream.once('error', onError);
    stream.once('open', onOpen);
  });
}

function closeStream(stream) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      /* eslint-disable */
      stream.removeListener('error', onError);
      stream.removeListener('close', onClose);
      /* eslint-enable */
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      resolve(stream);
    };

    stream.removeAllListeners('error');
    stream.removeAllListeners('close');
    stream.once('error', onError);
    stream.once('close', onClose);

    stream.close();
  });
}

/*
 * Expose
 */

module.exports = Logger;
