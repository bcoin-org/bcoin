/*!
 * error.js - errors for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

'use strict';

/**
 * ArgError
 */

class ArgError extends TypeError {
  constructor(name, value, expect) {
    let msg;

    if (Array.isArray(expect) && expect.length === 1)
      [expect] = expect;

    if (Array.isArray(expect)) {
      const last = expect.pop();

      msg = `The "${name}" argument must be one of type `
          + `${expect.join(', ')}, or ${last}. `
          + `Received type ${typeof value}`;
    } else {
      msg = `The "${name}" argument must be of type ${expect}. `
          + `Received type ${typeof value}`;
    }

    super(msg);

    this.code = 'ERR_INVALID_ARG_TYPE';
    this.name = `TypeError [${this.code}]`;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * FSError
 */

class FSError extends Error {
  constructor(desc, ...args) {
    let message, syscall, path;

    if (desc == null || typeof desc !== 'object')
      throw new TypeError('invalid arguments for fs error');

    message = desc.message;

    if (args.length === 3)
      [message, syscall, path] = args;
    else if (args.length === 2)
      [syscall, path] = args;
    else if (args.length === 1)
      [syscall] = args;

    let msg = `${desc.code}:`;

    if (message)
      msg += ` ${message},`;

    if (syscall)
      msg += ` ${syscall}`;

    if (path)
      msg += ` ${path}`;

    super(msg);

    this.code = desc.code;
    this.errno = desc.errno;

    if (syscall)
      this.syscall = syscall;

    if (path)
      this.path = path;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, this.constructor);
  }
}

/*
 * Errors
 */

FSError.EPERM = {
  code: 'EPERM',
  errno: -1,
  message: 'operation not permitted'
};

FSError.ENOENT = {
  code: 'ENOENT',
  errno: -2,
  message: 'no such file or directory'
};

FSError.EIO = {
  code: 'EIO',
  errno: -5,
  message: 'I/O error'
};

FSError.EBADF = {
  code: 'EBADF',
  errno: -9,
  message: 'bad file descriptor'
};

FSError.EACCES = {
  code: 'EACCES',
  errno: -13,
  message: 'permission denied'
};

FSError.EEXIST = {
  code: 'EEXIST',
  errno: -17,
  message: 'file already exists'
};

FSError.ENOTDIR = {
  code: 'ENOTDIR',
  errno: -20,
  message: 'not a directory'
};

FSError.EISDIR = {
  code: 'EISDIR',
  errno: -21,
  message: 'file is a directory'
};

/*
 * Expose
 */

exports.ArgError = ArgError;
exports.FSError = FSError;
