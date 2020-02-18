/*!
 * error.js - error line parsing for node.js
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

/* eslint func-name-matching: "off" */
/* eslint no-control-regex: "off" */

'use strict';

const fs = require('fs');
const {relative, resolve, sep} = require('path');

/*
 * Globals
 */

const {
  Array,
  Buffer,
  Error,
  Math,
  String,
  WeakMap,
  gc
} = global;

/*
 * Constants
 */

const WRAPPER_SIZE = 62;
const CWD = process.cwd();
const BIN_PATH = resolve(__dirname, '..', 'bin');
const LIB_PATH = resolve(__dirname, '.');

const map = new WeakMap();

let slab = null;

/*
 * Injection
 */

function hasAPI() {
  const oldPrepareStackTrace = Error.prepareStackTrace;

  let args = [null, null];
  let line, column, filename, str;

  Error.prepareStackTrace = function prepareStackTrace(error, stack) {
    args = [error, stack];
    return 'foobar';
  };

  const error = new Error();
  const stack = String(error.stack);

  Error.prepareStackTrace = oldPrepareStackTrace;

  if (stack !== 'foobar')
    return false;

  if (args[0] !== error)
    return false;

  const calls = args[1];

  if (!Array.isArray(calls))
    return false;

  for (const call of calls) {
    if (!isObject(call))
      return false;
  }

  if (calls.length === 0)
    return false;

  const call = calls[0];

  try {
    line = call.getLineNumber();
    column = call.getColumnNumber();
    filename = call.getFileName();
    str = call.toString();
  } catch (e) {
    return false;
  }

  if ((line >>> 0) !== line)
    return false;

  if ((column >>> 0) !== column)
    return false;

  if (typeof filename !== 'string')
    return false;

  if (typeof str !== 'string')
    return false;

  return true;
}

function inject() {
  if (!hasAPI())
    return null;

  const oldPrepareStackTrace = Error.prepareStackTrace;

  let prepare = oldPrepareStackTrace;

  if (typeof prepare !== 'function')
    prepare = defaultPrepareStackTrace;

  Error.prepareStackTrace = function prepareStackTrace(error, stack) {
    if (isObject(error))
      map.set(error, stack);

    return prepare.call(Error, error, stack);
  };

  return oldPrepareStackTrace;
}

function getCalls(error) {
  let stack = null;

  if (isObject(error)) {
    try {
      stack = error.stack;
    } catch (e) {
      ;
    }
  }

  if (stack != null && map.has(error))
    return map.get(error);

  return [];
}

/*
 * API
 */

function getCall(error) {
  const calls = getCalls(error);

  for (const call of calls) {
    const filename = call.getFileName();

    if (!filename)
      return null;

    // Up until node 8.11.2 (as far as I
    // can tell), captureStackTrace()
    // only hid the caller from the
    // _formatted_ stack, not the actual
    // calls. Search until we find a file
    // which is not an assert.js. Note
    // that we could just check
    // `filename === 'assert.js'`, but
    // we want to filter out 3rd-party
    // assertion libraries as well.
    if (filename.endsWith('assert.js'))
      continue;

    return call;
  }

  return null;
}

function hasLine(error) {
  const call = getCall(error);

  if (!call)
    return false;

  const filename = call.getFileName();

  if (!filename)
    return false;

  const file = resolve(CWD, filename);

  return !file.startsWith(BIN_PATH)
      && !file.startsWith(LIB_PATH);
}

function getLine(error) {
  const call = getCall(error);

  if (!call)
    return null;

  return getLineByCall(call);
}

function getLineByCall(call) {
  let filename = call.getFileName();

  if (!filename)
    return null;

  let line = call.getLineNumber();
  let column = call.getColumnNumber();
  let fd = null;
  let code = null;

  // Stack traces are one-indexed.
  line -= 1;
  column -= 1;

  // Remove node.js wrapper.
  if (line === 0)
    column -= WRAPPER_SIZE;

  try {
    fd = fs.openSync(filename, 'r', 0o666);
    [column, code] = getCode(fd, line, column);
  } catch (e) {
    ;
  } finally {
    if (fd != null)
      fs.closeSync(fd);
  }

  filename = relative(CWD, resolve(CWD, filename));

  return {
    filename,
    line,
    column,
    code
  };
}

function cleanStack(stack) {
  if (typeof stack !== 'string' || stack === '')
    return '';

  const bin = stack.indexOf(` (${BIN_PATH}${sep}`);
  const lib = stack.indexOf(` (${LIB_PATH}${sep}`);

  let index = -1;

  if (bin !== -1 && lib !== -1)
    index = Math.min(bin, lib);
  else if (bin !== -1)
    index = bin;
  else if (lib !== -1)
    index = lib;

  if (index !== -1) {
    while (index >= 0 && stack[index] !== '\n')
      index -= 1;

    if (index === -1)
      index = 0;

    stack = stack.substring(0, index);
  }

  return stack;
}

function why() {
  const hooks = require('async_hooks');
  const active = new Map();

  // Based on:
  // https://github.com/mafintosh/why-is-node-running
  const hook = hooks.createHook({
    init(id, type) {
      if (type === 'TIMERWRAP'
          || type === 'PROMISE') {
        return;
      }

      const err = new Error('');
      const calls = getCalls(err);

      active.set(id, [type, calls]);
    },
    destroy(id) {
      active.delete(id);
    }
  });

  hook.enable();

  return () => {
    if (typeof gc === 'function')
      gc();

    hook.disable();

    const out = [];

    for (const [type, calls] of active.values()) {
      const stacks = [];

      for (let i = 1; i < calls.length; i++) {
        const call = calls[i];
        const filename = call.getFileName();

        if (!filename)
          continue;

        if (!filename.includes(sep))
          continue;

        if (filename.startsWith('internal' + sep))
          continue;

        const file = resolve(CWD, filename);

        if (file.startsWith(BIN_PATH))
          continue;

        if (file.startsWith(LIB_PATH))
          continue;

        stacks.push(getLineByCall(call));
      }

      // Our `await nextTick()` call before calling calls().
      if (stacks.length === 0 && type === 'Immediate')
        continue;

      out.push([type, stacks]);
    }

    return out;
  };
}

/*
 * Parsing
 */

function getCode(fd, line, column) {
  assert(fd != null);
  assert((line >>> 0) === line);
  assert((column >>> 0) === column);

  if (!slab)
    slab = Buffer.allocUnsafe(8 * 1024);

  const stat = fs.fstatSync(fd);

  let start = 0;
  let current = 0;
  let pos = 0;

  // Try to find the offending line.
outer:
  while (pos < stat.size) {
    const length = Math.min(stat.size - pos, slab.length);
    const bytes = fs.readSync(fd, slab, 0, length, pos);

    if (bytes !== length)
      throw new Error('readSync failed.');

    for (let i = 0; i < length; i++) {
      const ch = slab[i];

      if (ch !== 0x0a) // '\n'
        continue;

      if (current === line) {
        pos += i;
        break outer;
      }

      current += 1;
      start = pos + i + 1;
    }

    pos += bytes;
  }

  if (current !== line)
    throw new Error('Could not find line.');

  let length = pos - start;

  // Enough to ensure utf8 decodes correctly
  // given our final string length limit of
  // 80 bytes (5 * 80).
  if (length > 400)
    length = 400;

  const bytes = fs.readSync(fd, slab, 0, length, start);

  if (bytes !== length)
    throw new Error('readSync failed.');

  let begin = -1;
  let end = -1;

  // Eat space and try to stop at a semicolon.
  for (let i = 0; i < length; i++) {
    const ch = slab[i];

    // Eat space and subtract from columns.
    if (begin === -1) {
      if (ch === 0x09 || ch === 0x20) // '\t', ' '
        column -= 1;
      else
        begin = i;
    }

    // Last non-unicode byte.
    if ((ch & 0x80) === 0)
      end = i;

    // Stop when we see a semicolon.
    if (ch === 0x3b) // ';'
      break;
  }

  if (begin === -1)
    begin = 0;

  end += 1;

  // Strange line with
  // unicode characters.
  if (begin > end) {
    begin = end;
    column = 0;
  }

  let code = slab.toString('utf8', begin, end);

  // Sanitize.
  code = code.replace(/^\ufeff/, '');
  code = code.replace(/\t/g, '  ');
  code = code.replace(/[\x00-\x09\x0b-\x1f\x7f]/g, '');

  if (code.length > 80) {
    code = code.substring(0, 76) + ' ...';

    if (column > 77)
      column = 77;
  }

  if (column < 0)
    column = 0;

  if (column >= code.length)
    column = code.length - 1;

  return [column, code];
}

/*
 * Helpers
 */

function assert(ok, msg) {
  if (!ok) {
    const err = new Error(msg || 'Assertion failure');
    Error.captureStackTrace(err, assert);
    throw err;
  }
}

function isObject(error) {
  if (error == null)
    return false;

  return typeof error === 'object'
      || typeof error === 'function';
}

/*
 * Stack Traces
 */

function getName(err) {
  let {name, message} = err;

  if (name === undefined)
    name = 'Error';

  if (message === undefined || message === '')
    return `${name}`;

  return `${name}: ${message}`;
}

function makeName(err) {
  if (!isObject(err))
    return '<error>';

  try {
    return getName(err);
  } catch (e) {
    try {
      return `<error: ${getName(e)}>`;
    } catch (e) {
      return '<error>';
    }
  }
}

function defaultPrepareStackTrace(error, stack) {
  // As far as I can figure, this is the exact
  // behavior of v8's default stack generator.
  let out = makeName(error);

  out += '\n';

  for (const call of stack)
    out += `    at ${call.toString()}\n`;

  return out.slice(0, -1);
}

/*
 * Inject
 */

inject();

/*
 * Expose
 */

exports.getCall = getCall;
exports.hasLine = hasLine;
exports.getLine = getLine;
exports.getLineByCall = getLineByCall;
exports.cleanStack = cleanStack;
exports.why = why;
