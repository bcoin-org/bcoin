/*!
 * error.js - error line parsing for node.js
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

/* global XMLHttpRequest */
/* eslint no-control-regex: "off" */

'use strict';

/*
 * Globals
 */

const {
  Error,
  String
} = global;

/*
 * Constants
 */

const PROTOCOL = global.location.protocol;
const PORT = global.location.port;
const URL = `${PROTOCOL}//localhost:${PORT}/index.js`;

let lines = null;
let start = -1;

/*
 * API
 */

function getCall(error) {
  if (!isObject(error))
    return null;

  let stack = null;
  let message = null;
  let index = -1;

  try {
    stack = error.stack;
  } catch (e) {
    return null;
  }

  if (typeof stack !== 'string' || stack === '')
    return null;

  try {
    message = error.message;
  } catch (e) {
    ;
  }

  // Remove the message from the stack trace.
  if (typeof message === 'string' && message.length > 0) {
    index = stack.indexOf(message);

    if (index !== -1) {
      index += message.length;
      stack = stack.substring(index + 1);
    }
  }

  if (index === -1)
    stack = stack.substring(stack.indexOf('\n') + 1);

  const m = / \(([^\)]+):(\d+):(\d+)\)/.exec(stack);

  if (!m)
    return null;

  const filename = m[1];
  const line = m[2] >>> 0;
  const column = m[3] >>> 0;

  if (line === 0 || column === 0)
    return null;

  return {
    getFileName: () => filename,
    getLineNumber: () => line,
    getColumnNumber: () => column
  };
}

function hasLine(error) {
  const call = getCall(error);

  if (!call)
    return false;

  const filename = call.getFileName();

  if (!filename)
    return false;

  if (filename !== URL)
    return false;

  const line = call.getLineNumber() - 1;
  const start = getStart();

  if (start === -1)
    return true;

  return line > start;
}

function getLine(error) {
  const call = getCall(error);

  if (!call)
    return null;

  return getLineByCall(call);
}

function getLineByCall(call) {
  const filename = call.getFileName();

  if (!filename)
    return null;

  let line = call.getLineNumber();
  let column = call.getColumnNumber();

  // Stack traces are one-indexed.
  line -= 1;
  column -= 1;

  const lines = getLines();

  if (line >= lines.length)
    return null;

  let code = lines[line];

  for (let i = 0; i < code.length; i++) {
    const ch = code.charCodeAt(i);

    if (ch !== 0x09 && ch !== 0x20) {
      code = code.substring(i);
      break;
    }

    column -= 1;
  }

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

  const start = getStart();

  if (start === -1)
    return stack;

  const lines = stack.split('\n');
  const out = [];

  for (const line of lines) {
    let index = line.indexOf(` (${URL}:`);
    let str = line;

    if (index === -1) {
      out.push(line);
      continue;
    }

    index += 2 + URL.length + 1;
    str = str.substring(index);

    const end = str.indexOf(')');

    if (end === -1) {
      out.push(line);
      continue;
    }

    str = str.substring(0, end);

    const parts = str.split(':');

    if (parts.length !== 2) {
      out.push(line);
      continue;
    }

    const lineNum = parts[0] >>> 0;

    if (lineNum !== 0 && lineNum < start)
      break;

    out.push(line);
  }

  return out.join('\n');
}

function why() {
  return () => [];
}

/*
 * Helpers
 */

function isObject(error) {
  if (error == null)
    return false;

  return typeof error === 'object'
      || typeof error === 'function';
}

function getFile() {
  if (lines)
    return [lines, start];

  if (PROTOCOL === 'file:')
    throw new Error('Cannot request file URL.');

  const xhr = new XMLHttpRequest();

  xhr.open('GET', '/index.js', false);
  xhr.send(null);

  const status = xhr.status >>> 0;

  if (status < 200 || status >= 400)
    throw new Error(`Status code: ${status}`);

  const text = String(xhr.responseText || '');

  lines = text.split('\n');

  // Normally we would search for
  // some kind of code marker to
  // see where the bmocha code ends
  // and the tests begin, but
  // browserify doesn't seem to be
  // ordering the modules in any
  // predictable manner. Disable
  // for now.
  start = -1;

  return [lines, start];
}

function getLines() {
  try {
    return getFile()[0];
  } catch (e) {
    return [];
  }
}

function getStart() {
  return -1;
}

/*
 * Expose
 */

exports.getCall = getCall;
exports.hasLine = hasLine;
exports.getLine = getLine;
exports.getLineByCall = getLineByCall;
exports.cleanStack = cleanStack;
exports.why = why;
