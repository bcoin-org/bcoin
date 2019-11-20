/*!
 * util.js - utils for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 *
 * Parts of this software are based on nodejs/node:
 *   Copyright Node.js contributors. All rights reserved.
 *   https://github.com/nodejs/node
 */

/* eslint no-control-regex: "off" */

'use strict';

const inspect = require('./inspect');
const error = require('./error');
const {hasLine, getLine, cleanStack, why} = error;

/*
 * Globals
 */

const {
  Array,
  Error,
  Math,
  Object,
  Promise,
  RegExp,
  String
} = global;

/*
 * Constants
 */

const MAX_SHORT_LENGTH = 10;

const errorStrings = {
  __proto__: null,
  bufferEqual: 'Expected buffers to be strictly equal:',
  deepStrictEqual: 'Expected values to be strictly deep-equal:',
  strictEqual: 'Expected values to be strictly equal:',
  strictEqualObject: 'Expected "actual" to be reference-equal to "expected":',
  deepEqual: 'Expected values to be loosely deep-equal:',
  equal: 'Expected values to be loosely equal:',
  notBufferEqual: 'Expected "actual" to be strictly unequal to:',
  notDeepStrictEqual: 'Expected "actual" not to be strictly deep-equal to:',
  notStrictEqual: 'Expected "actual" to be strictly unequal to:',
  notStrictEqualObject:
    'Expected "actual" not to be reference-equal to "expected":',
  notDeepEqual: 'Expected "actual" not to be loosely deep-equal to:',
  notEqual: 'Expected "actual" to be loosely unequal to:',
  notIdentical: 'Values identical but not reference-equal:'
};

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const BLUE = '\x1b[34m';
const WHITE = '\x1b[39m';

/*
 * Utils
 */

function assert(ok, msg) {
  if (!ok) {
    const err = new Error(msg || 'Assertion failure');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

function get(obj, prop) {
  try {
    return obj[prop];
  } catch (e) {
    return undefined;
  }
}

function has(obj, prop) {
  try {
    return Object.prototype.hasOwnProperty.call(obj, prop);
  } catch (e) {
    return false;
  }
}

function toString(obj) {
  try {
    return String(obj);
  } catch (e) {
    return 'Object';
  }
}

function getJSON(obj, prop) {
  try {
    const value = obj[prop];
    JSON.stringify(value);
    return value;
  } catch (e) {
    return undefined;
  }
}

async function nextTick() {
  return new Promise(r => setImmediate(r));
}

function isObject(error) {
  if (error == null)
    return false;

  return typeof error === 'object'
      || typeof error === 'function';
}

function isPromise(value) {
  if (!isObject(value))
    return false;

  const then = get(value, 'then');

  return typeof then === 'function';
}

function inject(target, values) {
  assert(target && typeof target === 'object');
  assert(values && typeof values === 'object');

  const snapshot = [];

  for (const key of Object.keys(values)) {
    const desc = Object.getOwnPropertyDescriptor(target, key);

    Object.defineProperty(target, key, {
      configurable: true,
      enumerable: true,
      writable: true,
      value: values[key]
    });

    snapshot.push([key, desc]);
  }

  return snapshot;
}

function restore(target, snapshot) {
  assert(target && typeof target === 'object');
  assert(Array.isArray(snapshot));

  for (const [key, desc] of snapshot) {
    if (!desc) {
      delete target[key];
      continue;
    }

    Object.defineProperty(target, key, desc);
  }
}

function stackError(start, msg) {
  const err = new Error(msg);

  if (Error.captureStackTrace) {
    if (typeof start !== 'function')
      start = stackError;

    Error.captureStackTrace(err, start);
  }

  return err;
}

function noop() {}

function getOperator(error) {
  if (!isObject(error))
    return null;

  const name = get(error, 'name');
  const code = get(error, 'code');
  const message = get(error, 'message');
  const operator = get(error, 'operator');
  const expected = get(error, 'expected');

  if (typeof operator !== 'string') {
    const isAssertion = name === 'AssertionError' // browserify
                     || code === 'ERR_ASSERTION'; // node.js

    if (isAssertion && operator === undefined) {
      // The node ~8.0.0 throws and doesNotThrow
      // calls set an undefined operator.
      if (typeof message === 'string') {
        if (message.startsWith('Missing expected exception'))
          return 'throws';

        if (message.startsWith('Got unwanted exception'))
          return 'doesNotThrow';
      }

      // So does the fail call.
      return 'fail';
    }

    // Not an assertion error.
    return null;
  }

  // Normalize loose equal calls.
  if (operator === '==') {
    // Direct assert() call.
    if (expected === true)
      return 'ok';
    return 'equal';
  }

  if (operator === '!=')
    return 'notEqual';

  // Normalize strict equal calls (browserify still does this).
  if (operator === '===')
    return 'strictEqual';

  if (operator === '!==')
    return 'notStrictEqual';

  return operator;
}

/*
 * Text Processing
 */

function indent(str, depth) {
  if (depth == null)
    depth = 0;

  assert(typeof str === 'string');
  assert((depth >>> 0) === depth);

  if (depth === 0)
    return str;

  return str.replace(/^/gm, ' '.repeat(depth * 2));
}

function sanitize(str) {
  str = toString(str);
  str = str.replace(/^\ufeff/, '');
  str = str.replace(/\r\n/g, '\n');
  str = str.replace(/[\r\u2028\u2029]/g, '\n');
  str = str.replace(/\t/g, '  ');
  str = str.replace(/\x1b\[[\?\d;]*[a-zA-Z]/g, '');
  str = str.replace(/[\x00-\x09\x0b-\x1f\x7f]/g, '');
  return str;
}

function strip(str) {
  str = toString(str);
  str = str.replace(/\x1b\[[\?\d;]*[a-zA-Z]/g, '');
  return str;
}

function singlify(str) {
  str = toString(str);

  const index = str.indexOf('\n');

  if (index !== -1)
    str = str.substring(0, index) + '...';

  return str;
}

function trim(str) {
  str = toString(str);
  str = str.replace(/^\n+/, '');
  str = str.replace(/\s+$/, '');
  return str;
}

function escape(str) {
  str = toString(str);
  str = str.replace(/&/g, '&amp;');
  str = str.replace(/</g, '&lt;');
  str = str.replace(/>/g, '&gt;');
  str = str.replace(/"/g, '&quot;');
  str = str.replace(/'/g, '&#39;');
  return str;
}

function clean(func) {
  assert(typeof func === 'function');

  let str = sanitize(func);
  let braceless = false;
  let state = 0;

  if (str.length < 4)
    return '';

  let i = 0;
  let j = str.length;

outer:
  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (state) {
      case 0:
        switch (ch) {
          case 0x3d: // '='
            state = 1;
            break;
          case 0x7b: // '{'
            i += 1;
            break outer;
        }
        break;
      case 1:
        switch (ch) {
          case 0x3e: // '>'
            state = 2;
            break;
          default:
            i = 0;
            break outer;
        }
        break;
      case 2:
        switch (ch) {
          case 0x7b: // '{'
            i += 1;
            break outer;
          default:
            if (ch > 0x20) { // ' '
              braceless = true;
              break outer;
            }
            break;
        }
        break;
    }
  }

  if (!braceless) {
    for (j -= 1; j > i; j--) {
      if (str.charCodeAt(j) === 0x7d) // '}'
        break;
    }
  }

  if (i >= j)
    return '';

  str = str.substring(i, j);
  str = trim(str);

  if (braceless)
    return `${str.trim()};`;

  let tab = false;
  let sp = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch !== 0x09 && ch !== 0x20) // '\t', ' '
      break;

    tab = ch === 0x09; // '\t'
    sp += 1;
  }

  if (sp === 0)
    return str;

  const ch = tab ? '\t' : ' ';
  const re = new RegExp(`^${ch}{${sp}}`, 'gm');

  return str.replace(re, '');
}

/*
 * Error Processing
 */

function isError(error) {
  try {
    return error instanceof Error;
  } catch (e) {
    return false;
  }
}

function toError(error) {
  if (isError(error))
    return error;

  if (isObject(error)) {
    const message = get(error, 'message');

    if (typeof message === 'string')
      return new Error(message);
  }

  const type = inspect.type(error);
  const data = inspect.single(error);

  return new Error(`the ${type} ${data} was thrown, throw an Error :)`);
}

function toMessage(error) {
  assert(isObject(error));

  let name = get(error, 'name');
  let message = get(error, 'message');

  name = sanitize(name || 'Error');
  message = sanitize(message);

  if (get(error, 'uncaught') === true) {
    if (get(error, 'rejection') === true)
      name = `Unhandled ${name}`;
    else
      name = `Uncaught ${name}`;
  }

  name = singlify(name);

  if (get(error, 'generatedMessage') === true) {
    const operator = getOperator(error);

    if (operator == null) {
      message = singlify(message);
    } else if (operator === 'ok') {
      // Better message for `assert(false)`.
      message = 'Assertion failed.';
    } else if (message.includes('\n')) {
      // Drop all the nonsense that node.js adds now.
      message = `${operator} failed.`;
    }
  } else {
    message = singlify(message);
  }

  return `${name}: ${message}`;
}

function toStack(error, fullTrace) {
  if (fullTrace == null)
    fullTrace = false;

  assert(isObject(error));
  assert(typeof fullTrace === 'boolean');

  let stack = get(error, 'stack');

  if (typeof stack !== 'string' || stack === '')
    return '';

  const message = get(error, 'message');

  let index = -1;

  // Remove the message from the stack trace.
  if (typeof message === 'string' && message.length > 0) {
    index = stack.indexOf(message);

    if (index !== -1) {
      index += message.length;
      stack = stack.substring(index + 1);
    }
  }

  stack = sanitize(stack);

  if (!fullTrace) {
    if (index === -1)
      stack = stack.substring(stack.indexOf('\n') + 1);

    stack = cleanStack(stack);
  }

  stack = stack.replace(/^ +/gm, '');
  stack = trim(stack);

  return stack;
}

function errorify(error) {
  if (typeof error === 'string')
    error = new Error(error);

  return toError(error);
}

function stackify(error, fullTrace) {
  const err = toError(error);
  const msg = toMessage(err);
  const stack = toStack(err, fullTrace);

  return msg + '\n' + indent(stack, 2);
}

function jsonify(error, fullTrace) {
  const stack = toStack(error, fullTrace);
  const message = get(error, 'message');
  const generatedMessage = getJSON(error, 'generatedMessage');
  const name = get(error, 'name');
  const type = getJSON(error, 'type');
  const code = getJSON(error, 'code');
  const actual = getJSON(error, 'actual');
  const expected = getJSON(error, 'expected');
  const operator = getJSON(error, 'operator');

  return {
    stack,
    message: sanitize(message),
    generatedMessage,
    name: sanitize(name || 'Error'),
    type,
    code,
    actual,
    expected,
    operator
  };
}

/*
 * Display
 */

function isDisplayable(error) {
  if (!isObject(error))
    return false;

  return get(error, 'display') === true
      && has(error, 'value');
}

function display(value, colors, fullTrace) {
  if (colors == null)
    colors = false;

  if (fullTrace == null)
    fullTrace = false;

  if (isError(value))
    return stackify(value, fullTrace);

  const options = { colors };
  const lines = inspect(value, options).split('\n');

  let blue = '';
  let white = '';

  if (colors) {
    blue = BLUE;
    white = WHITE;
  }

  if (lines.length > 30) {
    lines[26] = `${blue}...${white}`;
    lines.length = 27;
  }

  return lines.join('\n');
}

/*
 * Diff
 */

function isDiffable(error) {
  if (!isObject(error))
    return false;

  if (get(error, 'showDiff') === false)
    return false;

  if (!has(error, 'actual')
      && !has(error, 'expected')) {
    return false;
  }

  let operator = getOperator(error);

  if (operator == null)
    operator = 'strictEqual';

  return errorStrings[operator] != null;
}

function diff(actual, expected, operator, colors) {
  if (typeof operator !== 'string')
    operator = 'strictEqual';

  if (errorStrings[operator] == null)
    operator = 'strictEqual';

  if (colors == null)
    colors = false;

  const options = { sort: true, colors };
  const actualInspected = inspect(actual, options);
  const actualLines = actualInspected.split('\n');
  const expectedLines = inspect(expected, options).split('\n');

  let red = '';
  let green = '';
  let blue = '';
  let white = '';

  if (colors) {
    red = RED;
    green = GREEN;
    blue = BLUE;
    white = WHITE;
  }

  let other = '';
  let res = '';
  let lastPos = 0;
  let end = '';
  let skipped = false;
  let i = 0;
  let indicator = '';

  // In case both values are objects explicitly
  // mark them as not reference equal for the
  // `strictEqual` operator.
  if (operator === 'strictEqual'
      && typeof actual === 'object'
      && typeof expected === 'object'
      && actual !== null
      && expected !== null) {
    operator = 'strictEqualObject';
  }

  // If "actual" and "expected" fit on a single
  // line and they are not strictly equal, check
  // further special handling.
  if (actualLines.length === 1
      && expectedLines.length === 1
      && actualLines[0] !== expectedLines[0]) {
    const actualLine = strip(actualLines[0]);
    const expectedLine = strip(expectedLines[0]);
    const inputLength = actualLine.length + expectedLine.length;

    // If the character length of "actual" and
    // "expected" together is less than
    // MAX_SHORT_LENGTH and if neither is an
    // object and at least one of them is not
    // `zero`, use the strict equal comparison
    // to visualize the output.
    if (inputLength <= MAX_SHORT_LENGTH) {
      if ((typeof actual !== 'object' || actual === null)
          && (typeof expected !== 'object' || expected === null)
          && (actual !== 0 || expected !== 0)) {
        return `${errorStrings[operator]}\n\n`
             + `${actualLines[0]} !== ${expectedLines[0]}`;
      }
    } else if (operator !== 'strictEqualObject') {
      // If the stderr is a tty and the input
      // length is lower than the current
      // columns per line, add a mismatch
      // indicator below the output. If it is
      // not a tty, use a default value of 80
      // characters.
      if (inputLength < 80) {
        while (actualLine[i] === expectedLine[i])
          i += 1;

        // Ignore the first characters.
        if (i > 2) {
          // Add position indicator for the
          // first mismatch in case it is a
          // single line and the input length
          // is less than the column length.
          indicator = `\n  ${' '.repeat(i)}^`;
          i = 0;
        }
      }
    }
  }

  // Remove all ending lines that match (this
  // optimizes the output for readability by
  // reducing the number of total changed
  // lines).
  let a = actualLines[actualLines.length - 1];
  let b = expectedLines[expectedLines.length - 1];

  while (a === b) {
    if (i < 2)
      end = `\n  ${a}${end}`;
    else
      other = a;

    i += 1;

    actualLines.pop();
    expectedLines.pop();

    if (actualLines.length === 0
        || expectedLines.length === 0) {
      break;
    }

    a = actualLines[actualLines.length - 1];
    b = expectedLines[expectedLines.length - 1];
  }

  const maxLines = Math.max(actualLines.length,
                            expectedLines.length);

  // Strict equal with identical objects that
  // are not identical by reference. e.g.
  //   assert.deepStrictEqual({ a: Symbol() },
  //                          { a: Symbol() })
  if (maxLines === 0) {
    // We have to get the result again.
    // The lines were all removed before.
    const actualLines = actualInspected.split('\n');

    // Only remove lines in case it makes sense
    // to collapse those.
    if (actualLines.length > 30) {
      actualLines[26] = `${blue}...${white}`;
      actualLines.length = 27;
    }

    return `${errorStrings.notIdentical}\n\n`
         + `${actualLines.join('\n')}`;
  }

  if (i > 3) {
    end = `\n${blue}...${white}${end}`;
    skipped = true;
  }

  if (other !== '') {
    end = `\n  ${other}${end}`;
    other = '';
  }

  const msg = `${errorStrings[operator]}\n\n`
            + `${green}+ actual${white} `
            + `${red}- expected${white}`;

  const skippedMsg = ` ${blue}...${white} Lines skipped`;

  let printedLines = 0;

  for (i = 0; i < maxLines; i++) {
    // Only extra expected lines exist.
    const cur = i - lastPos;

    if (actualLines.length < i + 1) {
      // If the last diverging line is more
      // than one line above and the current
      // line is at least line three, add some
      // of the former lines and also add dots
      // to indicate skipped entries.
      if (cur > 1 && i > 2) {
        if (cur > 4) {
          res += `\n${blue}...${white}`;
          skipped = true;
        } else if (cur > 3) {
          res += `\n  ${expectedLines[i - 2]}`;
          printedLines += 1;
        }

        res += `\n  ${expectedLines[i - 1]}`;
        printedLines += 1;
      }

      // Mark the current line as the last diverging one.
      lastPos = i;

      // Add the expected line to the cache.
      other += `\n${red}- ${strip(expectedLines[i])}${white}`;
      printedLines += 1;
    } else if (expectedLines.length < i + 1) {
      // Only extra actual lines exist.
      // If the last diverging line is more
      // than one line above and the current
      // line is at least line three, add
      // some of the former lines and also
      // add dots to indicate skipped entries.
      if (cur > 1 && i > 2) {
        if (cur > 4) {
          res += `\n${blue}...${white}`;
          skipped = true;
        } else if (cur > 3) {
          res += `\n  ${actualLines[i - 2]}`;
          printedLines += 1;
        }
        res += `\n  ${actualLines[i - 1]}`;
        printedLines += 1;
      }

      // Mark the current line as the last
      // diverging one.
      lastPos = i;

      // Add the actual line to the result.
      res += `\n${green}+ ${strip(actualLines[i])}${white}`;
      printedLines += 1;
    } else {
      // Lines diverge.
      const expectedLine = expectedLines[i];

      let actualLine = actualLines[i];

      // If the lines diverge, specifically
      // check for lines that only diverge by
      // a trailing comma. In that case it
      // is actually identical and we should
      // mark it as such.
      let divergingLines = false;

      if (actualLine !== expectedLine) {
        divergingLines = !actualLine.endsWith(',')
                      || actualLine.slice(0, -1) !== expectedLine;
      }

      // If the expected line has a trailing
      // comma but is otherwise identical,
      // add a comma at the end of the actual
      // line. Otherwise the output could
      // look weird as in:
      //
      //   [
      //     1       // No comma at the end!
      // +   2
      //   ]
      //
      if (divergingLines
          && expectedLine.endsWith(',')
          && expectedLine.slice(0, -1) === actualLine) {
        divergingLines = false;
        actualLine += ',';
      }

      if (divergingLines) {
        // If the last diverging line is more
        // than one line above and the current
        // line is at least line three, add
        // some of the former lines and also
        // add dots to indicate skipped entries.
        if (cur > 1 && i > 2) {
          if (cur > 4) {
            res += `\n${blue}...${white}`;
            skipped = true;
          } else if (cur > 3) {
            res += `\n  ${actualLines[i - 2]}`;
            printedLines += 1;
          }
          res += `\n  ${actualLines[i - 1]}`;
          printedLines += 1;
        }

        // Mark the current line as the last
        // diverging one.
        lastPos = i;

        // Add the actual line to the result
        // and cache the expected diverging
        // line so consecutive diverging lines
        // show up as +++--- and not +-+-+-.
        res += `\n${green}+ ${strip(actualLine)}${white}`;
        other += `\n${red}- ${strip(expectedLine)}${white}`;
        printedLines += 2;
      } else {
        // Lines are identical.
        // Add all cached information to the
        // result before adding other things
        // and reset the cache.
        res += other;
        other = '';

        // If the last diverging line is
        // exactly one line above or if it
        // is the very first line, add the
        // line to the result.
        if (cur === 1 || i === 0) {
          res += `\n  ${actualLine}`;
          printedLines += 1;
        }
      }
    }

    // Inspected object to big.
    // Show ~20 rows max.
    if (printedLines > 20 && i < maxLines - 2) {
      return `${msg}${skippedMsg}\n`
           + `${res}\n`
           + `${blue}...${white}${other}\n`
           + `${blue}...${white}`;
    }
  }

  return `${msg}${skipped ? skippedMsg : ''}\n`
       + `${res}${other}${end}${indicator}`;
}

/*
 * Find
 */

function isFindable(error) {
  if (!isObject(error))
    return false;

  if (get(error, 'showCode') === false)
    return false;

  if (get(error, 'multiple') === true) {
    const value = get(error, 'value');

    if (!isError(value))
      return false;

    error = value;
  }

  return hasLine(error);
}

function find(error) {
  let line;

  try {
    line = getLine(error);
  } catch (e) {
    return null;
  }

  if (!line || !line.code)
    return null;

  let code = line.code;

  if (line.column !== 0) {
    code += '\n';
    code += ' '.repeat(line.column);
    code += '^';
  }

  return code;
}

/*
 * Show
 */

function isShowable(error) {
  return isDisplayable(error)
      || isDiffable(error)
      || isFindable(error);
}

function show(error, colors, fullTrace) {
  const out = [];

  if (isDisplayable(error)) {
    const value = get(error, 'value');
    const text = display(value, colors, fullTrace);

    out.push(text);
  }

  if (isDiffable(error)) {
    const actual = get(error, 'actual');
    const expected = get(error, 'expected');
    const operator = getOperator(error);
    const text = diff(actual, expected, operator, colors);

    out.push(text);
  }

  if (isFindable(error)) {
    const err = get(error, 'multiple') === true
      ? get(error, 'value')
      : error;

    const text = find(err);

    if (text)
      out.push(text);
  }

  return out.join('\n\n');
}

/*
 * Expose
 */

exports.assert = assert;
exports.get = get;
exports.has = has;
exports.toString = toString;
exports.getJSON = getJSON;
exports.nextTick = nextTick;
exports.isObject = isObject;
exports.isPromise = isPromise;
exports.inject = inject;
exports.restore = restore;
exports.stackError = stackError;
exports.noop = noop;
exports.getOperator = getOperator;
exports.indent = indent;
exports.sanitize = sanitize;
exports.strip = strip;
exports.singlify = singlify;
exports.trim = trim;
exports.escape = escape;
exports.clean = clean;
exports.isError = isError;
exports.toError = toError;
exports.toMessage = toMessage;
exports.toStack = toStack;
exports.errorify = errorify;
exports.stackify = stackify;
exports.jsonify = jsonify;
exports.isDisplayable = isDisplayable;
exports.display = display;
exports.isDiffable = isDiffable;
exports.diff = diff;
exports.isFindable = isFindable;
exports.find = find;
exports.isShowable = isShowable;
exports.show = show;
exports.inspect = inspect;
exports.why = why;
