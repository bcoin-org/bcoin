/*!
 * inspect.js - inspect implementation
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

/*
 * Globals
 */

const {
  Array,
  ArrayBuffer,
  Buffer,
  Date,
  Error,
  Map,
  Object,
  RegExp,
  Set,
  SharedArrayBuffer,
  Uint8Array
} = global;

/*
 * Constants
 */

const HAS_SHARED_ARRAY_BUFFER = typeof SharedArrayBuffer === 'function';

const colors = {
  __proto__: null,
  bigint: 33, // yellow
  boolean: 33, // yellow
  date: 35, // magenta
  func: 36, // cyan
  nil: 1, // bold
  number: 33, // yellow
  regexp: 31, // red
  string: 32, // green
  symbol: 32, // green
  undef: 90, // bright black
  unknown: 90 // bright black
};

/*
 * Inspector
 */

class Inspector {
  constructor(options) {
    this.seen = new Set();
    this.single = false;
    this.maxArrayLength = 512;
    this.showHidden = false;
    this.sort = false;
    this.colors = false;
    this.init(options);
  }

  /*
   * Helpers
   */

  init(options) {
    if (typeof options === 'boolean')
      options = { showHidden: options };
    else if (typeof options === 'number')
      options = { maxArrayLength: options };

    if (options == null || typeof options !== 'object')
      options = {};

    if (options.showHidden != null)
      this.showHidden = Boolean(options.showHidden);

    if (options.maxArrayLength != null)
      this.maxArrayLength = options.maxArrayLength >>> 0;

    if (options.sort != null)
      this.sort = Boolean(options.sort);

    if (options.colors != null)
      this.colors = Boolean(options.colors);

    return this;
  }

  color(name, str) {
    if (!this.colors)
      return str;

    return `\x1b[${colors[name] >>> 0}m${str}\x1b[0m`;
  }

  /*
   * Primitives
   */

  bigint(value, prefix) {
    return prefix + this.color('bigint', `${value}n`);
  }

  boolean(value, prefix) {
    return prefix + this.color('boolean', `${value}`);
  }

  nil(value, prefix) {
    return prefix + this.color('nil', 'null');
  }

  number(value, prefix) {
    return prefix + this.color('number', `${value}`);
  }

  string(value, prefix) {
    value = JSON.stringify(value).slice(1, -1);
    value = value.replace(/\\"/g, '"');
    value = value.replace(/'/g, '\\\'');
    return prefix + this.color('string', `'${value}'`);
  }

  symbol(value, prefix) {
    return prefix + this.color('symbol', toString(value));
  }

  undef(value, prefix) {
    return prefix + this.color('undef', 'undefined');
  }

  unknown(value, prefix) {
    return prefix + this.color('unknown', `[${typeof value}]`);
  }

  /*
   * Objects
   */

  *entries(obj, prefix) {
    let total = 0;
    let count = 0;

    if (isArrayLike(obj)) {
      if (!isBuffer(obj) && !isUint8Array(obj)) {
        const length = get(obj, 'length') >>> 0;

        total += length;

        for (let i = 0; i < length; i++) {
          if (count >= this.maxArrayLength)
            break;

          count += 1;

          yield [null, obj[i], false];
        }
      }
    } else if (isSet(obj)) {
      total += get(obj, 'size') >>> 0;

      for (const key of iterate(obj)) {
        if (count >= this.maxArrayLength)
          break;

        count += 1;

        yield [null, key, false];
      }
    } else if (isMap(obj)) {
      total += get(obj, 'size') >>> 0;

      for (const pair of iterate(obj)) {
        let key, value;

        try {
          // Can throw on child class.
          [key, value] = pair;
        } catch (e) {
          continue;
        }

        if (count >= this.maxArrayLength)
          break;

        count += 1;

        key = this.stringify(key, prefix + '  ');
        key = key.substring(prefix.length + 2);

        yield [key, value, false];
      }
    }

    const keys = getKeys(obj, this.showHidden);
    const symbols = getSymbols(obj, this.showHidden);

    if (isError(obj) && !isSimpleError(obj)) {
      if (!keys.includes('name'))
        keys.push('name');

      if (!keys.includes('message'))
        keys.push('message');
    }

    if (this.sort) {
      keys.sort();
      symbols.sort(symbolCompare);
    }

    for (let i = 0; i < keys.length; i++)
      yield this.property(obj, keys[i]);

    for (let i = 0; i < symbols.length; i++)
      yield this.property(obj, symbols[i]);

    if (count < total)
      yield [null, `... ${total - count} more items`, true];
  }

  property(obj, key) {
    let desc = getOwnPropertyDescriptor(obj, key);

    if (desc == null) {
      desc = {
        value: get(obj, key),
        get: null,
        set: null
      };
    }

    if (typeof key === 'symbol') {
      key = `[${this.symbol(key, '')}]`;
    } else {
      key = !isKey(key)
        ? this.string(key, '')
        : key;
    }

    // Might be an evil proxy.
    const get_ = get(desc, 'get');
    const set_ = get(desc, 'set');

    if (get_ && set_)
      return [key, this.color('func', '[Getter/Setter]'), true];

    if (get_)
      return [key, this.color('func', '[Getter]'), true];

    if (set_)
      return [key, this.color('func', '[Setter]'), true];

    return [key, get(desc, 'value'), false];
  }

  key(value, prefix) {
    this.single = true;
    try {
      return this.stringify(value, prefix);
    } finally {
      this.single = false;
    }
  }

  values(name, brackets, obj, prefix) {
    if (this.single)
      return name || `[${objectName(obj)}]`;

    const [open, close] = brackets;

    let str = prefix;
    let has = false;

    if (name)
      str += name + ' ';

    str += open;
    str += '\n';

    this.seen.add(obj);

    for (const [key, value, raw] of this.entries(obj, prefix)) {
      let line = value;

      if (!raw) {
        line = this.stringify(value, prefix + '  ');
        line = line.substring(prefix.length + 2);
      }

      str += prefix + '  ';

      if (key != null)
        str += key + ': ';

      str += line;
      str += ',';
      str += '\n';

      has = true;
    }

    this.seen.delete(obj);

    if (has) {
      str = str.slice(0, -2);
      str += '\n';
      str += prefix;
      str += close;
    } else {
      if (name) {
        str = prefix + name;
      } else {
        str = str.slice(0, -1);
        str += close;
      }
    }

    return str;
  }

  args(obj, prefix) {
    return this.values('[Arguments]', '[]', obj, prefix);
  }

  array(obj, prefix) {
    return this.values(null, '[]', obj, prefix);
  }

  arrayBuffer(obj, prefix) {
    let buffer;

    try {
      buffer = Buffer.from(obj, 0, obj.byteLength);
    } catch (e) {
      return this.object(obj, prefix);
    }

    const name = `[${objectType(obj)}: ${toHex(buffer, this.maxArrayLength)}]`;

    return this.values(name, '{}', obj, prefix);
  }

  buffer(obj, prefix) {
    let name;

    try {
      name = `[Buffer: ${toHex(obj, this.maxArrayLength)}]`;
    } catch (e) {
      return this.object(obj, prefix);
    }

    return this.values(name, '{}', obj, prefix);
  }

  circular(obj, prefix) {
    return prefix + this.color('func', '[Circular]');
  }

  date(obj, prefix) {
    let name;

    try {
      name = `[${obj.toISOString()}]`;
    } catch (e) {
      name = `[${toString(obj)}]`;
    }

    name = this.color('date', name);

    return this.values(name, '{}', obj, prefix);
  }

  error(obj, prefix) {
    let name;

    if (isSimpleError(obj)) {
      try {
        name = `[${obj.name}: ${obj.message}]`;
      } catch (e) {
        ;
      }
    }

    if (name == null)
      name = `[${objectName(obj)}]`;

    return this.values(name, '{}', obj, prefix);
  }

  func(obj, prefix) {
    let name = `[${funcName(obj)}]`;

    name = this.color('func', name);

    return this.values(name, '{}', obj, prefix);
  }

  map(obj, prefix) {
    return this.values('[Map]', '{}', obj, prefix);
  }

  object(obj, prefix) {
    let name = `[${objectName(obj)}]`;

    if (name === '[Object]')
      name = null;

    return this.values(name, '{}', obj, prefix);
  }

  regexp(obj, prefix) {
    const name = this.color('regexp', toString(obj));
    return this.values(name, '{}', obj, prefix);
  }

  set(obj, prefix) {
    return this.values('[Set]', '[]', obj, prefix);
  }

  uint8array(obj, prefix) {
    let buffer;

    try {
      buffer = Buffer.from(obj.buffer,
                           obj.byteOffset,
                           obj.byteLength);
    } catch (e) {
      return this.object(obj, prefix);
    }

    const name = `[Uint8Array: ${toHex(buffer, this.maxArrayLength)}]`;

    return this.values(name, '{}', obj, prefix);
  }

  view(obj, prefix) {
    const name = `[${objectName(obj)}]`;
    return this.values(name, '[]', obj, prefix);
  }

  /*
   * Stringification
   */

  stringify(value, prefix = '') {
    if (this.seen.has(value))
      return this.circular(value, prefix);

    switch (typeof value) {
      case 'undefined':
        return this.undef(value, prefix);
      case 'object':
        if (value === null)
          return this.nil(value, prefix);

        if (isArguments(value))
          return this.args(value, prefix);

        if (isArray(value))
          return this.array(value, prefix);

        if (isMap(value))
          return this.map(value, prefix);

        if (isSet(value))
          return this.set(value, prefix);

        if (isBuffer(value))
          return this.buffer(value, prefix);

        if (isDate(value))
          return this.date(value, prefix);

        if (isRegExp(value))
          return this.regexp(value, prefix);

        if (isError(value))
          return this.error(value, prefix);

        if (isArrayBuffer(value))
          return this.arrayBuffer(value, prefix);

        if (isUint8Array(value))
          return this.uint8array(value, prefix);

        if (isView(value))
          return this.view(value, prefix);

        return this.object(value, prefix);
      case 'boolean':
        return this.boolean(value, prefix);
      case 'number':
        return this.number(value, prefix);
      case 'string':
        return this.string(value, prefix);
      case 'symbol':
        return this.symbol(value, prefix);
      case 'function':
        return this.func(value, prefix);
      case 'bigint':
        return this.bigint(value, prefix);
      default:
        return this.unknown(value, prefix);
    }
  }
}

/*
 * API
 */

function inspect(value, options) {
  const inspector = new Inspector(options);
  try {
    return inspector.stringify(value, '');
  } catch (e) {
    // Last line of defense.
    return `[${objectType(value)}]`;
  }
}

inspect.log = function log(value, options) {
  console.log(inspect(value, options));
};

inspect.single = function single(value, options) {
  const inspector = new Inspector(options);
  try {
    return inspector.key(value, '');
  } catch (e) {
    // Last line of defense.
    return `[${objectType(value)}]`;
  }
};

inspect.type = function type(value) {
  const type = typeof value;

  if (type === 'object')
    return objectType(value).toLowerCase();

  return type;
};

/*
 * Helpers
 */

function objectString(obj) {
  if (obj === undefined)
    return '[object Undefined]';

  if (obj === null)
    return '[object Null]';

  try {
    // Not sure if this can throw.
    return Object.prototype.toString.call(obj);
  } catch (e) {
    return '[object Object]';
  }
}

function objectType(obj) {
  return objectString(obj).slice(8, -1);
}

function objectName(value) {
  const type = objectType(value);

  if (value == null)
    return type;

  if (type !== 'Object' && type !== 'Error')
    return type;

  const ctor = get(value, 'constructor');

  if (ctor == null)
    return type;

  const name = get(ctor, 'name');

  if (typeof name !== 'string' || name.length === 0)
    return type;

  return name;
}

function funcName(func) {
  const name = get(func, 'name');

  if (typeof name !== 'string' || name.length === 0)
    return 'Function';

  return `Function: ${name}`;
}

function isKey(key) {
  return key.length > 0 && !/[^\$\w]/.test(key) && !/^\d/.test(key);
}

function symbolCompare(a, b) {
  return String(a).localeCompare(String(b));
}

function isArguments(obj) {
  return objectString(obj) === '[object Arguments]';
}

function isArray(obj) {
  try {
    return Array.isArray(obj);
  } catch (e) {
    return false;
  }
}

function isArrayBuffer(obj) {
  if (HAS_SHARED_ARRAY_BUFFER) {
    if (instanceOf(obj, SharedArrayBuffer))
      return true;
  }

  return instanceOf(obj, ArrayBuffer);
}

function isArrayLike(obj) {
  return isArray(obj) || isView(obj) || isArguments(obj);
}

function isBuffer(obj) {
  try {
    return Buffer.isBuffer(obj);
  } catch (e) {
    return false;
  }
}

function isDate(obj) {
  return instanceOf(obj, Date);
}

function isError(obj) {
  return instanceOf(obj, Error);
}

function isSimpleError(obj) {
  if (!isError(obj))
    return false;

  const name = get(obj, 'name');
  const message = get(obj, 'message');

  return typeof name === 'string'
      && name.length > 0
      && !name.includes('\n')
      && typeof message === 'string'
      && message.length > 0
      && !message.includes('\n');
}

function isMap(obj) {
  return instanceOf(obj, Map);
}

function isRegExp(obj) {
  return instanceOf(obj, RegExp);
}

function isSet(obj) {
  return instanceOf(obj, Set);
}

function isUint8Array(obj) {
  return instanceOf(obj, Uint8Array);
}

function isView(obj) {
  try {
    return ArrayBuffer.isView(obj);
  } catch (e) {
    return false;
  }
}

function isIndex(key, length) {
  return /^\d+$/.test(key) && (key >>> 0) < length;
}

function getKeys(obj, showHidden) {
  if (isView(obj))
    return [];

  const keys = showHidden
    ? getOwnPropertyNames(obj)
    : getOwnKeys(obj);

  // Defend against weird proxy.
  if (!isArray(keys))
    return [];

  if (isArrayLike(obj)) {
    const length = get(obj, 'length') >>> 0;
    return keys.filter(key => !isIndex(key, length));
  }

  return keys;
}

function getSymbols(obj, showHidden) {
  const symbols = getOwnPropertySymbols(obj);

  // Defend against weird proxy.
  if (!isArray(symbols))
    return [];

  if (showHidden)
    return symbols;

  const out = [];

  for (const symbol of symbols) {
    if (isEnumerable(obj, symbol))
      out.push(symbol);
  }

  return out;
}

function toHex(buf, max) {
  if (buf.length > max) {
    const hex = buf.toString('hex', 0, max);
    const left = buf.length - max;

    return  `${hex} ... ${left} more bytes`;
  }

  return buf.toString('hex');
}

/*
 * Safety
 */

function instanceOf(obj, ctor) {
  // Can throw on proxy.
  try {
    return obj instanceof ctor;
  } catch (e) {
    return false;
  }
}

function get(obj, prop) {
  // Can throw on proxy/getter.
  try {
    return obj[prop];
  } catch (e) {
    return undefined;
  }
}

function getOwnKeys(obj) {
  // Can throw on proxy.
  try {
    return Object.keys(obj);
  } catch (e) {
    return [];
  }
}

function getOwnPropertyDescriptor(obj, prop) {
  // Can throw on proxy.
  try {
    return Object.getOwnPropertyDescriptor(obj, prop);
  } catch (e) {
    return undefined;
  }
}

function isEnumerable(obj, prop) {
  const desc = getOwnPropertyDescriptor(obj, prop);

  if (!desc)
    return false;

  return get(desc, 'enumerable') === true;
}

function getOwnPropertyNames(obj) {
  // Can throw on proxy.
  try {
    return Object.getOwnPropertyNames(obj);
  } catch (e) {
    return [];
  }
}

function getOwnPropertySymbols(obj) {
  // Can throw on proxy.
  try {
    return Object.getOwnPropertySymbols(obj);
  } catch (e) {
    return [];
  }
}

function* iterate(obj) {
  // Can throw on child class.
  try {
    for (const item of obj)
      yield item;
  } catch (e) {
    ;
  }
}

function toString(obj) {
  // Can throw on null proto
  // and who knows what else.
  try {
    return String(obj);
  } catch (e) {
    return 'Object';
  }
}

/*
 * Expose
 */

module.exports = inspect;
