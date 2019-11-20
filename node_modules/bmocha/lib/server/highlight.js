/*!
 * highlight.js - highlighter for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

/*
 * Helpers
 */

const rx = (pattern, flags = '') => {
  const str = pattern.replace(/#.*$/gm, '')
                     .replace(/\s/g, '');
  return new RegExp(str, flags);
};

const escape = (str) => {
  str = String(str);
  str = str.replace(/&/g, '&amp;');
  str = str.replace(/</g, '&lt;');
  str = str.replace(/>/g, '&gt;');
  str = str.replace(/"/g, '&quot;');
  str = str.replace(/'/g, '&#39;');
  return str;
};

/*
 * Constants
 */

const types = {
  string: 0,
  comment: 1,
  regex: 2,
  reserved: 3,
  number: 4,
  text: 5
};

const style = [
  'color:#d14',
  'color:#998',
  'color:#009926',
  'color:#000;font-weight:bold',
  'color:#099',
  'color:#000'
];

const rules = [
  // String
  /^(?:"(?:\\"|\\\\|[^"])*"|'(?:\\'|\\\\|[^'])*'|`(?:\\`|\\\\|[^`])*`)/,

  // Comment
  /^(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)/,

  // Regex
  /^\/(?:\\\/|\\\\|[^\/\n])+\/\w*/,

  // Reserved/Special
  rx(`^
    [^\\w]
    (?:
      # Conditional
      if
      | else
      | switch

      # Repeat
      | while
      | for
      | do
      | in
      | of

      # Branch
      | break
      | continue

      # Operator
      | new
      | delete
      | instanceof
      | typeof
      | yield
      | await

      # Type
      | Array
      | ArrayBuffer
      | AsyncFunction
      | Atomics
      | BigInt
      | BigInt64Array
      | BigUint64Array
      | Boolean
      | Buffer
      | DataView
      | Date
      | Error
      | EvalError
      | Float32Array
      | Float64Array
      | Function
      | Generator
      | GeneratorFunction
      | Infinity
      | Int16Array
      | Int32Array
      | Int8Array
      | InternalError
      | Intl
      | JSON
      | Map
      | Math
      | NaN
      | Number
      | Object
      | Promise
      | Proxy
      | RangeError
      | ReferenceError
      | Reflect
      | RegExp
      | SIMD
      | Set
      | SharedArrayBuffer
      | String
      | Symbol
      | SyntaxError
      | TypeError
      | TypedArray
      | URIError
      | Uint16Array
      | Uint32Array
      | Uint8Array
      | Uint8ClampedArray
      | WeakMap
      | WeakSet
      | WebAssembly
      | decodeURI
      | decodeURIComponent
      | encodeURI
      | encodeURIComponent
      | eval
      | isFinite
      | isNaN
      | parseFloat
      | parseInt
      | clearImmediate
      | clearInterval
      | clearTimeout
      | setImmediate
      | setInterval
      | setTimeout

      # Statement
      | return
      | with
      | class
      | extends
      | static

      # Boolean
      | true
      | false

      # Null
      | null
      | undefined
      | void

      # Identifier
      | arguments
      | this
      | var
      | let
      | const
      | async
      | super
      | constructor

      # Label
      | case
      | default

      # Exception
      | try
      | catch
      | finally
      | throw
      | debugger

      # Global
      | global

      # Member
      | console
      | process
      | module
      | exports
      | require
      | __dirname
      | __filename

      # Reserved
      | enum
      | implements
      | interface
      | package
      | private
      | protected
      | public
    )
    (?=[^\\w])
  `),

  // Number
  rx(`^
    [^\\w]
    -?
    (?:
      # Floating Point
      \\d*\\.\\d+ (?:[eE][+\\-]?\\d+)?

      # Binary, Octal, Hex
      | 0[bBoOxX][0-9a-fA-F]+ (?:[eE][+\\-]?\\d+|n)?

      # Integer
      | \\d+ (?:[eE][+\\-]?\\d+|n)?
    )
  `)
];

rules.push((() => {
  const sources = [];

  for (const rule of rules) {
    const src = rule.source.substring(1);
    sources.push(src);
  }

  const all = sources.join('|');

  return rx(`^[\\s\\S]+?(?=${all}|$)`);
})());

/*
 * Highlight
 */

function highlight(text) {
  text = String(text);
  text = ' ' + text;
  text = text.replace(/\r\n/g, '\n');
  text = text.replace(/\r/g, '\n');
  text = text.replace(/\t/g, '  ');

  let out = '';

  while (text.length > 0) {
outer:
    for (let type = 0; type < rules.length; type++) {
      const rule = rules[type];
      const match = rule.exec(text);

      if (!match)
        continue;

      let [str] = match;

      text = text.substring(str.length);

      switch (type) {
        case types.text:
          out += escape(str);
          break outer;
        case types.number:
        case types.reserved:
          out += escape(str[0]);
          str = str.substring(1);
          break;
      }

      out += `<span style="${style[type]}">`
           + escape(str)
           + '</span>';

      break;
    }
  }

  return out.substring(1);
}

/*
 * Expose
 */

module.exports = highlight;
