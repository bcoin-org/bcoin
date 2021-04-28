/*!
 * browserify.js - browserification for bmocha
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const stream = require('stream');
const {StringDecoder} = require('string_decoder');
const globalRequire = require('../require');

const {
  extname,
  resolve
} = path;

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/*
 * Compilation
 */

async function template(file, values) {
  assert(typeof file === 'string');
  assert(values && typeof values === 'object');

  const path = resolve(__dirname, 'templates', file);

  return preprocess(await read(path), values);
}

async function compile(file, values) {
  assert(typeof file === 'string');
  assert(values == null || typeof values === 'object');

  const input = resolve(__dirname, 'templates', file);

  try {
    return await tryBPKG(input, values);
  } catch (e) {
    if (e.code === 'ERR_NOT_INSTALLED')
      return tryBrowserify(input, values);
    throw e;
  }
}

async function tryBPKG(input, values) {
  assert(typeof input === 'string');
  assert(values == null || typeof values === 'object');

  let bpkg;

  try {
    bpkg = globalRequire('bpkg');
  } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
      const err = new Error('bpkg is not installed!');
      err.code = 'ERR_NOT_INSTALLED';
      throw err;
    }
    throw e;
  }

  return bpkg({
    env: 'browser',
    target: 'cjs',
    input: input,
    ignoreMissing: true,
    plugins: [
      [Plugin, {
        root: input,
        values
      }]
    ]
  });
}

async function tryBrowserify(input, values) {
  assert(typeof input === 'string');
  assert(values == null || typeof values === 'object');

  let browserify;

  try {
    browserify = globalRequire('browserify');
  } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
      const err = new Error('browserify is not installed!');
      err.code = 'ERR_NOT_INSTALLED';
      throw err;
    }
    throw e;
  }

  const options = { ignoreMissing: true };
  const transform = Transform.create(input, values);
  const ctx = browserify(options);

  return new Promise((resolve, reject) => {
    const cb = (err, buf) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(buf.toString('utf8'));
    };

    try {
      ctx.on('error', reject);
      ctx.add(input, options);
      ctx.transform(transform);
      ctx.bundle(cb);
    } catch (e) {
      reject(e);
    }
  });
}

function convert(options) {
  assert(options && typeof options === 'object');
  assert(Array.isArray(options.files));
  assert(Array.isArray(options.requires));

  const requires = [];
  const functions = [];

  for (const file of options.requires) {
    const path = globalRequire.imports.resolve(file);

    requires.push(`require(${JSON.stringify(path)});`);
  }

  for (const file of options.files)
    functions.push(`() => require(${JSON.stringify(file)})`);

  if (requires.length === 0)
    requires.push('// No requires');

  if (functions.length === 0)
    functions.push('// No functions');

  let bfile;
  try {
    bfile = globalRequire.resolve('bfile');
  } catch (e) {
    bfile = 'bfile';
  }

  return {
    requires: requires.join('\n'),
    functions: functions.join(',\n  '),
    bfile: JSON.stringify(bfile),
    options: JSON.stringify({
      allowMultiple: options.allowMultiple,
      allowUncaught: options.allowUncaught,
      asyncOnly: options.asyncOnly,
      backend: options.backend,
      bail: options.bail,
      checkLeaks: options.checkLeaks,
      colors: options.colors,
      columns: options.stream.isTTY ? options.stream.columns : 75,
      console: options.console,
      delay: options.delay,
      diff: options.diff,
      env: options.env,
      exit: options.exit,
      fgrep: options.fgrep,
      forbidOnly: options.forbidOnly,
      forbidPending: options.forbidPending,
      fullTrace: options.fullTrace,
      grep: options.grep ? options.grep.source : null,
      growl: options.growl,
      headless: options.headless,
      invert: options.invert,
      isTTY: Boolean(options.stream.isTTY),
      reporterOptions: options.reporterOptions,
      globals: options.globals,
      reporter: options.reporter,
      retries: options.retries,
      slow: options.slow,
      stream: null,
      swallow: options.swallow,
      timeout: options.timeout,
      timeouts: options.timeouts,
      why: options.why,
      windows: options.windows
    }, null, 2),
    platform: JSON.stringify({
      argv: process.argv,
      constants: fs.constants,
      env: process.env
    }, null, 2)
  };
}

/**
 * Plugin
 */

class Plugin {
  constructor(bundle, options) {
    assert(options && typeof options === 'object');
    assert(typeof options.root === 'string');
    assert(options.values == null || typeof options.values === 'object');

    this.root = resolve(options.root, '.');
    this.values = options.values;
  }

  async compile(module, code) {
    if (!this.values)
      return code;

    if (resolve(module.filename, '.') !== this.root)
      return code;

    return preprocess(code, this.values);
  }
}

/**
 * Transform
 */

class Transform extends stream.Transform {
  constructor(file, root, values) {
    assert(typeof file === 'string');
    assert(typeof root === 'string');
    assert(values == null || typeof values === 'object');

    super();

    this.file = file;
    this.isJS = extname(file) === '.js';
    this.isRoot = resolve(file, '.') === resolve(root, '.');
    this.values = values;
    this.decoder = new StringDecoder('utf8');
    this.code = '';
  }

  static create(root, values) {
    return function transform(file) {
      return new Transform(file, root, values);
    };
  }

  _preprocess(code) {
    if (this.isRoot && this.values)
      code = preprocess(code, this.values);

    if (!this.isJS)
      return code;

    const x = '$1BigInt($2)$3';
    const y = '$1BigInt(\'$2\')$3';

    code = code.replace(/(^|[^\w])(0[Bb][0-1]{1,53})n([^\w]|$)/g, x);
    code = code.replace(/(^|[^\w])(0[Oo][0-7]{1,17})n([^\w]|$)/g, x);
    code = code.replace(/(^|[^\w])(0[Xx][0-9a-fA-F]{1,13})n([^\w]|$)/g, x);
    code = code.replace(/(^|[^\w])([0-9]{1,15})n([^\w]|$)/g, x);

    code = code.replace(/(^|[^\w])(0[Bb][0-1]+)n([^\w]|$)/g, y);
    code = code.replace(/(^|[^\w])(0[Oo][0-7]+)n([^\w]|$)/g, y);
    code = code.replace(/(^|[^\w])(0[Xx][0-9a-fA-F]+)n([^\w]|$)/g, y);
    code = code.replace(/(^|[^\w])([0-9]+)n([^\w]|$)/g, y);

    return code;
  }

  _transform(chunk, encoding, cb) {
    assert(Buffer.isBuffer(chunk));

    this.code += this.decoder.write(chunk);

    cb(null, EMPTY);
  }

  _flush(cb) {
    const code = this._preprocess(this.code);
    const raw = Buffer.from(code, 'utf8');

    this.push(raw);

    cb();
  }
}

/*
 * Helpers
 */

function preprocess(text, values) {
  assert(typeof text === 'string');
  assert(values && typeof values === 'object');

  text = text.replace(/\n?\/\*[^*]*\*\/\n?/g, '');

  return text.replace(/(__[0-9a-zA-Z]+__)/g, (name) => {
    name = name.slice(2, -2).toLowerCase();
    return String(values[name]);
  });
}

async function read(path) {
  return new Promise((resolve, reject) => {
    const cb = (err, res) => {
      if (err)
        reject(err);
      else
        resolve(res);
    };

    try {
      fs.readFile(path, 'utf8', cb);
    } catch (e) {
      reject(e);
    }
  });
}

/*
 * Expose
 */

exports.template = template;
exports.compile = compile;
exports.convert = convert;
