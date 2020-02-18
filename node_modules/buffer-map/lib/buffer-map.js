/*!
 * buffer-map.js - buffer map for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/buffer-map
 */

/* global SharedArrayBuffer */

'use strict';

const {custom} = require('./custom');

/**
 * Buffer Map
 */

class BufferMap {
  constructor(iterable) {
    this.map = new Map();

    if (iterable != null) {
      for (const [key, value] of iterable)
        this.set(key, value);
    }
  }

  get size() {
    return this.map.size;
  }

  get(key) {
    const item = this.map.get(toBinary(key));

    if (!item)
      return undefined;

    return item.value;
  }

  has(key) {
    return this.map.has(toBinary(key));
  }

  set(key, value) {
    this.map.set(toBinary(key), new BufferItem(key, value));
    return this;
  }

  delete(key) {
    return this.map.delete(toBinary(key));
  }

  clear() {
    this.map.clear();
  }

  [Symbol.iterator]() {
    return this.entries();
  }

  *entries() {
    for (const {key, value} of this.map.values())
      yield [key, value];
  }

  *keys() {
    for (const {key} of this.map.values())
      yield key;
  }

  *values() {
    for (const {value} of this.map.values())
      yield value;
  }

  forEach(func, self) {
    if (typeof func !== 'function')
      throw new TypeError(`${typeof func} is not a function`);

    for (const {key, value} of this.map.values())
      func.call(self, value, key, this);
  }

  toKeys() {
    const out = [];

    for (const {key} of this.map.values())
      out.push(key);

    return out;
  }

  toValues() {
    const out = [];

    for (const {value} of this.map.values())
      out.push(value);

    return out;
  }

  toArray() {
    return this.toValues();
  }

  [custom]() {
    const map = new Map();

    for (const {key, value} of this.map.values())
      map.set(toHex(key), value);

    return map;
  }
}

/**
 * Buffer Set
 */

class BufferSet {
  constructor(iterable) {
    this.map = new Map();

    if (iterable != null) {
      for (const key of iterable)
        this.add(key);
    }
  }

  get size() {
    return this.map.size;
  }

  has(key) {
    return this.map.has(toBinary(key));
  }

  add(key) {
    this.map.set(toBinary(key), key);
    return this;
  }

  delete(key) {
    return this.map.delete(toBinary(key));
  }

  clear() {
    this.map.clear();
  }

  [Symbol.iterator]() {
    return this.keys();
  }

  *entries() {
    for (const key of this.map.values())
      yield [key, key];
  }

  keys() {
    return this.map.values();
  }

  values() {
    return this.map.values();
  }

  forEach(func, self) {
    if (typeof func !== 'function')
      throw new TypeError(`${typeof func} is not a function`);

    for (const key of this.map.values())
      func.call(self, key, key, this);
  }

  toKeys() {
    const out = [];

    for (const key of this.map.values())
      out.push(key);

    return out;
  }

  toValues() {
    return this.toKeys();
  }

  toArray() {
    return this.toKeys();
  }

  [custom]() {
    const set = new Set();

    for (const key of this.map.values())
      set.add(toHex(key));

    return set;
  }
}

/**
 * Buffer Item
 */

class BufferItem {
  constructor(key, value) {
    this.key = key;
    this.value = value;
  }
}

/*
 * Helpers
 */

const HAS_SHARED_ARRAY_BUFFER = typeof SharedArrayBuffer === 'function';

function isArrayBuffer(key) {
  if (key instanceof ArrayBuffer)
    return true;

  if (HAS_SHARED_ARRAY_BUFFER) {
    if (key instanceof SharedArrayBuffer)
      return true;
  }

  return false;
}

function toBuffer(key) {
  if (ArrayBuffer.isView(key))
    return Buffer.from(key.buffer, key.byteOffset, key.byteLength);

  if (isArrayBuffer(key))
    return Buffer.from(key, 0, key.byteLength);

  throw new TypeError('Non-buffer passed to buffer map/set.');
}

function encode(key, encoding) {
  if (!Buffer.isBuffer(key))
    key = toBuffer(key);

  return key.toString(encoding);
}

function toBinary(key) {
  return encode(key, 'binary');
}

function toHex(key) {
  return encode(key, 'hex');
}

/*
 * Expose
 */

exports.BufferMap = BufferMap;
exports.BufferSet = BufferSet;
