/*!
 * map.js - hash table for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');

/**
 * Map
 * @alias module:utils.Map
 * @constructor
 */

function Map() {
  if (!(this instanceof Map))
    return new Map();

  this.map = Object.create(null);
  this.size = 0;
}

/**
 * Get map keys.
 * @returns {String[]}
 */

Map.prototype.keys = function keys() {
  return Object.keys(this.map);
};

/**
 * Get map values.
 * @returns {Object[]}
 */

Map.prototype.values = function values() {
  var keys = Object.keys(this.map);
  var values = [];
  var i, key;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    values.push(this.map[key]);
  }

  return values;
};

/**
 * Get item from map.
 * @param {String} key
 * @returns {Object|null}
 */

Map.prototype.get = function get(key) {
  return this.map[key];
};

/**
 * Test whether map has an item.
 * @param {String} key
 * @returns {Boolean}
 */

Map.prototype.has = function has(key) {
  return this.map[key] !== undefined;
};

/**
 * Set a key to value in map.
 * @param {String} key
 * @param {Object} value
 * @returns {Boolean}
 */

Map.prototype.set = function set(key, value) {
  var item = this.map[key];

  assert(value !== undefined);

  this.map[key] = value;

  if (item === undefined) {
    this.size++;
    return true;
  }

  return false;
};

/**
 * Remove an item from map.
 * @param {String} key
 * @returns {Object|null}
 */

Map.prototype.remove = function remove(key) {
  var item = this.map[key];

  if (item === undefined)
    return;

  delete this.map[key];
  this.size--;

  return item;
};

/**
 * Reset the map.
 */

Map.prototype.reset = function reset() {
  this.map = Object.create(null);
  this.size = 0;
};

/**
 * Insert a key.
 * Equivalent to `this.set([key], true)`.
 * @param {String} key
 * @returns {Boolean}
 */

Map.prototype.insert = function insert(key) {
  return this.set(key, true);
};

/*
 * Expose
 */

module.exports = Map;
