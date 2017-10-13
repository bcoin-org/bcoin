/*!
 * ffldb.js - flat file database for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const path = require('path');
const co = require('../utils/co');
const layout = require('../blockchain/layout');
const LevelDOWN = require('leveldown');
const LowLevelUp = require('./lowlevelup');
const BlockIO = require('../utils/blockio');
const FileLocation = require('../utils/fileloc');

/**
 * Flat file database for bcoin
 * using a leveldb backend for metadata.
 * @alias module:db.FlatFileDB
 * @constructor
 * @param {String} location
 * @param {Object?} options
 */

function FlatFileDB(location, options) {
  if (!(this instanceof FlatFileDB))
    return new FlatFileDB(location);

  LowLevelUp.call(this, LevelDOWN, location, options);

  this.location = location;
  // TODO: Keep coin, tx in memory using @Treap

  this.blockio = new BlockIO({
    location: path.join(location, 'blocks'),
    maxFileSize: 512 * 1024 * 1024, // 512 MiB
    network: options.network
  });
}

Object.setPrototypeOf(FlatFileDB.prototype, LowLevelUp.prototype);

/**
 * Retrieve a raw block by hash
 * @param {Hash} hash
 * @returns {Promise} - Returns Buffer.
 */

FlatFileDB.prototype.getBlock = async function getBlock(key) {
  try {
    const entry = await this.get(layout.b(key));
    const loc = FileLocation.fromRaw(entry);
    return this.blockio.readBlock(loc);
  } catch (e) {
    throw e;
  }
};

/**
 * Store a raw block
 * @param {Hash} key
 * @param {Buffer} raw block
 */

FlatFileDB.prototype.putBlock = async function putBlock(key, value) {
  try {
    const loc = await this.blockio.writeBlock(value);
    const entry = loc.toRaw();
    this.put(layout.b(key), entry);
  } catch (e) {
    throw e;
  }
};

/**
 * Remove a block by hash
 * @param {Hash} key
 */

FlatFileDB.prototype.delBlock = async function delBlock(key) {
  try {
    const entry = await this.get(layout.b(key));
    if (!entry) {
      return;
    }
    const loc = FileLocation.fromRaw(entry);
    await this.blockio.removeBlock(loc);
    // TODO: delete block keys from metadata db
  } catch (e) {
    throw e;
  }
};

/**
 * Open the database (leveldown method).
 * @param {Object} options
 * @param {Function} callback
 */

FlatFileDB.prototype.open = async function open() {
  await this.blockio.ensure();
  await this.blockio.open();
  await LowLevelUp.prototype.open.call(this);
};

/**
 * Close the database (leveldown method).
 * @param {Function} callback
 */

FlatFileDB.prototype.close = async function close() {
  await this.blockio.close();
  await LowLevelUp.prototype.close.call(this);
};

/*
 * Expose
 */

module.exports = FlatFileDB;
