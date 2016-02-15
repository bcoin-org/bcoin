/**
 * db.js - db object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var levelup = require('levelup');
var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var fs = bcoin.fs;

/**
 * BlockDB
 */

function BlockDB(options) {
  var self = this;

  if (!(this instanceof BlockDB))
    return new BlockDB(options);

  EventEmitter.call(this);

  if (!options)
    options = {};

  if (typeof options === 'string')
    options = { file: options };

  if (!options.file)
    options.file = process.env.HOME + '/bcoin-server-' + network.type + '.ldb';

  this.options = options;
  this.parser = new bcoin.protocol.parser();
  this.data = new BlockData();
  this.index = levelup(options.file, {
    keyEncoding: 'ascii',
    valueEncoding: 'binary',
    cacheSize: 16 * 1024 * 1024
  });
}

inherits(BlockDB, EventEmitter);

BlockDB.prototype.get = function get(key, options, callback) {
  return this.index.get(key, options, callback);
};

BlockDB.prototype.put = function put(key, value, options, callback) {
  return this.index.put(key, value, options, callback);
};

BlockDB.prototype.del = function del(key, options, callback) {
  return this.index.del(key, options, callback);
};

BlockDB.prototype.batch = function batch() {
  return this.index.batch();
};

BlockDB.prototype.createOffset = function createOffset(size, offset, height) {
  var buf = new Buffer(16);
  utils.writeU32(buf, size, 0);
  utils.writeU64(buf, offset, 4);
  utils.writeU32(buf, height, 12);
  return buf;
};

BlockDB.prototype.parseOffset = function parseOffset(data, height) {
  return {
    size: utils.readU32(data, 0),
    offset: utils.readU64(data, 4).toNumber(),
    height: utils.readU32(data, 12)
  };
};

BlockDB.prototype.saveBlock = function saveBlock(block, callback) {
  var self = this;
  var batch = this.index.batch();

  this.data.saveAsync(block._raw, function(err, data) {
    if (err)
      return callback(err);

    var blockOffset = self.createOffset(data.size, data.offset, block.height);

    var batch = self.index.batch();
    batch.put('b/b/' + block.hash('hex'), blockOffset);
    batch.put('b/h/' + block.height, blockOffset);

    block.txs.forEach(function(tx, i) {
      var txOffset = self.createOffset(
        tx._size, data.offset + tx._offset,
        block.height);

      var hash = tx.hash('hex');
      var uniq = {};

      batch.put('t/t/' + hash, txOffset);

      tx.inputs.forEach(function(input) {
        var type = input.getType();
        var address = input.getAddress();
        var uaddr;

        if (type === 'pubkey' || type === 'multisig')
          address = null;

        uaddr = address;

        if (uaddr) {
          if (!uniq[uaddr])
            uniq[uaddr] = true;
          else
            uaddr = null;
        }

        if (uaddr)
          batch.put('t/a/' + uaddr + '/' + hash, txOffset);

        if (address)
          batch.del('u/a/' + address + '/' + input.prevout.hash + '/' + input.prevout.index);

        batch.del('u/t/' + input.prevout.hash + '/' + input.prevout.index);
      });

      tx.outputs.forEach(function(output) {
        var type = output.getType();
        var address = output.getAddress();
        var uaddr;

        if (type === 'pubkey' || type === 'multisig')
          address = null;

        uaddr = address;

        if (uaddr) {
          if (!uniq[uaddr])
            uniq[uaddr] = true;
          else
            uaddr = null;
        }

        var coinOffset = self.createOffset(
          output._size,
          data.offset + tx._offset + output._offset,
          block.height);

        if (uaddr)
          batch.put('t/a/' + uaddr + '/' + hash, txOffset);

        if (address)
          batch.put('u/a/' + address + '/' + hash + '/' + i, coinOffset);

        batch.put('u/t/' + hash + '/' + i, coinOffset);
      });
    });

    batch.write(callback);
  });
};

BlockDB.prototype.removeBlock = function removeBlock(hash, callback) {
  var self = this;

  this.getBlock(hash, function(err, block) {
    var batch, pending;

    if (err)
      return callback(err);

    if (!block)
      return callback();

    pending = block.txs.length;

    batch = self.index.batch();

    batch.del('b/b/' + hash);
    batch.del('b/h/' + block.height);

    function done() {
      batch.write(function(err) {
        if (err)
          return callback(err);
        return callback(null, block);
      });
    }

    if (!pending)
      return done();

    block.txs.forEach(function(tx, i) {
      var hash = tx.hash('hex');
      var uniq = {};

      batch.del('t/t/' + hash);

      self.fillTX2(tx, function(err) {
        if (err)
          return callback(err);

        tx.inputs.forEach(function(input) {
          var type = input.getType();
          var address = input.getAddress();
          var uaddr;

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          uaddr = address;

          if (uaddr) {
            if (!uniq[uaddr])
              uniq[uaddr] = true;
            else
              uaddr = null;
          }

          if (uaddr)
            batch.del('t/a/' + uaddr + '/' + hash);

          var coinOffset = self.createOffset(
            input.output._size,
            block._fileOffset + tx._offset + input.output._offset,
            block.height);

          if (address)
            batch.put('u/a/' + address + '/' + input.output.hash + '/' + input.output.index, coinOffset);

          batch.put('u/t/' + input.output.hash + '/' + input.output.index, coinOffset);
        });

        tx.outputs.forEach(function(output) {
          var type = output.getType();
          var address = output.getAddress();
          var uaddr;

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          uaddr = address;

          if (uaddr) {
            if (!uniq[uaddr])
              uniq[uaddr] = true;
            else
              uaddr = null;
          }

          if (uaddr)
            batch.del('t/a/' + uaddr + '/' + hash);

          if (address)
            batch.del('u/a/' + address + '/' + hash + '/' + i);

          batch.del('u/t/' + hash + '/' + i);
        });

        if (!--pending)
          done();
      });
    });
  });
};

BlockDB.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;
  var pending = tx.inputs.length;

  tx.inputs.forEach(function(input) {
    if (input.output) {
      if (!--pending)
        callback(null, tx);
      return;
    }
    self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
      if (err)
        return callback(err);

      if (coin)
        input.output = coin;

      if (!--pending)
        callback(null, tx);
    });
  });
};

BlockDB.prototype.fillTX2 = function fillTX2(tx, callback) {
  var self = this;
  var pending = tx.inputs.length;

  tx.inputs.forEach(function(input) {
    if (input.output) {
      if (!--pending)
        callback(null, tx);
      return;
    }
    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return callback(err);

      if (tx)
        input.output = bcoin.coin(tx, input.prevout.index);

      if (!--pending)
        callback(null, tx);
    });
  });
};

BlockDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, callback) {
  var self = this;
  var coins = [];
  var pending;

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  var pending = addresses.length;

  addresses.forEach(function(address) {
    self._getCoinsByAddress(address, function(err, coin) {
      if (err)
        return callback(err);

      if (coin)
        coins = coins.concat(coin);

      if (!--pending)
        return callback(null, coins);
    });
  });
};

BlockDB.prototype._getCoinsByAddress = function _getCoinsByAddress(address, callback) {
  var self = this;
  var pending = 0;
  var coins = [];
  var done = false;

  callback = utils.asyncify(callback);

  var stream = this.index.createReadStream({
    start: 'u/a/' + address,
    end: 'u/a/' + address + '~'
  });

  stream.on('data', function(data) {
    var parts = data.key.split('/').slice(3);
    var hash = parts[0];
    var index = +parts[1];
    var record = self.parseOffset(data.value);
    pending++;
    self.data.getAsync(record.size, record.offset, function(err, data) {
      var coin;

      if (err)
        return callback(err);

      if (data) {
        data = self.parser.parseTXOut(data);
        coin = bcoin.coin({
          version: 1,
          hash: hash,
          index: index,
          height: record.height,
          script: data.script,
          value: data.value,
          spent: false
        });
        coins.push(coin);
      }

      pending--;

      if (done) {
        if (!pending)
          return callback(null, coins);
      }
    });
  });

  stream.on('error', function(err) {
    return callback(err);
  });

  stream.on('end', function() {
    done = true;
    if (!pending)
      return callback(null, coins);
  });
};

BlockDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var self = this;
  var id = 'u/t/' + hash + '/' + index;

  this.index.get(id, { valueEncoding: 'binary' }, function(err, record) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    record = self.parseOffset(record);

    self.data.getAsync(record.size, record.offset, function(err, data) {
      var coin;

      if (err)
        return callback(err);

      if (data) {
        data = self.parser.parseTXOut(data);
        coin = bcoin.coin({
          version: 1,
          hash: hash,
          index: index,
          height: record.height,
          script: data.script,
          value: data.value,
          spent: false
        });
      }

      return callback(null, coin);
    });
  });
};

BlockDB.prototype.getTXByAddress = function getTXByAddress(addresses, callback) {
  var self = this;
  var txs = [];
  var pending;

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  pending = addresses.length;

  if (!pending)
    return callback(null, txs);

  addresses.forEach(function(address) {
    self._getTXByAddress(address, function(err, tx) {
      if (err)
        return callback(err);

      if (tx)
        txs = txs.concat(tx);

      if (!--pending)
        return callback(null, txs);
    });
  });
};

BlockDB.prototype._getTXByAddress = function _getTXByAddress(address, callback) {
  var self = this;
  var pending = 0;
  var txs = [];
  var done = false;
  var stream;

  callback = utils.asyncify(callback);

  stream = this.index.createReadStream({
    start: 't/a/' + address,
    end: 't/a/' + address + '~'
  });

  stream.on('data', function(data) {
    var parts = data.key.split('/').slice(3);
    var hash = parts[0];
    var record = self.parseOffset(data.value);

    pending++;

    self.data.getAsync(record.size, record.offset, function(err, data) {
      var tx, entry;

      if (err)
        return callback(err);

      if (data) {
        tx = bcoin.tx.fromRaw(data);
        entry = bcoin.chain.global.db.get(record.height);
        tx.height = record.height;
        tx.ts = entry.ts;
        tx.block = entry.hash;
        txs.push(tx);
      }

      pending--;

      if (done) {
        if (!pending)
          return callback(null, txs);
      }
    });
  });

  stream.on('error', function(err) {
    return callback(err);
  });

  stream.on('end', function() {
    done = true;
    if (!pending)
      return callback(null, txs);
  });
};

BlockDB.prototype.getTX = function getTX(hash, callback) {
  var self = this;
  var id = 't/t/' + hash;

  this.index.get(id, { valueEncoding: 'binary' }, function(err, record) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    record = self.parseOffset(record);

    self.data.getAsync(record.size, record.offset, function(err, data) {
      var tx, entry;

      if (err)
        return callback(err);

      if (data) {
        tx = bcoin.tx.fromRaw(data);
        entry = bcoin.chain.global.db.get(record.height);
        tx.height = record.height;
        tx.ts = entry.ts;
        tx.block = entry.hash;
      }

      return callback(null, tx);
    });
  });
};

BlockDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var id = 'b/b/' + value;

  if (typeof hash === 'number')
    id = 'b/h/' + value;

  this.index.get(id, { valueEncoding: 'binary' }, function(err, record) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    record = self.parseOffset(record);

    self.data.getAsync(record.size, record.offset, function(err, data) {
      var block;

      if (err)
        return callback(err);

      if (data) {
        block = bcoin.block.fromRaw(data);
        block._fileOffset = record.offset;
        block.height = record.height;
      }

      return callback(null, block);
    });
  });
};

/**
 * BlockData
 */

function BlockData(chain, options) {
  if (!(this instanceof BlockData))
    return new BlockData(chain, options);

  if (!options)
    options = {};

  this.options = options;
  this.chain = chain;
  this.file = options.file;

  if (!this.file)
    this.file = process.env.HOME + '/bcoin-' + network.type + '.data';

  this._queue = [];
  this._cache = {};
  this._bufferPool = { used: {} };
  this.size = 0;
  this.fd = null;

  this._init();
}

BlockData.prototype._init = function _init() {
  if (!bcoin.fs) {
    utils.debug('`fs` module not available. Falling back to ramdisk.');
    this.ramdisk = bcoin.ramdisk(new Buffer([]), 40 * 1024 * 1024);
    return;
  }

  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists()) {
    fs.writeFileSync(this.file, new Buffer(0));
    fs.truncateSync(this.file, 0);
  }

  this.size = this.getSize();

  this.fd = fs.openSync(this.file, 'r+');
};

BlockData.prototype._malloc = function(size) {
  if (!this._bufferPool[size])
    this._bufferPool[size] = new Buffer(size);

  if (this._bufferPool.used[size] === this._bufferPool[size])
    return new Buffer(size);

  this._bufferPool.used[size] = this._bufferPool[size];

  return this._bufferPool[size];
};

BlockData.prototype._free = function(buf) {
  if (this._bufferPool.used[buf.length] === buf) {
    assert(this._bufferPool[buf.length] === buf);
    delete this._bufferPool.used[buf.length];
  }
};

BlockData.prototype.exists = function exists() {
  if (!bcoin.fs)
    return true;

  try {
    fs.statSync(this.file);
    return true;
  } catch (e) {
    return false;
  }
};

BlockData.prototype.getSize = function getSize() {
  if (!bcoin.fs)
    return this.ramdisk.size;

  try {
    return fs.statSync(this.file).size;
  } catch (e) {
    return 0;
  }
};

BlockData.prototype.getSync = function getSync(size, offset) {
  var hash = size + '/' + offset;

  if (this._cache[hash])
    return this._cache[hash];

  if (this._queue[hash])
    return this._queue[hash];

  return this._readSync(size, offset);
};

BlockData.prototype.getAsync = function getAsync(size, offset, callback) {
  var self = this;
  var hash = size + '/' + offset;

  callback = utils.asyncify(callback);

  if (this._cache[hash])
    return callback(null, this._cache[hash]);

  if (this._queue[hash])
    return callback(null, this._queue[hash]);

  return this._readAsync(size, offset, callback);
};

BlockData.prototype.saveSync = function saveSync(data) {
  var self = this;
  var offset = this.size;
  var hash = data + '/' + offset;

  this._writeSync(data, offset);

  return { size: data.length, offset: offset };
};

BlockData.prototype.saveAsync = function saveAsync(data, callback) {
  var self = this;
  var offset = this.size;
  var hash = data + '/' + offset;

  callback = utils.asyncify(callback);

  // Something is already writing. Cancel it
  // and synchronously write the data after
  // it cancels.
  if (this._queue[hash]) {
    this._queue[hash] = data;
    return callback(null, { size: data.length, offset: offset });
  }

  // Speed up writes by doing them asynchronously
  // and keeping the data to be written in memory.
  this._queue[hash] = data;

  return this._writeAsync(data, offset, function(err, success) {
    if (err)
      return callback(err);

    var item = self._queue[hash];

    // Something tried to write here but couldn't.
    // Synchronously write it and get it over with.
    try {
      if (item && item !== data)
        success = self._writeSync(item, offset);
    } catch (e) {
      err = e;
    }

    delete self._queue[hash];

    return callback(null, { size: data.length, offset: offset });
  });
};

BlockData.prototype.truncate = function truncate(height) {
  this.size = (height + 1) * BLOCK_SIZE;
  this.tip = height;

  if (!bcoin.fs) {
    this.ramdisk.truncate(this.size);
    return;
  }

  fs.ftruncateSync(this.fd, this.size);
};

BlockData.prototype._readSync = function _readSync(size, offset) {
  var index = 0;
  var data, bytes;

  if (offset < 0 || offset == null)
    return;

  if (!bcoin.fs)
    return this.ramdisk.read(size, offset);

  data = this._malloc(size);

  try {
    while (bytes = fs.readSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this._free(data);
        return data;
      }
    }
  } catch (e) {
    this._free(data);
    throw e;
  }

  this._free(data);

  throw new Error('_readSync() failed.');
};

BlockData.prototype._readAsync = function _readAsync(size, offset, callback) {
  var self = this;
  var index = 0;
  var data, bytes;

  callback = utils.asyncify(callback);

  if (offset < 0 || offset == null)
    return callback();

  if (!bcoin.fs)
    return callback(null, this.ramdisk.read(size, offset));

  data = this._malloc(size);

  (function next() {
    fs.read(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self._free(data);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        self._free(data);
        return callback(null, data);
      }

      next();
    });
  })();
};

BlockData.prototype._writeSync = function _writeSync(data, offset) {
  var size = data.length;
  var added = Math.max(0, (offset + data.length) - this.size);
  var index = 0;
  var bytes;

  if (offset < 0 || offset == null)
    return false;

  if (!bcoin.fs) {
    this.size += added;
    this.ramdisk.write(data, offset);
    return;
  }

  try {
    while (bytes = fs.writeSync(this.fd, data, index, size, offset)) {
      index += bytes;
      size -= bytes;
      offset += bytes;
      if (index === data.length) {
        this.size += added;
        return true;
      }
    }
  } catch (e) {
    throw e;
  }

  throw new Error('_writeSync() failed.');
};

BlockData.prototype._writeAsync = function _writeAsync(data, offset, callback) {
  var self = this;
  var added = Math.max(0, (offset + data.length) - this.size);
  var size = data.length;
  var index = 0;

  callback = utils.asyncify(callback);

  if (offset < 0 || offset == null)
    return callback(null, false);

  if (!bcoin.fs) {
    this.size += added;
    this.ramdisk.write(data, offset);
    return callback(null, true);
  }

  this.size += added;

  (function next() {
    fs.write(self.fd, data, index, size, offset, function(err, bytes) {
      if (err) {
        self.size -= (added - index);
        return callback(err);
      }

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length)
        return callback(null, true);

      next();
    });
  })();
};

/**
 * Expose
 */

module.exports = BlockDB;
