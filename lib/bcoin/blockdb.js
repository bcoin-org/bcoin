/**
 * db.js - db object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var EventEmitter = require('events').EventEmitter;
var network = bcoin.protocol.network;
var fs = bcoin.fs;

/**
 * BlockDB
 */

function BlockDB(node, options) {
  var self = this;
  var levelup;

  if (!(this instanceof BlockDB))
    return new BlockDB(node, options);

  // Some lazy loading
  levelup = require('levelup');

  EventEmitter.call(this);

  if (!options)
    options = {};

  this.file = options.indexFile;

  bcoin.ensurePrefix();

  if (!this.file)
    this.file = bcoin.prefix + '/index-' + network.type + '.db';

  this.options = options;

  this.node = node;
  this.data = new BlockData(node, this, options);

  this.cache = {
    unspent: new bcoin.lru(32 * 1024 * 1024),
    tx: new bcoin.lru(32 * 1024 * 1024)
  };

  if (+process.env.BCOIN_FRESH === 1 && bcoin.cp)
    bcoin.cp.execFileSync('rm', ['-rf', this.file], { stdio: 'ignore' });

  this.index = new levelup(this.file, {
    keyEncoding: 'ascii',
    valueEncoding: 'binary',
    createIfMissing: true,
    errorIfExists: false,
    compression: true,
    cacheSize: 16 * 1024 * 1024,
    writeBufferSize: 8 * 1024 * 1024,
    // blockSize: 4 * 1024,
    maxOpenFiles: 8192,
    // blockRestartInterval: 16,
    db: bcoin.isBrowser
      ? require('level-js')
      : require('level' + 'down')
  });
}

utils.inherits(BlockDB, EventEmitter);

BlockDB.prototype.close = function close(callback) {
  var self = this;
  this.index.close(function(err) {
    if (err)
      return callback(err);

    self.data.closeAsync(function(err) {
      if (err)
        return callback(err);

      return callback();
    });
  });
};

BlockDB.prototype.migrate = function migrate(blockSize, compression, callback) {
  var options, db, pending, stream, total, done;

  callback = utils.once(callback);
  options = utils.merge({}, this.index.options);

  if (blockSize != null)
    options.blockSize = blockSize;

  if (compression != null)
    options.compression = compression;

  options.maxOpenFiles = 60000;

  utils.print('Migrating DB with options:');
  utils.print(options);

  db = levelup(this.file + '.migrated', options);

  stream = this.index.createReadStream();

  pending = 0;
  total = 0;

  function onPut(err) {
    if (err)
      return callback(err);

    if (++total % 10000 === 0)
      utils.print('%d written.', total);

    pending--;

    if (done && !pending)
      callback();
  }

  stream.on('data', function(data) {
    pending++;
    db.put(data.key, data.value, onPut);
  });

  stream.on('error', function(err) {
    callback(err);
  });

  stream.on('end', function() {
    done = true;
    if (!pending)
      callback();
  });
};

BlockDB.prototype.createOffset = function createOffset(size, offset, height) {
  var buf = new Buffer(16);
  utils.writeU32(buf, size, 0);
  utils.writeU64(buf, offset, 4);
  utils.writeU32(buf, height, 12);
  return buf;
};

BlockDB.prototype.parseOffset = function parseOffset(data) {
  // Avoid using bignumbers here to increase performance.
  // This is safe because this number will never exceed
  // 53 bits (up to 8.3 petabytes).
  var hi = utils.readU32(data, 8);
  var lo = utils.readU32(data, 4);
  return {
    size: utils.readU32(data, 0),
    offset: (hi * 0x100000000) + lo,
    height: utils.readU32(data, 12)
  };
};

BlockDB.prototype.saveBlock = function saveBlock(block, callback) {
  var self = this;

  this.data.saveAsync(block._raw, function(err, data) {
    var batch, blockOffset;

    if (err)
      return callback(err);

    batch = self.index.batch();

    blockOffset = self.createOffset(data.size, data.offset, block.height);

    batch.put('b/b/' + block.hash('hex'), blockOffset);
    batch.put('b/h/' + block.height, blockOffset);

    block.txs.forEach(function(tx, i) {
      var hash = tx.hash('hex');
      var uniq = {};
      var txOffset;

      txOffset = self.createOffset(
        tx._size,
        data.offset + tx._offset,
        block.height
      );

      batch.put('t/t/' + hash, txOffset);

      tx.inputs.forEach(function(input) {
        var type = input.getType();
        var address = input.getAddress();
        var uaddr;

        if (input.isCoinbase())
          return;

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

        if (address) {
          batch.del(
            'u/a/' + address
            + '/' + input.prevout.hash
            + '/' + input.prevout.index);
        }

        batch.del('u/t/' + input.prevout.hash + '/' + input.prevout.index);

        if (self.options.cache)
          self.cache.unspent.remove(input.prevout.hash + '/' + input.prevout.index);
      });

      tx.outputs.forEach(function(output, i) {
        var type = output.getType();
        var address = output.getAddress();
        var uaddr, coinOffset;

        if (type === 'pubkey' || type === 'multisig')
          address = null;

        uaddr = address;

        if (uaddr) {
          if (!uniq[uaddr])
            uniq[uaddr] = true;
          else
            uaddr = null;
        }

        coinOffset = self.createOffset(
          output._size,
          data.offset + tx._offset + output._offset,
          block.height
        );

        if (uaddr)
          batch.put('t/a/' + uaddr + '/' + hash, txOffset);

        if (address)
          batch.put('u/a/' + address + '/' + hash + '/' + i, coinOffset);

        batch.put('u/t/' + hash + '/' + i, coinOffset);
      });
    });

    batch.write(function(err) {
      if (err)
        return callback(err);
      self.emit('save block', block);
      return callback(null, block);
    });
  });
};

BlockDB.prototype.removeBlock = function removeBlock(hash, callback) {
  var self = this;

  this.getBlock(hash, function(err, block) {
    var batch;

    if (err)
      return callback(err);

    if (!block)
      return callback();

    batch = self.index.batch();

    if (typeof hash === 'string')
      assert(block.hash('hex') === hash);

    batch.del('b/b/' + block.hash('hex'));
    batch.del('b/h/' + block.height);

    utils.forEach(block.txs, function(tx, next, i) {
      var hash = tx.hash('hex');
      var uniq = {};

      if (self.options.cache)
        self.cache.tx.remove(hash);

      batch.del('t/t/' + hash);

      self.fillTX(tx, function(err) {
        if (err)
          return next(err);

        tx.inputs.forEach(function(input) {
          var type = input.getType();
          var address = input.getAddress();
          var uaddr, coinOffset;

          if (input.isCoinbase())
            return;

          if (type === 'pubkey' || type === 'multisig')
            address = null;

          uaddr = address;

          if (uaddr) {
            if (!uniq[uaddr])
              uniq[uaddr] = true;
            else
              uaddr = null;
          }

          assert(input.output._fileOffset >= 0);

          coinOffset = self.createOffset(
            input.output._size,
            input.output._fileOffset,
            input.output.height
          );

          if (uaddr)
            batch.del('t/a/' + uaddr + '/' + hash);

          if (address) {
            batch.put('u/a/' + address
              + '/' + input.prevout.hash
              + '/' + input.prevout.index,
              coinOffset);
          }

          batch.put('u/t/'
            + input.prevout.hash
            + '/' + input.prevout.index,
            coinOffset);
        });

        tx.outputs.forEach(function(output, i) {
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

          if (self.options.cache)
            self.cache.unspent.remove(hash + '/' + i);
        });

        next();
      });
    }, function(err) {
      if (err)
        return callback(err);
      batch.write(function(err) {
        if (err)
          return callback(err);
        // TODO: Add check to make sure we
        // can ONLY remove the last block.
        assert(block._fileOffset >= 0);
        assert(block._fileOffset < self.data.size);
        self.emit('remove block', block);
        return callback(null, block);
        // XXX This seems to be truncating too much right now
        self.data.truncateAsync(block._fileOffset, function(err) {
          if (err)
            return callback(err);
          self.emit('remove block', block);
          return callback(null, block);
        });
      });
    });
  });
};

BlockDB.prototype.fillCoins = function fillCoins(txs, callback) {
  var self = this;
  var pending = txs.length;

  callback = utils.asyncify(callback);

  utils.forEach(txs, function(tx, next) {
    self.fillCoin(tx, function(err) {
      if (err)
        return next(err);

      next();
    });
  }, callback);
};

BlockDB.prototype.fillTXs = function fillTXs(txs, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  utils.forEach(txs, function(tx, next) {
    self.fillTX(tx, function(err) {
      if (err)
        return next(err);

      next();
    });
  }, callback);
};

BlockDB.prototype.fillCoin = function fillCoin(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback();

  utils.forEach(tx.inputs, function(input, next) {
    if (input.output)
      return next();

    self.getCoin(input.prevout.hash, input.prevout.index, function(err, coin) {
      if (err)
        return callback(err);

      if (coin)
        input.output = coin;

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

BlockDB.prototype.fillTX = function fillTX(tx, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (tx.isCoinbase())
    return callback();

  utils.forEach(tx.inputs, function(input, next) {
    if (input.output)
      return next();

    self.getTX(input.prevout.hash, function(err, tx) {
      if (err)
        return next(err);

      if (tx) {
        input.output = bcoin.coin(tx, input.prevout.index);
        input.output._fileOffset = tx._fileOffset + input.output._offset;
      }

      next();
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, tx);
  });
};

BlockDB.prototype.getCoinsByAddress = function getCoinsByAddress(addresses, options, callback) {
  var self = this;
  var coins = [];

  if (!callback) {
    callback = options;
    options = {};
  }

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  utils.forEach(addresses, function(address, done) {
    var iter = self.index.db.iterator({
      gte: 'u/a/' + address,
      lte: 'u/a/' + address + '~',
      keys: true,
      values: true,
      fillCache: true,
      keyAsBuffer: false,
      valueAsBuffer: true
    });

    (function next() {
      iter.next(function(err, key, value) {
        var record, parts, hash, index;

        if (err) {
          return iter.end(function() {
            done(err);
          });
        }

        if (key === undefined) {
          return iter.end(function(err) {
            if (err)
              return done(err);
            done();
          });
        }

        parts = key.split('/');
        hash = parts[3];
        index = +parts[4];
        record = self.parseOffset(value);

        self.data.getAsync(record.size, record.offset, function(err, data) {
          var coin;

          if (err) {
            return iter.end(function() {
              done(err);
            });
          }

          if (!data)
            return next();

          try {
            data = bcoin.protocol.parser.parseOutput(data);
          } catch (e) {
            return iter.end(function() {
              done(e);
            });
          }

          coin = bcoin.coin({
            version: 1,
            hash: hash,
            index: index,
            height: record.height,
            script: data.script,
            value: data.value,
            spent: false
          });

          if (self.options.cache)
            self.cache.unspent.set(id, coin);

          coins.push(coin);

          next();
        });
      });
    })();
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, coins);
  });
};

BlockDB.prototype.getCoin = function getCoin(hash, index, callback) {
  var self = this;
  var id = 'u/t/' + hash + '/' + index;

  this.index.get(id, function(err, record) {
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

      if (!data)
        return callback();

      try {
        data = bcoin.protocol.parser.parseOutput(data);
      } catch (e) {
        return callback(e);
      }

      coin = bcoin.coin({
        version: 1,
        hash: hash,
        index: index,
        height: record.height,
        script: data.script,
        value: data.value,
        spent: false
      });

      return callback(null, coin);
    });
  });
};

BlockDB.prototype.getTXByAddress = function getTXByAddress(addresses, options, callback) {
  var self = this;
  var txs = [];
  var have = {};

  if (!callback) {
    callback = options;
    options = {};
  }

  if (typeof addresses === 'string')
    addresses = [addresses];

  addresses = utils.uniqs(addresses);

  utils.forEach(addresses, function(address, done) {
    var iter = self.index.db.iterator({
      gte: 't/a/' + address,
      lte: 't/a/' + address + '~',
      keys: true,
      values: true,
      fillCache: true,
      keyAsBuffer: false,
      valueAsBuffer: true
    });

    (function next() {
      iter.next(function(err, key, value) {
        var record, hash, index;

        if (err) {
          return iter.end(function() {
            done(err);
          });
        }

        if (key === undefined) {
          return iter.end(function(err) {
            if (err)
              return done(err);
            done();
          });
        }

        hash = key.split('/')[3];
        record = self.parseOffset(value);

        if (addresses.length > 1) {
          if (have[hash])
            return next();

          have[hash] = true;
        }

        if (self.options.cache && self.cache.tx.has(hash)) {
          txs.push(self.cache.tx.get(hash));
          return done();
        }

        self.data.getAsync(record.size, record.offset, function(err, data) {
          var coin;

          if (err) {
            return iter.end(function() {
              done(err);
            });
          }

          if (!data)
            return next();

          try {
            tx = bcoin.protocol.parser.parseTX(data);
            tx = new bcoin.tx(tx);
          } catch (e) {
            return iter.end(function() {
              done(e);
            });
          }

          return self._getEntry(record.height, function(err, entry) {
            if (err) {
              return iter.end(function() {
                done(err);
              });
            }

            tx.height = record.height;

            if (entry) {
              tx.ts = entry.ts;
              tx.block = entry.hash;
            }

            txs.push(tx);

            if (self.options.cache)
              self.cache.tx.set(hash, tx);

            if (self.options.paranoid && tx.hash('hex') !== hash)
              return next(new Error('BlockDB is corrupt. All is lost.'));

            next();
          });
        });
      });
    })();
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, txs);
  });
};

BlockDB.prototype.getTX = function getTX(hash, callback) {
  var self = this;
  var id = 't/t/' + hash;

  this.index.get(id, function(err, record) {
    if (err) {
      if (err.type === 'NotFoundError')
        return callback();
      return callback(err);
    }

    record = self.parseOffset(record);

    self.data.getAsync(record.size, record.offset, function(err, data) {
      var tx;

      if (err)
        return callback(err);

      if (data) {
        try {
          tx = bcoin.protocol.parser.parseTX(data);
          tx = new bcoin.tx(tx);
        } catch (e) {
          return callback(e);
        }
        return self._getEntry(record.height, function(err, entry) {
          if (err)
            return callback(err);

          tx.height = record.height;

          if (entry) {
            tx.ts = entry.ts;
            tx.block = entry.hash;
          }

          tx._fileOffset = record.offset;

          if (self.options.paranoid && tx.hash('hex') !== hash)
            return callback(new Error('BlockDB is corrupt. All is lost.'));

          return callback(null, tx);
        });
      }

      return callback(null, tx);
    });
  });
};

BlockDB.prototype.getBlock = function getBlock(hash, callback) {
  var self = this;
  var id = 'b/b/' + hash;

  if (typeof hash === 'number')
    id = 'b/h/' + hash;

  this.index.get(id, function(err, record) {
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
        try {
          block = bcoin.protocol.parser.parseBlock(data);
          block = new bcoin.block(block);
        } catch (e) {
          return callback(e);
        }
        block._fileOffset = record.offset;
        block.height = record.height;
        block.txs.forEach(function(tx) {
          tx.height = block.height;
        });
        if (self.options.paranoid) {
          if (typeof hash === 'number') {
            self._getEntry(hash, function(err, entry) {
              if (err)
                return callback(err);

              if (!entry)
                return callback(null, block);

              if (block.hash('hex') !== entry.hash)
                return callback(new Error('BlockDB is corrupt. All is lost.'));

              return callback(null, block);
            });
            return;
          }
          if (block.hash('hex') !== hash)
            return callback(new Error('BlockDB is corrupt. All is lost.'));
        }
      }

      return callback(null, block);
    });
  });
};

BlockDB.prototype.hasBlock = function hasBlock(hash, callback) {
  var self = this;
  var id = 'b/b/' + hash;

  if (typeof hash === 'number')
    id = 'b/h/' + hash;

  this.index.get(id, function(err, record) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!record)
      return callback(null, false);

    record = self.parseOffset(record);

    if (self.data.size < record.offset + record.size)
      return callback(null, false);

    return callback(null, true);
  });
};

BlockDB.prototype.hasCoin = function hasCoin(hash, index, callback) {
  var self = this;
  var id = 'u/t/' + hash + '/' + index;

  this.index.get(id, function(err, record) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!record)
      return callback(null, false);

    record = self.parseOffset(record);

    if (self.data.size < record.offset + record.size)
      return callback(null, false);

    return callback(null, true);
  });
};

// For BIP30
// https://bitcointalk.org/index.php?topic=67738.0
BlockDB.prototype.hasUnspentTX = function hasUnspentTX(hash, callback) {
  var self = this;
  this.getTX(hash, function(err, tx) {
    var hash, spent;

    if (err)
      return callback(err);

    if (!tx)
      return callback(null, false);

    hash = tx.hash('hex');
    spent = 0;

    utils.forEach(tx.outputs, function(output, next, i) {
      self.isSpent(hash, i, function(err, result) {
        if (err)
          return next(err);

        if (result)
          spent++;

        next();
      });
    });
  }, function(err) {
    if (err)
      return callback(err);
    return callback(null, spent < tx.outputs.length);
  });
};

BlockDB.prototype.hasTX = function hasTX(hash, callback) {
  var self = this;
  var id = 't/t/' + hash;

  this.index.get(id, function(err, record) {
    if (err && err.type !== 'NotFoundError')
      return callback(err);

    if (!record)
      return callback(null, false);

    record = self.parseOffset(record);

    if (self.data.size < record.offset + record.size)
      return callback(null, false);

    return callback(null, true);
  });
};

BlockDB.prototype.isSpent = function isSpent(hash, index, callback) {
  return this.hasCoin(hash, index, function(err, result) {
    if (err)
      return callback(err);

    return callback(null, !result);
  });
};

BlockDB.prototype.getHeight = function getHeight(callback) {
  var self = this;
  var maxHeight = -1;
  var iter;

  iter = this.index.db.iterator({
    gte: 'b/h',
    lte: 'b/h~',
    keys: true,
    values: false,
    fillCache: false,
    keyAsBuffer: false
  });

  (function next() {
    iter.next(function(err, key, value) {
      var height;

      if (err) {
        return iter.end(function() {
          callback(err);
        });
      }

      if (key === undefined) {
        return iter.end(function(err) {
          if (err)
            return callback(err);
          callback(null, maxHeight);
        });
      }

      height = +key.split('/')[2];
      if (height > maxHeight)
        maxHeight = height;

      next();
    });
  })();
};

BlockDB.prototype.resetHeight = function resetHeight(height, callback, emit) {
  var self = this;
  this.getHeight(function(err, currentHeight) {
    if (err)
      return callback(err);

    if (currentHeight < height)
      return callback(new Error('Cannot reset to height ' + height));

    (function next() {
      if (currentHeight === height)
        return callback();

      self.removeBlock(currentHeight, function(err, block) {
        if (err)
          return callback(err);

        // Emit the blocks we removed.
        if (emit && block)
          emit(block);

        currentHeight--;
        next();
      });
    })();
  });
};

BlockDB.prototype._getEntry = function _getEntry(height, callback) {
  if (!this.node)
    return callback();

  return this.node.chain.db.getAsync(height, callback);
};

/**
 * BlockData
 */

function BlockData(node, blockdb, options) {
  if (!(this instanceof BlockData))
    return new BlockData(node, blockdb, options);

  if (!options)
    options = {};

  this.node = node;
  this.blockdb = blockdb;
  this.options = options;
  this.file = options.blockFile;

  bcoin.ensurePrefix();

  if (!this.file)
    this.file = bcoin.prefix + '/block-' + network.type + '.db';

  this.bufferPool = { used: {} };
  this.size = 0;
  this.fd = null;

  this._init();
}

BlockData.prototype._init = function _init() {
  if (!bcoin.fs) {
    utils.debug('`fs` module not available. Falling back to ramdisk.');
    this.ramdisk = new bcoin.ramdisk(40 * 1024 * 1024);
    return;
  }

  if (+process.env.BCOIN_FRESH === 1) {
    try {
      fs.unlinkSync(this.file);
    } catch (e) {
      ;
    }
  }

  if (!this.exists())
    fs.writeFileSync(this.file, new Buffer([]));

  this.size = this.getFileSize();

  this.fd = fs.openSync(this.file, 'r+');
};

BlockData.prototype.closeSync = function closeSync() {
  if (!bcoin.fs) {
    this.ramdisk = null;
    return;
  }
  fs.closeSync(this.fd);
  this.fd = null;
};

BlockData.prototype.closeAsync = function closeAsync(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!bcoin.fs) {
    this.ramdisk = null;
    return callback();
  }

  fs.close(this.fd, function(err) {
    if (err)
      return callback(err);
    self.fd = null;
    return callback();
  });
};

BlockData.prototype._malloc = function _malloc(size) {
  if (!this.options.usePool)
    return new Buffer(size);

  if (size > 500)
    return new Buffer(size);

  if (!this.bufferPool[size])
    this.bufferPool[size] = new Buffer(size);

  if (this.bufferPool.used[size] === this.bufferPool[size])
    return new Buffer(size);

  this.bufferPool.used[size] = this.bufferPool[size];

  return this.bufferPool[size];
};

BlockData.prototype._free = function _free(buf) {
  if (!this.options.usePool)
    return;

  if (this.bufferPool.used[buf.length] === buf) {
    assert(this.bufferPool[buf.length] === buf);
    delete this.bufferPool.used[buf.length];
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

BlockData.prototype.getFileSize = function getFileSize() {
  if (!bcoin.fs)
    return this.ramdisk.size;

  try {
    return fs.statSync(this.file).size;
  } catch (e) {
    return 0;
  }
};

BlockData.prototype.getSync = function getSync(size, offset) {
  return this._readSync(size, offset);
};

BlockData.prototype.getAsync = function getAsync(size, offset, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  return this._readAsync(size, offset, callback);
};

BlockData.prototype.saveSync = function saveSync(data) {
  var self = this;
  var offset = this.size;

  this._writeSync(data, offset);

  return { size: data.length, offset: offset };
};

BlockData.prototype.saveAsync = function saveAsync(data, callback) {
  var self = this;
  var offset = this.size;

  callback = utils.asyncify(callback);

  return this._writeAsync(data, offset, function(err, success) {
    if (err)
      return callback(err);
    return callback(null, { size: data.length, offset: offset });
  });
};

BlockData.prototype.truncateSync = function truncateSync(size) {
  if (!bcoin.fs) {
    this.ramdisk.truncate(size);
    this.size = size;
    return;
  }

  fs.ftruncateSync(this.fd, size);
  this.size = size;
};

BlockData.prototype.truncateAsync = function truncateAsync(size, callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!bcoin.fs) {
    this.ramdisk.truncate(size);
    this.size = size;
    return callback();
  }

  fs.ftruncate(this.fd, size, function(err) {
    if (err)
      return callback(err);
    self.size = size;
    return callback();
  });
};

BlockData.prototype._ioError = function _ioError(name, size, offset) {
  return new Error(name
    + '() failed at offset '
    + offset
    + ' with '
    + size
    + ' bytes left.');
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

  throw this._ioError('_readSync', size, offset);
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

      if (!bytes)
        return callback(self._ioError('_readAsync', size, offset));

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

  fs.fsyncSync(this.fd);

  throw this._ioError('_writeSync', size, offset);
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

      if (!bytes)
        return callback(self._ioError('_writeAsync', size, offset));

      index += bytes;
      size -= bytes;
      offset += bytes;

      if (index === data.length) {
        return fs.fsync(self.fd, function(err) {
          if (err)
            return callback(err);
          return callback(null, true);
        });
      }

      next();
    });
  })();
};

/**
 * Expose
 */

module.exports = BlockDB;
