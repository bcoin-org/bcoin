/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const Logger = require('blgr');
const bio = require('bufio');
const assert = require('bsert');
const common = require('./util/common');
const {resolve} = require('path');
const fs = require('bfile');
const {rimraf, testdir} = require('./util/common');
const random = require('bcrypto/lib/random');

const vectors = [
  common.readBlock('block300025'),
  common.readBlock('block426884'),
  common.readBlock('block898352')
];

const extra = [
  common.readBlock('block482683')
];

const undos = [
  common.readBlock('block300025'),
  common.readBlock('block928816'),
  common.readBlock('block928828'),
  common.readBlock('block928831'),
  common.readBlock('block928848'),
  common.readBlock('block928849')
];

const {
  AbstractBlockStore,
  FileBlockStore,
  LevelBlockStore
} = require('../lib/blockstore');

const layout = require('../lib/blockstore/layout');
const {types} = require('../lib/blockstore/common');

const {
  BlockRecord,
  FileRecord
} = require('../lib/blockstore/records');

describe('BlockStore', function() {
  describe('Abstract', function() {
    let logger = null;

    function context(ctx) {
      return {info: () => ctx};
    }

    beforeEach(() => {
      logger = Logger.global;
      Logger.global = {context};
    });

    afterEach(() => {
      Logger.global = logger;
    });

    it('construct with custom logger', async () => {
      const store = new AbstractBlockStore({logger: {context}});
      assert(store.logger);
      assert(store.logger.info);
      assert.equal(store.logger.info(), 'blockstore');
    });

    it('construct with default logger', async () => {
      const store = new AbstractBlockStore();
      assert(store.logger);
      assert(store.logger.info);
      assert.equal(store.logger.info(), 'blockstore');
    });

    it('has unimplemented base methods', async () => {
      const methods = ['open', 'close', 'write', 'writeUndo',
                       'read', 'readUndo', 'prune', 'pruneUndo',
                       'has', 'hasUndo', 'ensure'];

      const store = new AbstractBlockStore();

      for (const method of methods) {
        assert(store[method]);

        let err = null;
        try {
          await store[method]();
        } catch (e) {
          err = e;
        }
        assert(err, `Expected unimplemented method ${method}.`);
        assert.equal(err.message, 'Abstract method.');
      }
    });
  });

  describe('Records', function() {
    describe('BlockRecord', function() {
      function constructError(options) {
        let err = null;

        try {
          new BlockRecord({
            file: options.file,
            position: options.position,
            length: options.length
          });
        } catch (e) {
          err = e;
        }

        assert(err);
      }

      function toAndFromRaw(options) {
        const rec1 = new BlockRecord(options);
        assert.equal(rec1.file, options.file);
        assert.equal(rec1.position, options.position);
        assert.equal(rec1.length, options.length);

        const raw = rec1.toRaw();
        const rec2 = BlockRecord.fromRaw(raw);
        assert.equal(rec2.file, options.file);
        assert.equal(rec2.position, options.position);
        assert.equal(rec2.length, options.length);
      }

      it('construct with correct options', () => {
        const rec = new BlockRecord({
          file: 12,
          position: 23392,
          length: 4194304
        });
        assert.equal(rec.file, 12);
        assert.equal(rec.position, 23392);
        assert.equal(rec.length, 4194304);
      });

      it('construct null record', () => {
        const rec = new BlockRecord();
        assert.equal(rec.file, 0);
        assert.equal(rec.position, 0);
        assert.equal(rec.length, 0);
      });

      it('fail with signed number (file)', () => {
        constructError({file: -1, position: 1, length: 1});
      });

      it('fail with signed number (position)', () => {
        constructError({file: 1, position: -1, length: 1});
      });

      it('fail with signed number (length)', () => {
        constructError({file: 1, position: 1, length: -1});
      });

      it('fail with non-32-bit number (file)', () => {
        constructError({file: Math.pow(2, 32), position: 1, length: 1});
      });

      it('fail with non-32-bit number (position)', () => {
        constructError({file: 1, position: Math.pow(2, 32), length: 1});
      });

      it('fail with non-32-bit number (length)', () => {
        constructError({file: 1, position: 1, length: Math.pow(2, 32)});
      });

      it('construct with max 32-bit numbers', () => {
        const max = Math.pow(2, 32) - 1;

        const rec = new BlockRecord({
          file: max,
          position: max,
          length: max
        });

        assert(rec);
        assert.equal(rec.file, max);
        assert.equal(rec.position, max);
        assert.equal(rec.length, max);
      });

      it('serialize/deserialize file record (min)', () => {
        toAndFromRaw({file: 0, position: 0, length: 0});
      });

      it('serialize/deserialize file record', () => {
        toAndFromRaw({file: 12, position: 23392, length: 4194304});
      });

      it('serialize/deserialize file record (max)', () => {
        const max = Math.pow(2, 32) - 1;
        toAndFromRaw({file: max, position: max, length: max});
      });
    });

    describe('FileRecord', function() {
      function constructError(options) {
        let err = null;

        try {
          new FileRecord({
            blocks: options.blocks,
            used: options.used,
            length: options.length
          });
        } catch (e) {
          err = e;
        }

        assert(err);
      }

      function toAndFromRaw(options) {
        const rec1 = new FileRecord(options);
        assert.equal(rec1.blocks, options.blocks);
        assert.equal(rec1.used, options.used);
        assert.equal(rec1.length, options.length);

        const raw = rec1.toRaw();
        const rec2 = FileRecord.fromRaw(raw);
        assert.equal(rec2.blocks, options.blocks);
        assert.equal(rec2.used, options.used);
        assert.equal(rec2.length, options.length);
      }

      it('construct with correct options', () => {
        const rec = new FileRecord({
          blocks: 1,
          used: 4194304,
          length: 20971520
        });
        assert.equal(rec.blocks, 1);
        assert.equal(rec.used, 4194304);
        assert.equal(rec.length, 20971520);
      });

      it('fail to with signed number (blocks)', () => {
        constructError({blocks: -1, used: 1, length: 1});
      });

      it('fail to with signed number (used)', () => {
        constructError({blocks: 1, used: -1, length: 1});
      });

      it('fail to with signed number (length)', () => {
        constructError({blocks: 1, used: 1, length: -1});
      });

      it('fail to with non-32-bit number (blocks)', () => {
        constructError({blocks: Math.pow(2, 32), used: 1, length: 1});
      });

      it('fail to with non-32-bit number (used)', () => {
        constructError({blocks: 1, used: Math.pow(2, 32), length: 1});
      });

      it('fail to with non-32-bit number (length)', () => {
        constructError({blocks: 1, used: 1, length: Math.pow(2, 32)});
      });

      it('serialize/deserialize block record (min)', () => {
        toAndFromRaw({blocks: 0, used: 0, length: 0});
      });

      it('serialize/deserialize block record', () => {
        toAndFromRaw({blocks: 10, used: 4194304, length: 20971520});
      });

      it('serialize/deserialize block record (max)', () => {
        const max = Math.pow(2, 32) - 1;
        toAndFromRaw({blocks: max, used: max, length: max});
      });
    });
  });

  describe('FileBlockStore (Unit)', function() {
    const location = '/tmp/.bcoin/blocks';
    let store = null;

    before(() => {
      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024
      });
    });

    describe('constructor', function() {
      it('will pass options to super', () => {
        const info = () => 'info';
        const logger = {
          context: () => {
            return {info};
          }
        };

        const store = new FileBlockStore({
          location: '/tmp/.bcoin/blocks',
          maxFileLength: 1024,
          logger: logger
        });

        assert.strictEqual(store.logger.info, info);
      });

      it('will error with invalid location', () => {
        let err = null;

        try {
          new FileBlockStore({
            location: 'tmp/.bcoin/blocks',
            maxFileLength: 1024
          });
        } catch (e) {
          err = e;
        }

        assert(err);
        assert.equal(err.message, 'Location not absolute.');
      });

      it('will error with invalid max file length', () => {
        let err = null;

        try {
          new FileBlockStore({
            location: location,
            maxFileLength: 'notanumber'
          });
        } catch (e) {
          err = e;
        }

        assert(err);
        assert.equal(err.message, 'Invalid max file length.');
      });
    });

    describe('allocate', function() {
      it('will fail with length above file max', async () => {
        let err = null;
        try {
          await store.allocate(types.BLOCK, 1025);
        } catch (e) {
          err = e;
        }
        assert(err);
        assert.equal(err.message, 'Block length above max file length.');
      });
    });

    describe('filepath', function() {
      it('will give correct path (0)', () => {
        const filepath = store.filepath(types.BLOCK, 0);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk00000.dat');
      });

      it('will give correct path (1)', () => {
        const filepath = store.filepath(types.BLOCK, 7);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk00007.dat');
      });

      it('will give correct path (2)', () => {
        const filepath = store.filepath(types.BLOCK, 23);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk00023.dat');
      });

      it('will give correct path (3)', () => {
        const filepath = store.filepath(types.BLOCK, 456);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk00456.dat');
      });

      it('will give correct path (4)', () => {
        const filepath = store.filepath(types.BLOCK, 8999);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk08999.dat');
      });

      it('will give correct path (5)', () => {
        const filepath = store.filepath(types.BLOCK, 99999);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blk99999.dat');
      });

      it('will fail over max size', () => {
        let err = null;
        try {
          store.filepath(types.BLOCK, 100000);
        } catch (e) {
          err = e;
        }

        assert(err);
        assert.equal(err.message, 'File number too large.');
      });

      it('will give undo type', () => {
        const filepath = store.filepath(types.UNDO, 99999);
        assert.equal(filepath, '/tmp/.bcoin/blocks/blu99999.dat');
      });

      it('will fail for unknown prefix', () => {
        let err = null;
        try {
          store.filepath(0, 1234);
        } catch (e) {
          err = e;
        }

        assert(err);
        assert.equal(err.message, 'Unknown file prefix.');
      });
    });

    describe('write', function() {
      const write = fs.write;
      const open = fs.open;
      const close = fs.close;
      let allocate = null;
      let has = null;

      beforeEach(() => {
        allocate = store.allocate;
        has = store.db.has;
      });

      afterEach(() => {
        // Restore stubbed methods.
        fs.write = write;
        fs.open = open;
        fs.close = close;
        store.allocate = allocate;
        store.db.has = has;
      });

      it('will error if total magic bytes not written', async () => {
        let err = null;

        store.allocate = () => {
          return {
            fileno: 20,
            filerecord: {
              used: 0
            },
            filepath: '/tmp/.bcoin/blocks/blk00020.dat'
          };
        };
        store.db.has = () => false;
        fs.open = () => 7;
        fs.close = () => undefined;
        fs.write = () => 0;

        try {
          const hash = random.randomBytes(128);
          const block = random.randomBytes(32);
          await store.write(hash, block);
        } catch (e) {
          err = e;
        }

        assert(err, 'Expected error.');
        assert.equal(err.message, 'Could not write block magic.');
      });

      it('will error if total block bytes not written', async () => {
        let err = 0;

        let called = 0;
        store.allocate = () => {
          return {
            fileno: 20,
            filerecord: {
              used: 0
            },
            filepath: '/tmp/.bcoin/blocks/blk00020.dat'
          };
        };
        store.db.has = () => false;
        fs.open = () => 7;
        fs.close = () => undefined;
        fs.write = (fd, buffer, offset, length, position) => {
          let written = 0;

          if (called === 0)
            written = length;

          called += 1;

          return written;
        };

        try {
          const hash = random.randomBytes(128);
          const block = random.randomBytes(32);
          await store.write(hash, block);
        } catch (e) {
          err = e;
        }

        assert(err, 'Expected error.');
        assert.equal(err.message, 'Could not write block.');
      });

      it('will close file if write throws', async () => {
        let err = null;
        let closed = null;

        store.allocate = () => {
          return {
            fileno: 20,
            filerecord: {
              used: 0
            },
            filepath: '/tmp/.bcoin/blocks/blk00020.dat'
          };
        };
        store.db.has = () => false;
        fs.open = () => 7;
        fs.close = (fd) => {
          closed = fd;
        };
        fs.write = () => {
          throw new Error('Test.');
        };

        try {
          const hash = random.randomBytes(128);
          const block = random.randomBytes(32);
          await store.write(hash, block);
        } catch (e) {
          err = e;
        }

        assert(err, 'Expected error.');
        assert.equal(err.message, 'Test.');
        assert.equal(closed, 7);
      });
    });

    describe('read', function() {
      const read = fs.read;
      const open = fs.open;
      const close = fs.close;
      let get = null;
      let raw = null;

      before(() => {
        const record = new BlockRecord({
          file: 1,
          position: 8,
          length: 100
        });
        raw = record.toRaw();
      });

      beforeEach(() => {
        get = store.db.get;
      });

      afterEach(() => {
        // Restore stubbed methods.
        store.db.get = get;
        fs.read = read;
        fs.open = open;
        fs.close = close;
      });

      it('will error if total read bytes not correct', async () => {
        let err = null;

        store.db.get = () => raw;
        fs.open = () => 7;
        fs.close = () => undefined;
        fs.read = () => 99;

        try {
          const hash = random.randomBytes(128);
          const block = random.randomBytes(32);
          await store.read(hash, block);
        } catch (e) {
          err = e;
        }

        assert(err, 'Expected error.');
        assert.equal(err.message, 'Wrong number of bytes read.');
      });

      it('will close file if read throws', async () => {
        let err = null;
        let closed = null;

        store.db.get = () => raw;
        fs.open = () => 7;
        fs.close = (fd) => {
          closed = fd;
        };
        fs.read = () => {
          throw new Error('Test.');
        };

        try {
          const hash = random.randomBytes(128);
          const block = random.randomBytes(32);
          await store.read(hash, block);
        } catch (e) {
          err = e;
        }

        assert(err, 'Expected error.');
        assert.equal(err.message, 'Test.');
        assert.equal(closed, 7);
      });
    });
  });

  describe('FileBlockStore (Integration 1)', function() {
    const location = testdir('blockstore');
    let store = null;

    beforeEach(async () => {
      await rimraf(location);

      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024
      });

      await store.ensure();
      await store.open();
    });

    afterEach(async () => {
      await store.close();
    });

    after(async () => {
      await rimraf(location);
    });

    it('will write and read a block', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const block2 = await store.read(hash);

      assert.bufferEqual(block1, block2);
    });

    it('will write and read block undo coins', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.writeUndo(hash, block1);

      const block2 = await store.readUndo(hash);

      assert.bufferEqual(block1, block2);
    });

    it('will read a block w/ offset and length', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const offset = 79;
      const size = 15;

      const block2 = await store.read(hash, offset, size);

      assert.bufferEqual(block1.slice(offset, offset + size), block2);
    });

    it('will fail to read w/ out-of-bounds length', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const offset = 79;
      const size = 50;

      let err = null;
      try {
        await store.read(hash, offset, size);
      } catch (e) {
        err = e;
      }

      assert(err);
      assert.equal(err.message, 'Out-of-bounds read.');
    });

    it('will allocate new files', async () => {
      const blocks = [];

      for (let i = 0; i < 16; i++) {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        blocks.push({hash, block});
        await store.write(hash, block);
        const block2 = await store.read(hash);
        assert.bufferEqual(block2, block);
      }

      const first = await fs.stat(store.filepath(types.BLOCK, 0));
      const second = await fs.stat(store.filepath(types.BLOCK, 1));
      const third = await fs.stat(store.filepath(types.BLOCK, 2));
      assert.equal(first.size, 952);
      assert.equal(second.size, 952);
      assert.equal(third.size, 272);

      const magic = (8 * 16);
      const len = first.size + second.size + third.size - magic;
      assert.equal(len, 128 * 16);

      for (let i = 0; i < 16; i++) {
        const expect = blocks[i];
        const block = await store.read(expect.hash);
        assert.bufferEqual(block, expect.block);
      }
    });

    it('will allocate new files with block undo coins', async () => {
      const blocks = [];

      for (let i = 0; i < 16; i++) {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        blocks.push({hash, block});
        await store.writeUndo(hash, block);
        const block2 = await store.readUndo(hash);
        assert.bufferEqual(block2, block);
      }

      const first = await fs.stat(store.filepath(types.UNDO, 0));
      const second = await fs.stat(store.filepath(types.UNDO, 1));
      const third = await fs.stat(store.filepath(types.UNDO, 2));

      const magic = (40 * 16);
      const len = first.size + second.size + third.size - magic;
      assert.equal(len, 128 * 16);

      for (let i = 0; i < 16; i++) {
        const expect = blocks[i];
        const block = await store.readUndo(expect.hash);
        assert.bufferEqual(block, expect.block);
      }
    });

    it('will recover from interrupt during block write', async () => {
      {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        await store.write(hash, block);

        const block2 = await store.read(hash);
        assert.bufferEqual(block2, block);
      }

      // Manually insert a partially written block to the
      // end of file as would be the case of an untimely
      // interrupted write of a block. The file record
      // would not be updated to include the used bytes and
      // thus this data should be overwritten.
      {
        const filepath = store.filepath(types.BLOCK, 0);

        const fd = await fs.open(filepath, 'a');

        const bw = bio.write(8);
        bw.writeU32(store.network.magic);
        bw.writeU32(73);
        const magic = bw.render();

        const failblock = random.randomBytes(73);

        const mwritten = await fs.write(fd, magic, 0, 8);
        const bwritten = await fs.write(fd, failblock, 0, 73);

        await fs.close(fd);

        assert.equal(mwritten, 8);
        assert.equal(bwritten, 73);
      }

      // Now check that this block has the correct position
      // in the file and that it can be read correctly.
      {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        await store.write(hash, block);

        const block2 = await store.read(hash);
        assert.bufferEqual(block2, block);
      }
    });

    it('will not write blocks at the same position', (done) => {
      let err = null;
      let finished = 0;

      for (let i = 0; i < 16; i++) {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);

        // Accidentally don't use `await` and attempt to
        // write multiple blocks in parallel and at the
        // same file position.
        (async () => {
          try {
            await store.write(hash, block);
          } catch (e) {
            err = e;
          } finally {
            finished += 1;
            if (finished >= 16) {
              assert(err);
              assert(err.message, 'Already writing.');
              done();
            }
          }
        })();
      }
    });

    it('will not duplicate a block on disk', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);

      const first = await store.write(hash, block);
      assert.equal(first, true);
      const second = await store.write(hash, block);
      assert.equal(second, false);

      const pruned = await store.prune(hash);
      assert.equal(pruned, true);

      assert.equal(await fs.exists(store.filepath(types.BLOCK, 0)), false);
    });

    it('will return null if block not found', async () => {
      const hash = random.randomBytes(32);
      const block = await store.read(hash);
      assert.strictEqual(block, null);
    });

    it('will check if block exists (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.has(hash);
      assert.strictEqual(exists, false);
    });

    it('will check if block exists (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.write(hash, block);
      const exists = await store.has(hash);
      assert.strictEqual(exists, true);
    });

    it('will check if block undo coins exists (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.hasUndo(hash);
      assert.strictEqual(exists, false);
    });

    it('will check if block undo coins exists (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.writeUndo(hash, block);
      const exists = await store.hasUndo(hash);
      assert.strictEqual(exists, true);
    });

    it('will prune blocks', async () => {
      const hashes = [];
      for (let i = 0; i < 16; i++) {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        hashes.push(hash);
        await store.write(hash, block);
      }

      const first = await fs.stat(store.filepath(types.BLOCK, 0));
      const second = await fs.stat(store.filepath(types.BLOCK, 1));
      const third = await fs.stat(store.filepath(types.BLOCK, 2));

      const magic = (8 * 16);
      const len = first.size + second.size + third.size - magic;
      assert.equal(len, 128 * 16);

      for (let i = 0; i < 16; i++) {
        const pruned = await store.prune(hashes[i]);
        assert.strictEqual(pruned, true);
      }

      assert.equal(await fs.exists(store.filepath(types.BLOCK, 0)), false);
      assert.equal(await fs.exists(store.filepath(types.BLOCK, 1)), false);
      assert.equal(await fs.exists(store.filepath(types.BLOCK, 2)), false);

      for (let i = 0; i < 16; i++) {
        const exists = await store.has(hashes[i]);
        assert.strictEqual(exists, false);
      }

      const exists = await store.db.has(layout.f.encode(types.BLOCK, 0));
      assert.strictEqual(exists, false);
    });

    it('will prune block undo coins', async () => {
      const hashes = [];
      for (let i = 0; i < 16; i++) {
        const block = random.randomBytes(128);
        const hash = random.randomBytes(32);
        hashes.push(hash);
        await store.writeUndo(hash, block);
      }

      const first = await fs.stat(store.filepath(types.UNDO, 0));
      const second = await fs.stat(store.filepath(types.UNDO, 1));
      const third = await fs.stat(store.filepath(types.UNDO, 2));

      const magic = (40 * 16);
      const len = first.size + second.size + third.size - magic;
      assert.equal(len, 128 * 16);

      for (let i = 0; i < 16; i++) {
        const pruned = await store.pruneUndo(hashes[i]);
        assert.strictEqual(pruned, true);
      }

      assert.equal(await fs.exists(store.filepath(types.UNDO, 0)), false);
      assert.equal(await fs.exists(store.filepath(types.UNDO, 1)), false);
      assert.equal(await fs.exists(store.filepath(types.UNDO, 2)), false);

      for (let i = 0; i < 16; i++) {
        const exists = await store.hasUndo(hashes[i]);
        assert.strictEqual(exists, false);
      }

      const exists = await store.db.has(layout.f.encode(types.UNDO, 0));
      assert.strictEqual(exists, false);
    });
  });

  describe('FileBlockStore (Integration 2)', function() {
    const location = testdir('blockstore');
    let store = null;

    beforeEach(async () => {
      await rimraf(location);

      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024 * 1024
      });

      await store.ensure();
      await store.open();
    });

    afterEach(async () => {
      await store.close();
    });

    after(async () => {
      await rimraf(location);
    });

    it('will import from files (e.g. db corruption)', async () => {
      const blocks = [];

      for (let i = 0; i < vectors.length; i++) {
        const [block] = vectors[i].getBlock();
        const hash = block.hash();
        const raw = block.toRaw();

        blocks.push({hash, block: raw});
        await store.write(hash, raw);
      }

      await store.close();

      await rimraf(resolve(location, './index'));

      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024
      });

      await store.open();

      for (let i = 0; i < vectors.length; i++) {
        const expect = blocks[i];
        const block = await store.read(expect.hash);
        assert.equal(block.length, expect.block.length);
        assert.bufferEqual(block, expect.block);
      }
    });

    it('will import from files after write interrupt', async () => {
      const blocks = [];

      for (let i = 0; i < vectors.length; i++) {
        const [block] = vectors[i].getBlock();
        const hash = block.hash();
        const raw = block.toRaw();

        blocks.push({hash, block: raw});
        await store.write(hash, raw);
      }

      await store.close();

      assert.equal(await fs.exists(store.filepath(types.BLOCK, 0)), true);
      assert.equal(await fs.exists(store.filepath(types.BLOCK, 1)), true);
      assert.equal(await fs.exists(store.filepath(types.BLOCK, 2)), false);

      // Write partial block as would be the case in a
      // block write interrupt.
      const [partial] = extra[0].getBlock();
      {
        // Include all of the header, but not the block.
        let raw = partial.toRaw();
        const actual = raw.length;
        const part = raw.length - 1;
        raw = raw.slice(0, part);

        const filepath = store.filepath(types.BLOCK, 1);

        const fd = await fs.open(filepath, 'a');

        const bw = bio.write(8);
        bw.writeU32(store.network.magic);
        bw.writeU32(actual);
        const magic = bw.render();

        const mwritten = await fs.write(fd, magic, 0, 8);
        const bwritten = await fs.write(fd, raw, 0, part);

        await fs.close(fd);

        assert.equal(mwritten, 8);
        assert.equal(bwritten, part);
      }

      await rimraf(resolve(location, './index'));

      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024
      });

      await store.open();

      const incomplete = await store.read(partial.hash());
      assert(incomplete === null);

      for (let i = 0; i < vectors.length; i++) {
        const expect = blocks[i];
        const block = await store.read(expect.hash);
        assert.equal(block.length, expect.block.length);
        assert.bufferEqual(block, expect.block);
      }
    });

    it('will import undo blocks from files', async () => {
      const blocks = [];

      for (let i = 0; i < undos.length; i++) {
        const [block] = undos[i].getBlock();
        const raw = undos[i].undoRaw;
        const hash = block.hash();

        blocks.push({hash, block: raw});
        await store.writeUndo(hash, raw);
      }

      await store.close();

      await rimraf(resolve(location, './index'));

      store = new FileBlockStore({
        location: location,
        maxFileLength: 1024
      });

      await store.open();

      for (let i = 0; i < undos.length; i++) {
        const expect = blocks[i];
        const block = await store.readUndo(expect.hash);
        assert.equal(block.length, expect.block.length);
        assert.bufferEqual(block, expect.block);
      }
    });
  });

  describe('LevelBlockStore', function() {
    const location = testdir('blockstore');
    let store = null;

    beforeEach(async () => {
      await rimraf(location);

      store = new LevelBlockStore({
        location: location
      });

      await store.ensure();
      await store.open();
    });

    afterEach(async () => {
      await store.close();
    });

    after(async () => {
      await rimraf(location);
    });

    it('will write and read a block', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const block2 = await store.read(hash);

      assert.bufferEqual(block1, block2);
    });

    it('will write and read block undo coins', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.writeUndo(hash, block1);

      const block2 = await store.readUndo(hash);

      assert.bufferEqual(block1, block2);
    });

    it('will read a block w/ offset and length', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const offset = 79;
      const size = 15;

      const block2 = await store.read(hash, offset, size);

      assert.bufferEqual(block1.slice(offset, offset + size), block2);
    });

    it('will fail to read w/ out-of-bounds length', async () => {
      const block1 = random.randomBytes(128);
      const hash = random.randomBytes(32);

      await store.write(hash, block1);

      const offset = 79;
      const size = 50;

      let err = null;
      try {
        await store.read(hash, offset, size);
      } catch (e) {
        err = e;
      }

      assert(err);
      assert.equal(err.message, 'Out-of-bounds read.');
    });

    it('will check if block exists (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.has(hash);
      assert.strictEqual(exists, false);
    });

    it('will check if block exists (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.write(hash, block);
      const exists = await store.has(hash);
      assert.strictEqual(exists, true);
    });

    it('will check if block undo coins exists (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.has(hash);
      assert.strictEqual(exists, false);
    });

    it('will check if block undo coins exists (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.writeUndo(hash, block);
      const exists = await store.hasUndo(hash);
      assert.strictEqual(exists, true);
    });

    it('will prune blocks (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.write(hash, block);
      const pruned = await store.prune(hash);
      assert.strictEqual(pruned, true);
      const block2 = await store.read(hash);
      assert.strictEqual(block2, null);
    });

    it('will prune blocks (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.has(hash);
      assert.strictEqual(exists, false);
      const pruned = await store.prune(hash);
      assert.strictEqual(pruned, false);
    });

    it('will prune block undo coins (true)', async () => {
      const block = random.randomBytes(128);
      const hash = random.randomBytes(32);
      await store.writeUndo(hash, block);
      const pruned = await store.pruneUndo(hash);
      assert.strictEqual(pruned, true);
      const block2 = await store.readUndo(hash);
      assert.strictEqual(block2, null);
    });

    it('will prune block undo coins (false)', async () => {
      const hash = random.randomBytes(32);
      const exists = await store.hasUndo(hash);
      assert.strictEqual(exists, false);
      const pruned = await store.pruneUndo(hash);
      assert.strictEqual(pruned, false);
    });
  });
});
