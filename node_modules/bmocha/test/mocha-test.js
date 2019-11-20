/* global Worker */

'use strict';

const assert = require('assert');
const fs = require('fs');
const {resolve, sep} = require('path');
const wrap = require('./util/wrap');

let hooks = null;

try {
  hooks = require('perf_hooks');
} catch (e) {
  ;
}

const fsAccess = wrap(fs.access);
const fsExists = wrap(fs.exists);
const fsLstat = wrap(fs.lstat);
const fsReaddir = wrap(fs.readdir);
const fsReadFile = wrap(fs.readFile);
const fsStat = wrap(fs.stat);

const x = (Math.random() * 0x100000000) >>> 0;
const y = x.toString(32);
const z = `i-dont-exist${y}`;

const FILE = resolve(__dirname, '..', 'package.json');
const DIR = resolve(__dirname, '..');
const NOENT = resolve(__dirname, '..', z);
const ACCES = `${__dirname}${sep}..${sep}..${sep}${z}`;

const TOTAL_TESTS = 23;

const IS_MOCHA = Boolean(process.env.LOADED_MOCHA_OPTS);

let called = 0;

describe('Mocha', function() {
  describe('Sanity', function() {
    describe('Level 1', function() {
      this.timeout(120000);

      let x = 0;
      let y = 0;

      beforeEach('named hook', () => {
        x += 1;
      });

      afterEach(function namedHook() {
        x += 1;
      });

      before(() => {
        y = 1;
      });

      after(() => {
        y = 0;
      });

      it('should succeed', () => {
        assert.strictEqual(x, 1);
        assert.strictEqual(y, 1);
        assert.strictEqual(1, 1);
        called += 1;
      });

      let i = 0;

      it('should fail (once)', function() {
        this.retries(1000);
        i += 1;
        if (i === 1)
          assert.strictEqual(0, 1);
        called += 1;
      });

      it('should take a while (1)', async () => {
        assert.strictEqual(x, 7);
        await new Promise(r => setTimeout(r, 40));
        called += 1;
      });

      it('should take a while (2)', async () => {
        assert.strictEqual(x, 9);
        await new Promise(r => setTimeout(r, 130));
        called += 1;
      });

      it('should take a while (3)', function(cb) {
        this.timeout(2000);
        assert.strictEqual(x, 11);
        setTimeout(cb, 30);
        called += 1;
      });

      describe('Level 2', function() {
        this.timeout(2000);

        after(() => {
          x = 1;
        });

        it('should succeed', () => {
          assert.strictEqual(x, 15);
          assert.strictEqual(y, 1);
          assert.strictEqual(1, 1);
          called += 1;
        });

        let i = 0;

        it('should fail (once)', function() {
          this.retries(1000);
          i += 1;
          if (i === 1)
            assert.strictEqual(0, 1);
          called += 1;
        });

        it('should have retried', () => {
          assert(i > 1);
          called += 1;
        });
      });

      it('should happen before describe', () => {
        assert.strictEqual(x, 13);
        called += 1;
      });
    });

    describe('Level 3', function() {
      it('should skip', function() {
        this.skip();
        called += 1;
        assert.strictEqual(0, 1);
      });

      it.skip('should skip again', function() {
        called += 1;
        assert.strictEqual(0, 1);
      });

      it('should skip once more');

      it('should not skip', function() {
        assert.strictEqual(1, 1);
        called += 1;
      });
    });
  });

  describe('Global', function() {
    it('should do setImmediate', (cb) => {
      assert(typeof setImmediate === 'function');
      setImmediate(cb);
      called += 1;
    });
  });

  describe('Process', function() {
    it('should have properties', () => {
      assert(typeof process.arch === 'string' && process.arch.length > 0);
      assert(typeof process.argv0 === 'string' && process.argv0.length > 0);
      assert(Array.isArray(process.argv) && process.argv.length > 0);
      assert(process.env && typeof process.env === 'object');
      assert(typeof process.env.PATH === 'string');
      assert(typeof process.env.HOME === 'string');
      if (!IS_MOCHA) {
        assert(typeof process.env.NODE_TEST === 'string');
        assert(typeof process.env.BMOCHA === 'string');
      }
      assert(typeof process.pid === 'number');
      assert(typeof process.version === 'string' && process.version.length > 0);
      assert(process.versions && typeof process.versions === 'object');
      assert(typeof process.versions.node === 'string');
      called += 1;
    });

    it('should have streams', () => {
      assert(process.stdin && typeof process.stdin === 'object');
      assert(process.stdout && typeof process.stdout === 'object');
      assert(process.stderr && typeof process.stderr === 'object');
      assert(typeof process.stdin.on === 'function');
      assert(typeof process.stdout.write === 'function');
      assert(typeof process.stderr.write === 'function');
      called += 1;
    });

    it('should do hrtime', () => {
      assert(typeof process.hrtime === 'function');

      const [sec, ns] = process.hrtime();

      assert(typeof sec === 'number');
      assert(typeof ns === 'number');

      const result = process.hrtime([sec, ns]);
      assert(Array.isArray(result));

      assert(typeof result[0] === 'number');
      assert(typeof result[1] === 'number');
      called += 1;
    });

    if (process.browser || process.hrtime.bigint) {
      it('should do hrtime.bigint', (cb) => {
        assert(typeof process.hrtime.bigint === 'function');

        const time = process.hrtime.bigint();
        setTimeout(() => {
          assert(process.hrtime.bigint() > time);
          cb();
        }, 1);
      });
    }

    it('should get memory usage', () => {
      assert(typeof process.memoryUsage === 'function');
      const mem = process.memoryUsage();
      assert(mem && typeof mem === 'object');
      assert(typeof mem.rss === 'number');
      assert(typeof mem.heapTotal === 'number');
      assert(typeof mem.heapUsed === 'number');
      assert(typeof mem.external === 'number');
      called += 1;
    });

    it('should get uptime', () => {
      assert(typeof process.uptime === 'function');
      assert(typeof process.uptime() === 'number');
      called += 1;
    });
  });

  if (hooks) {
    describe('Performance', function() {
      it('should have perf hooks', () => {
        assert(hooks && typeof hooks === 'object');
        assert(typeof hooks.performance === 'object');
        assert(typeof hooks.performance.now() === 'number');
      });
    });
  }

  describe('FS', function() {
    it('should access file', () => {
      fs.accessSync(FILE, fs.constants.R_OK);

      assert.throws(() => {
        fs.accessSync(NOENT, fs.constants.R_OK);
      }, /ENOENT/);

      assert.throws(() => {
        fs.accessSync(ACCES, fs.constants.R_OK);
      }, process.browser ? /EACCES/ : /ENOENT/);

      called += 1;
    });

    it('should check file existence', () => {
      assert(fs.existsSync(FILE));
      assert(!fs.existsSync(NOENT));
      assert(!fs.existsSync(ACCES));

      called += 1;
    });

    it('should lstat file', () => {
      const stat = fs.lstatSync(FILE);
      assert(stat && stat.isFile());

      assert.throws(() => {
        fs.lstatSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.lstatSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);

      called += 1;
    });

    it('should read dir', () => {
      const list = fs.readdirSync(DIR);

      assert(Array.isArray(list));
      assert.notStrictEqual(list.indexOf('package.json'), -1);

      assert.throws(() => {
        fs.readdirSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.readdirSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);

      called += 1;
    });

    it('should read file', () => {
      const text = fs.readFileSync(FILE, 'utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');

      assert.throws(() => {
        fs.readFileSync(NOENT, 'utf8');
      }, /ENOENT/);

      assert.throws(() => {
        fs.readFileSync(ACCES, 'utf8');
      }, process.browser ? /EACCES/ : /ENOENT/);

      called += 1;
    });

    it('should read file (buffer)', () => {
      const raw = fs.readFileSync(FILE);

      assert(Buffer.isBuffer(raw));

      const text = raw.toString('utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');

      called += 1;
    });

    it('should stat file', () => {
      const stat = fs.statSync(FILE);
      assert(stat && stat.isFile());

      assert.throws(() => {
        fs.statSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.statSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);

      called += 1;
    });

    if (!assert.rejects)
      return;

    it('should access file (async)', async () => {
      await fsAccess(FILE, fs.constants.R_OK);

      await assert.rejects(() => {
        return fsAccess(NOENT, fs.constants.R_OK);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fsAccess(ACCES, fs.constants.R_OK);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should check file existence (async)', async () => {
      assert(await fsExists(FILE));
      assert(!await fsExists(NOENT));
      assert(!await fsExists(ACCES));
    });

    it('should lstat file (async)', async () => {
      const stat = await fsLstat(FILE);
      assert(stat && stat.isFile());

      await assert.rejects(() => {
        return fsLstat(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fsLstat(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read dir (async)', async () => {
      const list = await fsReaddir(DIR);

      assert(Array.isArray(list));
      assert.notStrictEqual(list.indexOf('package.json'), -1);

      await assert.rejects(() => {
        return fsReaddir(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fsReaddir(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file (async)', async () => {
      const text = await fsReadFile(FILE, 'utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');

      await assert.rejects(() => {
        return fsReadFile(NOENT, 'utf8');
      }, /ENOENT/);

      await assert.rejects(() => {
        return fsReadFile(ACCES, 'utf8');
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file (buffer) (async)', async () => {
      const raw = await fsReadFile(FILE);

      assert(Buffer.isBuffer(raw));

      const text = raw.toString('utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');
    });

    it('should stat file (async)', async () => {
      const stat = await fsStat(FILE);
      assert(stat && stat.isFile());

      await assert.rejects(() => {
        return fsStat(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fsStat(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });
  });

  describe('BFS', function() {
    let fs;

    try {
      fs = require('bfile');
    } catch (e) {
      return;
    }

    it('should access file', () => {
      fs.accessSync(FILE, fs.constants.R_OK);

      assert.throws(() => {
        fs.accessSync(NOENT, fs.constants.R_OK);
      }, /ENOENT/);

      assert.throws(() => {
        fs.accessSync(ACCES, fs.constants.R_OK);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should check file existence', () => {
      assert(fs.existsSync(FILE));
      assert(!fs.existsSync(NOENT));
      assert(!fs.existsSync(ACCES));
    });

    it('should lstat file', () => {
      const stat = fs.lstatSync(FILE);
      assert(stat && stat.isFile());

      assert.throws(() => {
        fs.lstatSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.lstatSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read dir', () => {
      const list = fs.readdirSync(DIR);

      assert(Array.isArray(list));
      assert.notStrictEqual(list.indexOf('package.json'), -1);

      assert.throws(() => {
        fs.readdirSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.readdirSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file', () => {
      const text = fs.readFileSync(FILE, 'utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');

      assert.throws(() => {
        fs.readFileSync(NOENT, 'utf8');
      }, /ENOENT/);

      assert.throws(() => {
        fs.readFileSync(ACCES, 'utf8');
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read json file', () => {
      const json = fs.readJSONSync(FILE);

      assert.strictEqual(json.name, 'bmocha');

      assert.throws(() => {
        fs.readJSONSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.readJSONSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file (buffer)', () => {
      const raw = fs.readFileSync(FILE);

      assert(Buffer.isBuffer(raw));

      const text = raw.toString('utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');
    });

    it('should stat file', () => {
      const stat = fs.statSync(FILE);
      assert(stat && stat.isFile());

      assert.throws(() => {
        fs.statSync(NOENT);
      }, /ENOENT/);

      assert.throws(() => {
        fs.statSync(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    if (!assert.rejects)
      return;

    it('should access file (async)', async () => {
      await fs.access(FILE, fs.constants.R_OK);

      await assert.rejects(() => {
        return fs.access(NOENT, fs.constants.R_OK);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.access(ACCES, fs.constants.R_OK);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should check file existence (async)', async () => {
      assert(await fs.exists(FILE));
      assert(!await fs.exists(NOENT));
      assert(!await fs.exists(ACCES));
    });

    it('should lstat file (async)', async () => {
      const stat = await fs.lstat(FILE);
      assert(stat && stat.isFile());

      await assert.rejects(() => {
        return fs.lstat(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.lstat(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read dir (async)', async () => {
      const list = await fs.readdir(DIR);

      assert(Array.isArray(list));
      assert.notStrictEqual(list.indexOf('package.json'), -1);

      await assert.rejects(() => {
        return fs.readdir(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.readdir(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file (async)', async () => {
      const text = await fs.readFile(FILE, 'utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');

      await assert.rejects(() => {
        return fs.readFile(NOENT, 'utf8');
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.readFile(ACCES, 'utf8');
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read json file (async)', async () => {
      const json = await fs.readJSON(FILE);

      assert.strictEqual(json.name, 'bmocha');

      await assert.rejects(() => {
        return fs.readJSON(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.readJSON(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });

    it('should read file (buffer) (async)', async () => {
      const raw = await fs.readFile(FILE);

      assert(Buffer.isBuffer(raw));

      const text = raw.toString('utf8');
      const json = JSON.parse(text);

      assert.strictEqual(json.name, 'bmocha');
    });

    it('should stat file (async)', async () => {
      const stat = await fs.stat(FILE);
      assert(stat && stat.isFile());

      await assert.rejects(() => {
        return fs.stat(NOENT);
      }, /ENOENT/);

      await assert.rejects(() => {
        return fs.stat(ACCES);
      }, process.browser ? /EACCES/ : /ENOENT/);
    });
  });

  if (process.browser) {
    describe('Worker', function() {
      it('should register worker', () => {
        assert(typeof register === 'function');

        register('/worker.js', [__dirname, 'util', 'worker.js']);
      });

      it('should create worker', (cb) => {
        const worker = new Worker('/worker.js');

        worker.onmessage = ({data}) => {
          try {
            assert(typeof data === 'string');
            assert(data === 'hello world');
            cb();
          } catch (e) {
            cb(e);
          }
        };

        worker.postMessage('hello');
      });
    });
  }

  describe('Normal Context', function(ctx) {
    it('should have context (this)', function() {
      assert(this && typeof this === 'object');
      assert(typeof this.retries === 'function');
    });

    it('should have context (this async)', async function() {
      assert(this && typeof this === 'object');
      assert(typeof this.retries === 'function');
    });

    it('should have context (this cb)', function(cb) {
      assert(this && typeof this === 'object');
      assert(typeof this.retries === 'function');
      cb();
    });

    it('should have context (ctx)', function() {
      assert(ctx && typeof ctx === 'object');
      assert(typeof ctx.retries === 'function');
    });

    it('should have context (ctx async)', async function() {
      assert(ctx && typeof ctx === 'object');
      assert(typeof ctx.retries === 'function');
    });

    it('should have context (ctx cb)', function(cb) {
      assert(ctx && typeof ctx === 'object');
      assert(typeof ctx.retries === 'function');
      cb();
    });
  });

  if (!IS_MOCHA) {
    describe('Context', function(ctx) {
      it('should have context (this)', () => {
        assert(this && typeof this === 'object');
        assert(typeof this.retries === 'function');
      });

      it('should have context (this async)', async () => {
        assert(this && typeof this === 'object');
        assert(typeof this.retries === 'function');
      });

      it('should have context (this cb)', (cb) => {
        assert(this && typeof this === 'object');
        assert(typeof this.retries === 'function');
        cb();
      });

      it('should have context (ctx)', () => {
        assert(ctx && typeof ctx === 'object');
        assert(typeof ctx.retries === 'function');
      });

      it('should have context (ctx async)', async () => {
        assert(ctx && typeof ctx === 'object');
        assert(typeof ctx.retries === 'function');
      });

      it('should have context (ctx cb)', (cb) => {
        assert(ctx && typeof ctx === 'object');
        assert(typeof ctx.retries === 'function');
        cb();
      });
    });
  }

  describe('Mocha Bugs', function() {
    it('should do callback and then throw', function(cb) {
      cb();
      throw new Error('foo');
    });
  });

  describe('Paranoia', function() {
    it('should have called a total number of tests', () => {
      assert.strictEqual(called, TOTAL_TESTS);
    });
  });
});
