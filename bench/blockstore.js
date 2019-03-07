/*!
 * bench/blockstore.js - benchmark blockstore for bcoin
 *
 * This can be run to benchmark the performance of the blockstore
 * module for writing, reading and pruning block data. Results are
 * written to stdout as JSON or formated bench results.
 *
 * Usage:
 * node ./blockstore.js [--maxfile=<bytes>] [--total=<bytes>]
 *                      [--location=<path>] [--store=<name>]
 *                      [--output=<name>] [--unsafe]
 *
 * Options:
 * - `maxfile`  The maximum file size (applies to "file" store).
 * - `total`    The total number of block bytes to write.
 * - `location` The location to store block data.
 * - `store`    This can be "file" or "level".
 * - `output`   This can be "json", "bench" or "benchjson".
 * - `unsafe`   This will allocate block data directly from memory
 *              instead of random, it is faster.
 *
 * Copyright (c) 2019, Braydon Fuller (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

process.title = 'blockstore-bench';

const {isAbsolute} = require('path');
const {mkdirp} = require('bfile');
const random = require('bcrypto/lib/random');
const {BufferMap} = require('buffer-map');

const {
  FileBlockStore,
  LevelBlockStore
} = require('../lib/blockstore');

const config = {
  'maxfile': {
    value: true,
    parse: a => parseInt(a),
    valid: a => Number.isSafeInteger(a),
    fallback: 128 * 1024 * 1024
  },
  'total': {
    value: true,
    parse: a => parseInt(a),
    valid: a => Number.isSafeInteger(a),
    fallback: 3 * 1024 * 1024 * 1024
  },
  'location': {
    value: true,
    valid: a => isAbsolute(a),
    fallback: '/tmp/bcoin-bench-blockstore'
  },
  'store': {
    value: true,
    valid: a => (a === 'file' || a === 'level'),
    fallback: 'file'
  },
  'output': {
    value: true,
    valid: a => (a === 'json' || a === 'bench' || a === 'benchjson'),
    fallback: 'bench'
  },
  'unsafe': {
    value: false,
    valid: a => (a === true || a === false),
    fallback: false
  }
};

/**
 * These block sizes were generated from bitcoin mainnet blocks by putting
 * sizes into bins of 256 ^ (2 * n) as the upper bound and calculating
 * the percentage of each and then distributing to roughly match the
 * percentage of the following:
 *
 * |-------------|------------|
 * | percentage  | bytes      |
 * |-------------|------------|
 * | 23.4055     | 1048576    |
 * | 15.5338     | 256        |
 * | 12.2182     | 262144     |
 * | 8.4079      | 524288     |
 * | 7.1289      | 131072     |
 * | 6.9197      | 65536      |
 * | 6.7073      | 2097152    |
 * | 4.6753      | 32768      |
 * | 3.9695      | 4096       |
 * | 3.3885      | 16384      |
 * | 2.6526      | 8192       |
 * | 2.0048      | 512        |
 * | 1.587       | 1024       |
 * | 1.3976      | 2048       |
 * | 0.0032      | 4194304    |
 * |-------------|------------|
 */

const distribution = [
  1048576, 256, 256, 524288, 262144, 256, 131072, 256, 524288, 256, 131072,
  1048576, 262144, 1048576, 2097152, 256, 1048576, 65536, 256, 262144, 8192,
  32768, 32768, 256, 1048576, 524288, 2097152, 1024, 1048576, 1048576, 131072,
  131072, 262144, 512, 1048576, 1048576, 1024, 1048576, 1048576, 262144, 2048,
  262144, 256, 1048576, 131072, 4096, 524288, 65536, 4096, 65536, 131072,
  2097152, 2097152, 2097152, 256, 524288, 4096, 262144, 65536, 65536, 262144,
  16384, 1048576, 32768, 262144, 1048576, 256, 131072, 1048576, 1048576,
  1048576, 8192, 1048576, 256, 16384, 1048576, 256, 256, 524288, 256, 32768,
  16384, 32768, 1048576, 512, 4096, 1048576, 1048576, 524288, 65536, 2097152,
  512, 262144, 8192, 524288, 131072, 65536, 16384, 2048, 262144, 1048576,
  1048576, 256, 524288, 262144, 4194304, 262144, 2097152
];

(async () => {
  let settings = null;
  try {
    settings = processArgs(process.argv, config);
  } catch (err) {
    console.log(err.message);
    process.exit(1);
  }

  await mkdirp(settings.location);

  let store = null;
  let output = null;

  if (settings.store === 'file') {
    store = new FileBlockStore({
      location: settings.location,
      maxFileLength: settings.maxfile
    });
  } else if (settings.store === 'level') {
    store = new LevelBlockStore({
      location: settings.location
    });
  }

  if (settings.output === 'bench') {
    output = new BenchOutput();
  } else if (settings.output === 'benchjson') {
    output = new BenchJSONOutput();
  } else if (settings.output === 'json') {
    output = new JSONOutput();
  }

  await store.open();

  const hashes = [];
  const lengths = new BufferMap();

  output.start();

  // 1. Write data to the block store
  let written = 0;

  async function write() {
    for (const length of distribution) {
      const hash = random.randomBytes(32);
      let raw = null;
      if (settings.unsafe) {
        raw = Buffer.allocUnsafe(length);
      } else {
        raw = random.randomBytes(length);
      }

      const start = process.hrtime();
      await store.write(hash, raw);
      const elapsed = process.hrtime(start);

      hashes.push(hash);
      lengths.set(hash, length);
      written += length;

      output.result('write', start, elapsed, length);

      if (written >= settings.total)
        break;
    }
  }

  while (written < settings.total)
    await write();

  // 2. Read data from the block store
  for (const hash of hashes) {
    const start = process.hrtime();
    const raw = await store.read(hash);
    const elapsed = process.hrtime(start);

    output.result('read', start, elapsed, raw.length);
  }

  // 3. Read data not in the order it was written (random)
  for (let i = 0; i < hashes.length; i++) {
    const rand = random.randomInt() / 0xffffffff * (hashes.length - 1) | 0;
    const hash = hashes[rand];

    const start = process.hrtime();
    const raw = await store.read(hash);
    const elapsed = process.hrtime(start);

    output.result('randomread', start, elapsed, raw.length);
  }

  // 4. Prune data from the block store
  for (const hash of hashes) {
    const start = process.hrtime();
    await store.prune(hash);
    const elapsed = process.hrtime(start);
    const length = lengths.get(hash);

    output.result('prune', start, elapsed, length);
  }

  output.end();

  await store.close();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});

class JSONOutput {
  constructor() {
    this.time = process.hrtime();
    this.index = 0;
  }

  start() {
    process.stdout.write('[');
  }

  result(type, start, elapsed, length) {
    if (this.index > 0)
      process.stdout.write(',');

    const since = [start[0] - this.time[0], start[1] - this.time[1]];
    const smicro = hrToMicro(since);
    const emicro = hrToMicro(elapsed);

    process.stdout.write(`{"type":"${type}","start":${smicro},`);
    process.stdout.write(`"elapsed":${emicro},"length":${length},`);
    process.stdout.write(`"index":${this.index}}`);

    this.index += 1;
  }

  end() {
    process.stdout.write(']');
  }
}

class BenchOutput {
  constructor() {
    this.time = process.hrtime();
    this.index = 0;
    this.results = {};
    this.interval = null;
    this.stdout = process.stdout;
  }

  start() {
    this.stdout.write('Starting benchmark...\n');
    this.interval = setInterval(() => {
      this.stdout.write(`Operation count=${this.index}\n`);
    }, 5000);
  }

  result(type, start, elapsed, length) {
    const micro = hrToMicro(elapsed);

    if (!this.results[type])
      this.results[type] = {};

    if (!this.results[type][length])
      this.results[type][length] = [];

    this.results[type][length].push(micro);

    this.index += 1;
  }

  end() {
    clearInterval(this.interval);

    this.stdout.write('Benchmark finished.\n');

    function format(value) {
      if (typeof value === 'number')
        value = value.toFixed(2);

      if (typeof value !== 'string')
        value = value.toString();

      while (value.length < 15)
        value = `${value} `;

      return value;
    }

    function title(value) {
      if (typeof value !== 'string')
        value = value.toString();

      while (value.length < 85)
        value = ` ${value} `;

      if (value.length > 85)
        value = value.slice(0, 85);

      return value;
    }

    for (const type in this.results) {
      this.stdout.write('\n');
      this.stdout.write(`${title(type)}\n`);
      this.stdout.write(`${'='.repeat(85)}\n`);
      this.stdout.write(`${format('length')}`);
      this.stdout.write(`${format('operations')}`);
      this.stdout.write(`${format('min')}`);
      this.stdout.write(`${format('max')}`);
      this.stdout.write(`${format('average')}`);
      this.stdout.write(`${format('median')}`);
      this.stdout.write('\n');
      this.stdout.write(`${'-'.repeat(85)}\n`);

      for (const length in this.results[type]) {
        const cal = calculate(this.results[type][length]);

        this.stdout.write(`${format(length)}`);
        this.stdout.write(`${format(cal.operations.toString())}`);
        this.stdout.write(`${format(cal.min)}`);
        this.stdout.write(`${format(cal.max)}`);
        this.stdout.write(`${format(cal.average)}`);
        this.stdout.write(`${format(cal.median)}`);
        this.stdout.write('\n');
      }
      this.stdout.write('\n');
    }
    this.stdout.write('\n');
  }
}

class BenchJSONOutput {
  constructor() {
    this.time = null;
    this.results = {};
    this.stdout = process.stdout;
  }

  start() {
    this.time = process.hrtime();
  }

  result(type, start, elapsed, length) {
    const micro = hrToMicro(elapsed);

    if (!this.results[type])
      this.results[type] = {};

    if (!this.results[type][length])
      this.results[type][length] = [];

    this.results[type][length].push(micro);
  }

  end() {
    const report = {
      summary: [],
      time: hrToMicro(process.hrtime(this.time)),
      elapsed: 0
    };

    for (const type in this.results) {
      for (const length in this.results[type]) {
        const cal = calculate(this.results[type][length]);

        report.elapsed += cal.total;

        report.summary.push({
          type: type,
          length: length,
          operations: cal.operations,
          min: cal.min,
          max: cal.max,
          average: cal.average,
          median: cal.median
        });
      }
    }

    this.stdout.write(JSON.stringify(report, null, 2));
    this.stdout.write('\n');
  }
}

function hrToMicro(time) {
  return (time[0] * 1000000) + (time[1] / 1000);
}

function calculate(times) {
  times.sort((a, b) => a - b);

  let min = Infinity;
  let max = 0;

  let total = 0;

  for (const micro of times) {
    if (micro < min)
      min = micro;

    if (micro > max)
      max = micro;

    total += micro;
  }

  const average = total / times.length;
  const median = times[times.length / 2 | 0];
  const operations = times.length;

  return {
    total,
    operations,
    min,
    max,
    average,
    median
  };
}

function processArgs(argv, config) {
  const args = {};

  for (const key in config)
    args[key] = config[key].fallback;

  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    const match = arg.match(/^(\-){1,2}([a-z]+)(\=)?(.*)?$/);

    if (!match) {
      throw new Error(`Unexpected argument: ${arg}.`);
    } else {
      const key = match[2];
      let value = match[4];

      if (!config[key])
        throw new Error(`Invalid argument: ${arg}.`);

      if (config[key].value && !value) {
        value = process.argv[i + 1];
        i++;
      } else if (!config[key].value && !value) {
        value = true;
      } else if (!config[key].value && value) {
        throw new Error(`Unexpected value: ${key}=${value}`);
      }

      if (config[key].parse)
        value = config[key].parse(value);

      if (value)
        args[key] = value;

      if (!config[key].valid(args[key]))
        throw new Error(`Invalid value: ${key}=${value}`);
    }
  }

  return args;
}
