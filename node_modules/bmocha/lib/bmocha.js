/*!
 * bmocha.js - alternative mocha implementation
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bmocha
 *
 * Parts of this software are based on mochajs/mocha:
 *   Copyright (c) 2011-2018, JS Foundation and contributors
 *   https://github.com/mochajs/mocha
 */

/* eslint no-control-regex: "off" */
/* eslint no-ex-assign: "off" */

'use strict';

const util = require('./util');

const {
  assert,
  get,
  nextTick,
  isPromise,
  inject,
  restore,
  stackError,
  noop,
  indent,
  singlify,
  escape,
  clean,
  toError,
  toMessage,
  toStack,
  errorify,
  stackify,
  jsonify,
  isShowable,
  show,
  inspect,
  why
} = util;

/*
 * Globals
 */

const {
  Array,
  Boolean,
  clearTimeout,
  Date,
  Error,
  JSON,
  Math,
  Object,
  Promise,
  RegExp,
  setTimeout,
  String
} = global;

/*
 * Constants
 */

const style = {
  __proto__: null,
  title: 'bmocha',
  font: 'monospace',
  fg: '#000000', // #eeeeee
  bg: '#ffffff', // #111111
  colors: [
    '#2e3436', // black
    '#cc0000', // red
    '#4e9a06', // green
    '#c4a000', // yellow
    '#3465a4', // blue
    '#75507b', // magenta
    '#06989a', // cyan
    '#d3d7cf', // white
    '#555753', // bright black
    '#ef2929', // bright red
    '#8ae234', // bright green
    '#fce94f', // bright yellow
    '#729fcf', // bright blue
    '#ad7fa8', // bright magenta
    '#34e2e2', // bright cyan
    '#eeeeec'  // bright white
  ]
};

const colors = {
  __proto__: null,
  suite: 0,
  title: 0,
  plane: 0,
  fail: 31,
  crash: 31,
  slow: 31,
  message: 31,
  checkmark: 32,
  green: 32,
  medium: 33,
  pending: 36,
  light: 90,
  fast: 90,
  stack: 90,
  pass: 90,
  runway: 90,
  progress: 90,
  warning: 93
};

const symbolsUnix = {
  __proto__: null,
  ok: '\u2713',
  err: '\u2716',
  dot: '\u2024',
  dash: '-',
  comma: ',',
  bang: '!',
  plane: '\u2708',
  runway: '\u22c5',
  open: '[',
  complete: '\u25ac',
  incomplete: '\u2024',
  close: ']'
};

const symbolsWindows = {
  __proto__: null,
  ok: '\u221a',
  err: '\u00d7',
  dot: '.',
  dash: '-',
  comma: ',',
  bang: '!',
  plane: '\u2708',
  runway: '\u22c5',
  open: '[',
  complete: '\u25ac',
  incomplete: '.',
  close: ']'
};

const PENDING = new Error('pending');

/**
 * Runnable
 */

class Runnable {
  constructor() {
    this.mocha = null;
    this.suite = null;
    this.parent = null;
    this.name = '';
    this.title = '';
    this.matching = false;
    this.depth = 0;
    this.slow = 0;
    this.timeout = 0;
    this.timeouts = false;
    this.retries = 0;
    this.skippable = false;
    this.skip = false;
    this.only = false;
    this.running = false;
    this.stats = null;
    this.context = null;
  }

  get duration() {
    return this.stats.duration;
  }

  get elapsed() {
    return this.stats.elapsed;
  }

  get speed() {
    if (this.duration > this.slow)
      return 'slow';

    if (this.duration > (this.slow >>> 1))
      return 'medium';

    return 'fast';
  }

  titlePath() {
    const path = [this.title];

    let parent = this.parent;

    while (parent) {
      if (parent.title)
        path.push(parent.title);
      parent = parent.parent;
    }

    return path.reverse();
  }

  fullTitle() {
    return this.titlePath().join(' ');
  }
}

/**
 * Mocha
 */

class Mocha extends Runnable {
  constructor(options) {
    super();

    // Runnable Properties
    this.mocha = this;
    this.suite = null;
    this.parent = null;
    this.name = '';
    this.title = '';
    this.matching = false;
    this.depth = -1;
    this.slow = 75;
    this.timeout = 2000;
    this.timeouts = true;
    this.retries = 0;
    this.skippable = false;
    this.skip = false;
    this.only = false;
    this.running = false;
    this.stats = new Stats();
    this.context = new MochaContext(this);

    // Mocha Options
    this.allowMultiple = false;
    this.asyncOnly = false;
    this.bail = false;
    this.catcher = this._catcher.bind(this);
    this.checkLeaks = false;
    this.colors = false;
    this.delay = false;
    this.diff = true;
    this.exit = this._exit.bind(this);
    this.fgrep = '';
    this.forbidOnly = false;
    this.forbidPending = false;
    this.fullTrace = false;
    this.global = true;
    this.globals = [];
    this.grep = null;
    this.invert = false;
    this.notify = null;
    this.reporter = 'spec';
    this.reporterOptions = Object.create(null);
    this.retries;
    this.slow;
    this.stream = new Stream();
    this.swallow = true;
    this.timeout;
    this.timeouts;
    this.why = false;
    this.windows = false;

    // State
    this.report = null;
    this.current = null;
    this.exclusive = false;
    this.beforeEaches = [];
    this.afterEaches = [];
    this.results = [];
    this.errors = [];
    this.test = null;
    this.uncatcher = null;
    this.aborters = [];
    this.runCalled = false;
    this.runResolve = null;

    // API
    this.before = this._before.bind(this);
    this.after = this._after.bind(this);
    this.beforeEach = this._beforeEach.bind(this);
    this.afterEach = this._afterEach.bind(this);
    this.describe = this._describe.bind(this);
    this.it = this._it.bind(this);
    this.doRun = this._doRun.bind(this);

    this.init();
    this.set(options);
  }

  init() {
    for (const method of [this.describe, this.it]) {
      method.only = function only(title, func) {
        return method(title, func, 'only', only);
      };

      method.skip = function skip(title, func) {
        return method(title, func, 'skip', skip);
      };
    }
  }

  set(options) {
    if (options == null)
      return this;

    if (typeof options === 'function'
        || typeof options === 'string') {
      options = { reporter: options };
    }

    assert(typeof options === 'object');

    if (typeof options.write === 'function')
      options = { stream: options };

    if (options.allowMultiple != null)
      this.allowMultiple = Boolean(options.allowMultiple);

    if (options.asyncOnly != null)
      this.asyncOnly = Boolean(options.asyncOnly);

    if (options.bail != null)
      this.bail = Boolean(options.bail);

    if (typeof options.catcher === 'function')
      this.catcher = options.catcher;

    if (options.checkLeaks != null)
      this.checkLeaks = Boolean(options.checkLeaks);

    if (options.colors != null)
      this.colors = Boolean(options.colors);

    if (options.delay != null)
      this.delay = Boolean(options.delay);

    if (options.diff != null)
      this.diff = Boolean(options.diff);

    if (typeof options.exit === 'function')
      this.exit = options.exit;

    if (options.fgrep != null)
      this.fgrep = String(options.fgrep);

    if (options.forbidOnly != null)
      this.forbidOnly = Boolean(options.forbidOnly);

    if (options.forbidPending != null)
      this.forbidPending = Boolean(options.forbidPending);

    if (options.fullTrace != null)
      this.fullTrace = Boolean(options.fullTrace);

    if (options.global != null)
      this.global = Boolean(options.global);

    if (Array.isArray(options.globals))
      this.globals = options.globals.slice();

    if (options.grep != null)
      this.grep = RegExp(options.grep);

    if (options.invert != null)
      this.invert = Boolean(options.invert);

    if (typeof options.notify === 'function')
      this.notify = options.notify;

    if (options.reporter != null)
      this.reporter = Base.get(options.reporter).id;

    if (options.reporterOptions != null) {
      assert(options.reporterOptions);
      assert(typeof options.reporterOptions === 'object');
      this.reporterOptions = options.reporterOptions;
    }

    if (options.retries != null)
      this.retries = options.retries >>> 0;

    if (options.slow != null)
      this.slow = options.slow >>> 0;

    if (options.stream != null) {
      assert(typeof options.stream.write === 'function');

      this.stream = options.stream;

      if (options.colors == null)
        this.colors = Boolean(options.stream.isTTY);
    }

    if (options.swallow != null)
      this.swallow = Boolean(options.swallow);

    if (options.timeout != null)
      this.timeout = options.timeout >>> 0;

    if (options.timeouts != null)
      this.timeouts = Boolean(options.timeouts);

    if (options.why != null)
      this.why = Boolean(options.why);

    if (options.windows != null)
      this.windows = Boolean(options.windows);

    return this;
  }

  _suite() {
    if (!this.current)
      throw new Error('No suite is currently initializing.');
    return this.current;
  }

  _before(desc, func) {
    return this._suite().before(desc, func, this._before);
  }

  _after(desc, func) {
    return this._suite().after(desc, func, this._after);
  }

  _beforeEach(desc, func) {
    return this._suite().beforeEach(desc, func, this._beforeEach);
  }

  _afterEach(desc, func) {
    return this._suite().afterEach(desc, func, this._afterEach);
  }

  _describe(title, func, action) {
    return this._suite().describe(title, func, action, this._describe);
  }

  _it(title, func, action) {
    return this._suite().it(title, func, action, this._it);
  }

  globalize() {
    if (!this.global)
      return null;

    return inject(global, {
      // API
      before: this.before,
      after: this.after,
      beforeEach: this.beforeEach,
      afterEach: this.afterEach,
      describe: this.describe,
      it: this.it,

      // Aliases
      xdescribe: this.describe.skip,
      xit: this.it.skip,
      specify: this.it,

      // Runner
      run: this.delay ? this.doRun : undefined
    });
  }

  unglobalize(snapshot) {
    if (this.global)
      restore(global, snapshot);

    return this;
  }

  _catcher(reject) {
    return null;
  }

  _exit(code) {
    throw new Error(`Test suite failed: ${code >>> 0}.`);
  }

  catch() {
    if (this.global && !this.uncatcher) {
      const reject = this.reject.bind(this);
      this.uncatcher = this.catcher(reject, this.allowMultiple);
    }

    return this;
  }

  uncatch() {
    const uncatcher = this.uncatcher;

    if (uncatcher) {
      this.uncatcher = null;
      uncatcher();
    }

    return this;
  }

  reject(error) {
    if (this.test) {
      // If we have a running test, reject it.
      // This usually means an uncaught exception
      // or an unhandled rejection.
      if (this.test.job && !this.test.job.done) {
        this.test.job.reject(error);
        return;
      }

      // Otherwise, inject into our last test.
      // This is usually triggered by the "multiple
      // resolves" event.
      if (!this.test.fail) {
        this.test.setError(toError(error));
        return;
      }
    }

    // Fallback to "global" error system.
    // Something happening in the background
    // that we can't get a hold on?
    this.error(error);
  }

  error(error) {
    const err = toError(error);

    // If the suite is still running, push
    // onto an array for the reporter to
    // display.
    if (this.running) {
      this.errors.push(err);
      this.stats.failures += 1;
      return;
    }

    // Last resort: print the error to
    // stdout and exit.
    this.report.exception(err);
    this.exit(1);
  }

  matches(title) {
    assert(typeof title === 'string');

    let ret = !this.invert;

    if (this.grep)
      ret = this.grep.test(title);
    else if (this.fgrep)
      ret = title.includes(this.fgrep);

    if (this.invert)
      ret = !ret;

    return ret;
  }

  _doRun() {
    if (this.runCalled) {
      // Note: mocha doesn't throw at all here.
      throw stackError(this._doRun, 'run() called twice!');
    }

    this.runCalled = true;

    if (this.runResolve)
      this.runResolve();
  }

  async waitForRun() {
    if (this.runCalled)
      return undefined;

    return new Promise((resolve) => {
      this.current = this.suite;

      this.runResolve = () => {
        this.current = null;
        this.runResolve = null;

        resolve();
      };
    });
  }

  async run(funcs) {
    const Reporter = Base.get(this.reporter);

    this.stats = new Stats();
    this.results = [];
    this.errors = [];
    this.exclusive = false;
    this.runResolve = null;
    this.runCalled = false;

    this.report = new Reporter(this.stream, this.reporterOptions);
    this.report.stats = this.stats;
    this.report.colors = this.colors;
    this.report.diff = this.diff;
    this.report.fullTrace = this.fullTrace;
    this.report.windows = this.windows;

    this.suite = new Suite(this);

    // Track async hooks.
    let calls = null;

    if (this.why)
      calls = why();

    // Inject globals.
    const save = this.globalize();

    try {
      await this.suite.initAsync(funcs);
    } catch (e) {
      this.unglobalize(save);

      const err = toError(e);

      err.uncaught = true;
      err.exception = true;

      this.report.exception(err);

      return 1;
    }

    // Start catching all errors.
    this.catch();

    // Wait for run() call if
    // we're delaying things.
    if (this.delay)
      await this.waitForRun();

    // Revert globals.
    this.unglobalize(save);

    this.running = true;
    this.stats.mark();
    this.stats.total = this.suite.total();

    if (this.stats.total > 0)
      this.report.start(this);

    await this.suite.run();

    this.stats.mark();

    // Maybe send notification.
    if (this.notify) {
      try {
        await this.notify(this.stats);
      } catch (e) {
        this.error(e);
      }
    }

    // Unbinding to the error events in
    // node can cause some errors to get
    // missed. Only unbind if we're not
    // "global".
    if (!this.global)
      this.uncatch();

    this.running = false;

    if (this.stats.total > 0)
      this.report.end(this);

    if (calls) {
      await nextTick();
      this.report.why(calls());
    }

    if (this.isAborting)
      this.doAbort();

    return Math.min(this.stats.failures, 255);
  }

  async abort() {
    return new Promise((resolve, reject) => {
      if (!this.running) {
        resolve();
        return;
      }

      this.aborters.push(resolve);
    });
  }

  get isAborting() {
    return this.aborters.length > 0;
  }

  doAbort() {
    const aborters = this.aborters;

    this.aborters = [];

    for (const abort of aborters)
      abort();
  }
}

/**
 * Suite
 */

class Suite extends Runnable {
  constructor(parent, title = '', start) {
    assert((parent instanceof Mocha)
        || (parent instanceof Suite));

    if (typeof title !== 'string')
      throw stackError(start, 'Must provide a title for suite.');

    if (/[\x00-\x1f\x7f]/.test(title))
      throw stackError(start, 'Invalid suite title.');

    super();

    this.mocha = parent.mocha;
    this.suite = this;
    this.parent = parent;
    this.name = '';
    this.title = title;
    this.matching = parent.matching || parent.mocha.matches(title);
    this.depth = parent.depth + 1;
    this.slow = parent.slow;
    this.timeout = parent.timeout;
    this.timeouts = parent.timeouts;
    this.retries = parent.retries;
    this.skippable = parent.skippable;
    this.only = parent.only;
    this.running = false;
    this.stats = new Stats();
    this.context = new Context(this);

    this.root = this.depth === 0;
    this.befores = [];
    this.afters = [];
    this.beforeEaches = parent.beforeEaches.slice();
    this.afterEaches = parent.afterEaches.slice();
    this.tests = [];
    this.suites = [];
  }

  before(desc, func, start) {
    if (typeof desc === 'function')
      [desc, func] = [func, desc];

    const hook = new Hook(this, 'before all', desc, func, start);

    this.befores.push(hook);
  }

  after(desc, func, start) {
    if (typeof desc === 'function')
      [desc, func] = [func, desc];

    const hook = new Hook(this, 'after all', desc, func, start);

    this.afters.push(hook);
  }

  beforeEach(desc, func, start) {
    if (typeof desc === 'function')
      [desc, func] = [func, desc];

    const hook = new Hook(this, 'before each', desc, func, start);

    this.beforeEaches.push(hook);
  }

  afterEach(desc, func, start) {
    if (typeof desc === 'function')
      [desc, func] = [func, desc];

    const hook = new Hook(this, 'after each', desc, func, start);

    this.afterEaches.push(hook);
  }

  describe(title, func, action, start) {
    const suite = new Suite(this, title, start);

    if (action === 'only')
      suite.context.only();
    else if (action === 'skip')
      suite.context.skip();
    else if (action != null)
      throw stackError(start, `Invalid action: ${action}`);

    if (typeof func !== 'function') {
      throw stackError(start,
        `Suite ${suite.fullTitle()} was `
        + 'defined but no callback was '
        + 'supplied. Supply a callback '
        + 'or explicitly skip the suite.');
    }

    suite.init(func, start);

    this.suites.push(suite);

    return suite.context;
  }

  it(title, func, action, start) {
    if (func == null) {
      func = noop;
      action = 'skip';
    }

    const test = new Test(this, title, func, start);

    if (action === 'only')
      test.context.only();
    else if (action === 'skip')
      test.context.skip();
    else if (action != null)
      throw stackError(start, `Invalid action: ${action}`);

    this.tests.push(test);

    return test.context;
  }

  init(funcs, start) {
    if (typeof funcs === 'function')
      funcs = [funcs];

    assert(Array.isArray(funcs));

    for (const func of funcs)
      assert(typeof func === 'function');

    const ctx = this.mocha.context;
    const current = this.mocha.current;

    this.mocha.current = this;

    try {
      for (const func of funcs) {
        const result = func.call(ctx, ctx);

        if (isPromise(result))
          throw stackError(start, 'Cannot resolve asynchronous test suites.');
      }
    } finally {
      this.mocha.current = current;
    }

    return this;
  }

  async initAsync(funcs) {
    if (typeof funcs === 'function')
      funcs = [funcs];

    assert(Array.isArray(funcs));

    for (const func of funcs)
      assert(typeof func === 'function');

    const ctx = this.mocha.context;
    const current = this.mocha.current;

    this.mocha.current = this;

    try {
      for (const func of funcs)
        await func.call(ctx, ctx);
    } finally {
      this.mocha.current = current;
    }

    return this;
  }

  total() {
    let count = 0;

    for (const test of this.tests) {
      if (this.mocha.exclusive && !test.only)
        continue;

      if (!test.matching)
        continue;

      count += 1;
    }

    for (const suite of this.suites)
      count += suite.total();

    return count;
  }

  succeed(test) {
    assert(test instanceof Executable);

    if (test.skip)
      this.mocha.stats.pending += 1;
    else
      this.mocha.stats.passes += 1;

    this.mocha.stats.tests += 1;
    this.mocha.results.push(test);

    this.mocha.report.testEnd(test);
  }

  fail(test) {
    assert(test instanceof Executable);

    if (this.mocha.isAborting)
      return false;

    this.mocha.stats.failures += 1;
    this.mocha.stats.tests += 1;
    this.mocha.results.push(test);

    this.mocha.report.testEnd(test);

    return !this.mocha.bail;
  }

  async run() {
    if (this.total() === 0)
      return true;

    this.stats = new Stats();

    this.running = true;
    this.stats.mark();

    if (!this.root)
      this.mocha.stats.suites += 1;

    this.mocha.report.suiteStart(this);

    const ok = await this.exec();

    this.stats.mark();
    this.running = false;

    this.mocha.report.suiteEnd(this);

    return ok;
  }

  async exec() {
    for (const hook of this.befores) {
      if (!await hook.run())
        return this.fail(hook);
    }

    for (const test of this.tests) {
      if (this.mocha.exclusive && !test.only)
        continue;

      if (!test.matching)
        continue;

      this.mocha.report.testStart(test);

      let success = false;

      for (let retry = 0; retry < test.retries + 1; retry++) {
        for (const hook of this.beforeEaches) {
          if (!await hook.run(test))
            return this.fail(hook);
        }

        success = await test.run(retry);

        for (const hook of this.afterEaches) {
          if (!await hook.run(test))
            return this.fail(hook);
        }

        if (success)
          break;
      }

      if (success) {
        this.succeed(test);
        continue;
      }

      if (!this.fail(test))
        return false;
    }

    for (const suite of this.suites) {
      if (!await suite.run())
        return false;
    }

    for (const hook of this.afters) {
      if (!await hook.run())
        return this.fail(hook);
    }

    return true;
  }
}

/**
 * Executable
 */

class Executable extends Runnable {
  constructor(parent, name, title, body) {
    assert(parent instanceof Suite);
    assert(typeof name === 'string');
    assert(typeof title === 'string');
    assert(typeof body === 'function');

    super();

    this.mocha = parent.mocha;
    this.suite = parent;
    this.parent = parent;
    this.name = name;
    this.title = title;
    this.matching = parent.matching || parent.mocha.matches(title);
    this.depth = parent.depth;
    this.slow = parent.slow;
    this.timeout = parent.timeout;
    this.timeouts = parent.timeouts;
    this.retries = parent.retries;
    this.skippable = parent.skippable;
    this.only = parent.only;
    this.running = false;
    this.stats = new Stats();
    this.context = new Context(this);

    this.body = body;
    this.job = null;
    this.retry = 0;
    this.fail = false;
    this.error = null;
    this.swallowed = null;
  }

  setError(err) {
    assert(err instanceof Error);

    this.skip = false;
    this.fail = true;
    this.error = err;
    this.swallowed = null;
  }

  getGlobals() {
    if (!this.mocha.checkLeaks)
      return null;

    return Object.keys(global);
  }

  checkGlobals(snapshot) {
    if (!this.mocha.checkLeaks)
      return;

    const globals = Object.keys(global);
    const leaks = [];

    for (const name of globals) {
      if (snapshot.includes(name))
        continue;

      if (this.mocha.globals.includes(name))
        continue;

      leaks.push(name);
    }

    if (leaks.length === 0)
      return;

    this.setError(new Error(`global leaks detected: ${leaks.join(', ')}`));
  }

  async exec() {
    return new Promise((resolve, reject) => {
      if (this.mocha.isAborting) {
        resolve();
        return;
      }

      if (this.mocha.forbidOnly && this.only) {
        reject(new Error('`.only` forbidden'));
        return;
      }

      if (this.skippable) {
        this.skip = true;
        resolve();
        return;
      }

      const ctx = this.context;
      const job = new Job(this, resolve, reject);

      if (this.body.length > 0) {
        const done = job.callback();

        let result;

        try {
          result = this.body.call(ctx, done);
        } catch (e) {
          if (this.mocha.swallow) {
            // No idea why, but mocha behaves
            // this way for some reason and
            // _swallows the error_ if the callback
            // has already been called synchronously.
            // I repeat: mocha SWALLOWS THE ERROR.
            // Update: it seems that the mocha devs
            // are aware of this. See:
            // https://github.com/mochajs/mocha/issues/3226
            if (job.called && e !== PENDING) {
              this.swallowed = toError(e);
              return;
            }
          }
          job.reject(e);
          return;
        }

        if (isPromise(result)) {
          job.reject(new Error(''
            + 'Resolution method is overspecified. '
            + 'Specify a callback *or* return a '
            + 'Promise; not both.'));
          return;
        }
      } else {
        let result;

        try {
          result = this.body.call(ctx);
        } catch (e) {
          job.reject(e);
          return;
        }

        if (!isPromise(result)) {
          if (this.mocha.asyncOnly) {
            job.reject(new Error(''
              + '--async-only option in use '
              + 'without declaring `done()` '
              + 'or returning a promise'));
            return;
          }
          job.resolve();
          return;
        }

        const onResolve = () => {
          job.resolve();
          return null;
        };

        const onReject = (err) => {
          if (!err)
            err = new Error('Promise rejected with no or falsy reason');

          job.reject(err);
        };

        try {
          result.then(onResolve, onReject);
        } catch (e) {
          job.reject(e);
          return;
        }
      }

      job.start();
    });
  }

  async run() {
    this.stats = new Stats();

    this.skip = false;
    this.fail = false;
    this.error = null;
    this.swallowed = null;

    this.running = true;
    this.stats.mark();

    this.mocha.test = this;

    const snapshot = this.getGlobals();

    try {
      await this.exec();
    } catch (e) {
      if (e !== PENDING)
        this.setError(toError(e));
    }

    if (this.mocha.forbidPending && this.skip)
      this.setError(new Error('Pending test forbidden'));

    this.checkGlobals(snapshot);

    await nextTick();

    this.mocha.test = null;

    this.stats.mark();
    this.running = false;

    if (this.mocha.isAborting)
      return false;

    return !this.fail;
  }

  toJSON(minimal = false) {
    assert(typeof minimal === 'boolean');

    let err, stack;

    if (this.fail) {
      const json = jsonify(this.error, this.mocha.fullTrace);

      if (minimal) {
        err = json.message;
        stack = json.stack;
      } else {
        err = json;
      }
    } else {
      if (!minimal)
        err = {};
    }

    return {
      title: this.title,
      fullTitle: this.fullTitle(),
      duration: this.stats.duration,
      currentRetry: this.retry,
      err,
      stack
    };
  }
}

/**
 * Hook
 */

class Hook extends Executable {
  constructor(parent, type, desc, body, start) {
    if (desc == null)
      desc = '';

    assert(typeof type === 'string');

    if (typeof desc !== 'string')
      throw stackError(start, 'Must provide a description for hook.');

    if (typeof body !== 'function')
      throw stackError(start, 'Must provide a callback for hook.');

    if (/[\x00-\x1f\x7f]/.test(desc))
      throw stackError(start, 'Invalid hook description.');

    let name = `"${type}" hook`;

    if (!desc && body.name)
      desc = body.name;

    if (desc)
      name += `: ${desc}`;

    super(parent, name, '', body);
  }

  async run(test) {
    assert(test == null || (test instanceof Test));

    if (test) {
      this.context = test.context;
      this.title = `${this.name} for "${test.title}"`;
    } else {
      this.context = this.suite.context;
      this.title = this.name;
    }

    return super.run();
  }
}

/**
 * Test
 */

class Test extends Executable {
  constructor(parent, title, body, start) {
    if (typeof title !== 'string')
      throw stackError(start, 'Must provide a title for test.');

    if (typeof body !== 'function')
      throw stackError(start, 'Must provide a callback for test.');

    // Note:
    // Temporary hack to get
    // bcoin tests passing.
    title = singlify(title);

    if (/[\x00-\x1f\x7f]/.test(title))
      throw stackError(start, 'Invalid test title.');

    super(parent, '', title, body);
  }

  async run(retry = 0) {
    assert((retry >>> 0) === retry);
    this.retry = retry;
    return super.run();
  }
}

/**
 * AbstractContext
 */

class AbstractContext {
  constructor() {}

  bail(enabled) {
    if (arguments.length === 0)
      return this.mocha.bail;

    this.mocha.bail = Boolean(enabled);

    return this;
  }

  enableTimeouts(enabled) {
    if (arguments.length === 0)
      return this.runnable.timeouts;

    this.runnable.timeouts = Boolean(enabled);

    return this;
  }

  only() {
    this.runnable.only = true;
    this.mocha.exclusive = true;
    return this;
  }

  retries(n) {
    if (arguments.length === 0)
      return this.runnable.retries;

    this.runnable.retries = n >>> 0;

    return this;
  }

  skip() {
    if (this.runnable.running) {
      this.runnable.skip = true;
      throw PENDING;
    }

    this.runnable.skippable = true;

    return this;
  }

  slow(ms) {
    if (arguments.length === 0)
      return this.runnable.slow;

    this.runnable.slow = ms >>> 0;

    return this;
  }

  timeout(ms) {
    if (arguments.length === 0)
      return this.runnable.timeout;

    this.runnable.timeout = ms >>> 0;

    return this;
  }
}

/**
 * MochaContext
 */

class MochaContext extends AbstractContext {
  constructor(mocha) {
    assert(mocha instanceof Mocha);
    super();
    this.mocha = mocha;
  }

  get runnable() {
    const mocha = this.mocha;
    const runnable = mocha.current || mocha.test;

    if (!runnable)
      throw new Error('No context currently running!');

    return runnable;
  }
}

/**
 * Context
 */

class Context extends AbstractContext {
  constructor(runnable) {
    assert(runnable instanceof Runnable);
    super();
    this.runnable = runnable;
  }

  get mocha() {
    return this.runnable.mocha;
  }
}

/**
 * Job
 */

class Job {
  constructor(test, resolve, reject) {
    assert(test instanceof Executable);
    assert(typeof resolve === 'function');
    assert(typeof reject === 'function');

    this.test = test;
    this.timer = null;
    this.done = false;
    this.called = false;
    this._resolve = resolve;
    this._reject = reject;

    this.init();
  }

  init() {
    this.test.job = this;
    return this;
  }

  resolve() {
    if (this.done)
      return null;

    this.done = true;
    this.clear();
    this._resolve();

    return null;
  }

  reject(err) {
    if (this.done)
      return null;

    this.done = true;
    this.clear();
    this._reject(err);

    return null;
  }

  _callback(err) {
    if (this.called) {
      const msg = 'done() called multiple times';
      const message = err ? get(err, 'message') : null;

      if (typeof message === 'string') {
        try {
          err.message += ` (and Mocha's ${msg})`;
        } catch (e) {
          ;
        }
      } else {
        err = new Error(msg);
      }

      this.reject(err);

      return this;
    }

    this.called = true;

    setImmediate(() => {
      if (err)
        this.reject(err);
      else
        this.resolve();
    });

    return this;
  }

  callback() {
    const self = this;
    return function done(err) {
      self._callback(err);
    };
  }

  start() {
    const {timeout, timeouts} = this.test;

    if (this.done)
      return this;

    assert(this.timer == null);

    if (!timeouts || timeout === 0) {
      // We still want something on the event
      // loop in the case that we're calling
      // out to a native library which does
      // not poll anything directly.
      this.timer = setTimeout(() => {}, 1 << 29);
      return this;
    }

    this.timer = setTimeout(() => {
      this.reject(new Error(''
        + `Timeout of ${timeout}ms exceeded. `
        + 'For async tests and hooks, ensure '
        + '"done()" is called; if returning a '
        + 'Promise, ensure it resolves.'));
    }, timeout);

    return this;
  }

  clear() {
    if (this.timer != null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    this.test.job = null;

    return this;
  }
}

/*
 * Stats
 */

class Stats {
  constructor() {
    this.start = 0;
    this.end = 0;
    this.duration = 0;
    this.suites = 0;
    this.passes = 0;
    this.pending = 0;
    this.failures = 0;
    this.tests = 0;
    this.total = 0;
  }

  get elapsed() {
    if (this.end === 0)
      return Math.max(0, Date.now() - this.start);
    return this.duration;
  }

  mark() {
    if (this.start === 0) {
      this.start = Date.now();
      this.end = 0;
      this.duration = 0;
    } else {
      this.end = Date.now();
      this.duration = Math.max(0, this.end - this.start);
    }
    return this;
  }

  toJSON() {
    return {
      suites: this.suites,
      tests: this.tests,
      passes: this.passes,
      pending: this.pending,
      failures: this.failures,
      start: new Date(this.start).toISOString(),
      end: new Date(this.end).toISOString(),
      duration: this.duration
    };
  }
}

/**
 * Base
 */

class Base {
  constructor(stream, options) {
    if (options == null)
      options = Object.create(null);

    assert(stream && typeof stream.write === 'function');
    assert(options && typeof options === 'object');

    this.stats = new Stats();
    this.stream = stream;
    this.options = options;
    this.colors = false;
    this.diff = true;
    this.fullTrace = false;
    this.windows = false;
    this.color = this._color.bind(this);
  }

  get id() {
    return this.constructor.id;
  }

  get isTTY() {
    return this.stream.isTTY && typeof this.stream.columns === 'number';
  }

  get columns() {
    if (typeof this.stream.columns === 'number')
      return this.stream.columns;
    return 75;
  }

  get width() {
    return (Math.min(100, this.columns) * 0.75) >>> 0;
  }

  get symbols() {
    return this.windows ? symbolsWindows : symbolsUnix;
  }

  _color(col, str) {
    if (!this.colors)
      return str;

    if (typeof col === 'string')
      col = colors[col];

    return `\x1b[${col >>> 0}m${str}\x1b[0m`;
  }

  write(str) {
    return this.stream.write(String(str));
  }

  hide() {
    if (this.isTTY)
      this.write('\x1b[?25l');
  }

  show() {
    if (this.isTTY)
      this.write('\x1b[?25h');
  }

  deleteLine() {
    if (this.isTTY)
      this.write('\x1b[2K');
  }

  beginningOfLine() {
    if (this.isTTY)
      this.write('\x1b[0G');
  }

  carriage() {
    if (this.isTTY) {
      this.deleteLine();
      this.beginningOfLine();
    }
  }

  cursorUp(n) {
    if (this.isTTY)
      this.write(`\x1b[${n >>> 0}A`);
  }

  cursorDown(n) {
    if (this.isTTY)
      this.write(`\x1b[${n >>> 0}B`);
  }

  start(mocha) {
    assert(mocha instanceof Mocha);
  }

  suiteStart(suite) {
    assert(suite instanceof Suite);
  }

  testStart(test) {
    assert(test instanceof Executable);
  }

  testEnd(test) {
    assert(test instanceof Executable);
  }

  suiteEnd(suite) {
    assert(suite instanceof Suite);
  }

  end(mocha) {
    assert(mocha instanceof Mocha);
  }

  exception(error) {
    this.write('\n');
    this.write('  An error occurred outside of the test suite:\n');
    this.error(toError(error), 2);
  }

  error(error, depth) {
    assert(error && typeof error === 'object');
    assert((depth >>> 0) === depth);

    const {color} = this;
    const message = toMessage(error);
    const stack = toStack(error, this.fullTrace);

    this.write('\n');
    this.write('  '.repeat(depth)
      + color('message', message)
      + '\n');

    if (this.diff && isShowable(error)) {
      const text = show(error, this.colors, this.fullTrace);

      if (text.length > 0) {
        this.write('\n');
        this.write(indent(text, depth) + '\n');
      }
    }

    if (stack.length > 0) {
      const text = color('stack', stack);

      this.write('\n');
      this.write(indent(text, depth) + '\n');
    }

    this.write('\n');
  }

  epilogue(mocha) {
    assert(mocha instanceof Mocha);

    const {color, stats} = this;

    const duration = stats.duration >= 1000
      ? Math.ceil(stats.duration / 1000) + 's'
      : stats.duration + 'ms';

    this.write('\n');

    this.write(' '
      + color('green', ` ${stats.passes} passing`)
      + color('light', ` (${duration})`)
      + '\n');

    if (stats.pending > 0) {
      this.write('  '
        + color('pending', `${stats.pending} pending`)
        + '\n');
    }

    if (stats.failures > 0) {
      this.write('  '
        + color('fail', `${stats.failures} failing`)
        + '\n');
    }

    this.write('\n');

    let total = 0;

    for (let i = 0; i < mocha.results.length; i++) {
      const test = mocha.results[i];

      if (!test.fail)
        continue;

      const {error} = test;
      const id = (total + 1).toString(10);
      const path = test.titlePath();

      for (let j = 0; j < path.length; j++) {
        let title = path[j];

        if (j === path.length - 1)
          title += ':';

        const padding = '  '.repeat(j + 1);
        const col = get(error, 'uncaught') === true
          ? 'warning'
          : 'title';

        if (j === 0) {
          this.write(padding
            + color(col, `${id})`)
            + ' '
            + color('title', title)
            + '\n');
        } else {
          this.write(padding
            + ' '.repeat(id.length)
            + '  '
            + color('title', title)
            + '\n');
        }
      }

      this.error(error, 3);

      total += 1;
    }

    for (let i = 0; i < mocha.errors.length; i++) {
      const id = total + 1;
      const error = mocha.errors[i];

      this.write('  '
        + color('warning', `${id})`)
        + ' '
        + color('title', 'Uncaught Error')
        + '\n');

      this.error(error, 3);

      total += 1;
    }
  }

  why(active) {
    const {color} = this;

    assert(Array.isArray(active));

    this.write(color('warning', '  '
      + `There are ${active.length} handle(s) `
      + 'potentially keeping the process running.\n'));

    this.write('\n');

    // Based on:
    // https://github.com/mafintosh/why-is-node-running
    for (const [type, calls] of active) {
      const stacks = [];

      let max = 0;

      this.write('  ' + color('title', type) + '\n');

      if (calls.length === 0) {
        this.write('    ');
        this.write(color('stack', '(unknown stack trace)\n'));
      }

      for (const call of calls) {
        const prefix = '    at '
          + `${call.filename}:`
          + `${call.line + 1}:`
          + `${call.column + 1}`;

        if (prefix.length > max)
          max = prefix.length;

        stacks.push([prefix, call.code]);
      }

      for (const [prefix, code] of stacks) {
        const pad = ' '.repeat(max - prefix.length);
        const pre = color('stack', prefix);

        if (code)
          this.write(`${pre}:${pad}  ${code}\n`);
        else
          this.write(pre);
      }

      this.write('\n');
    }
  }

  static get(reporter) {
    if (reporter == null)
      return SpecReporter;

    if (typeof reporter === 'string') {
      switch (reporter) {
        case 'doc':
          reporter = DocReporter;
          break;
        case 'dot':
          reporter = DotReporter;
          break;
        case 'json':
          reporter = JSONReporter;
          break;
        case 'json-stream':
          reporter = JSONStreamReporter;
          break;
        case 'landing':
          reporter = LandingReporter;
          break;
        case 'list':
          reporter = ListReporter;
          break;
        case 'markdown':
          reporter = MarkdownReporter;
          break;
        case 'min':
          reporter = MinReporter;
          break;
        case 'nyan':
          reporter = NyanReporter;
          break;
        case 'progress':
          reporter = ProgressReporter;
          break;
        case 'spec':
          reporter = SpecReporter;
          break;
        case 'tap':
          reporter = TapReporter;
          break;
        case 'xunit':
          reporter = XUnitReporter;
          break;
        default:
          throw new Error(`Unknown reporter: ${reporter}.`);
      }
    }

    assert(typeof reporter === 'function');
    assert(typeof reporter.id === 'string');

    return reporter;
  }
}

Base.id = '';

/**
 * DocReporter
 */

class DocReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
  }

  suiteStart(suite) {
    const indent = '  '.repeat(suite.depth);

    this.write(indent + '<section class="suite">\n');

    if (!suite.root)
      this.write(indent + `  <h1>${escape(suite.title)}</h1>\n`);

    this.write(indent + '  <dl>\n');
  }

  suiteEnd(suite) {
    const indent = '  '.repeat(suite.depth);

    this.write(indent + '  </dl>\n');
    this.write(indent + '</section>\n');
  }

  testEnd(test) {
    const indent = '  '.repeat(test.depth + 2);
    const code = escape(clean(test.body));

    if (test.fail)  {
      const message = escape(toMessage(test.error));
      const stack = escape(toStack(test.error, this.fullTrace));

      this.write(indent
        + `<dt class="error">${escape(test.title)}</dt>`
        + '\n');

      this.write(indent
        + `<dd class="error"><pre><code>${code}</code></pre></dd>`
        + '\n');

      this.write(indent
        + `<dd class="error">${message}\n\n${stack}</dd>`
        + '\n');

      return;
    }

    this.write(indent
      + `<dt>${escape(test.title)}</dt>`
      + '\n');

    this.write(indent
      + `<dd><pre><code>${code}</code></pre></dd>`
      + '\n');
  }
}

DocReporter.id = 'doc';

/**
 * DotReporter
 */

class DotReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.n = -1;
  }

  start(mocha) {
    this.n = -1;
    this.write('\n');
  }

  testEnd(test) {
    const {color} = this;
    const {comma, bang, dot} = this.symbols;

    if (++this.n % this.width === 0)
      this.write('\n  ');

    if (test.skip)
      this.write(color('pending', comma));
    else if (test.fail)
      this.write(color('fail', bang));
    else
      this.write(color(test.speed, dot));
  }

  end(mocha) {
    this.write('\n');
    this.epilogue(mocha);
  }
}

DotReporter.id = 'dot';

/**
 * JSONReporter
 */

class JSONReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.pending = [];
    this.failures = [];
    this.passes = [];
    this.tests = [];
  }

  json(json) {
    this.write(JSON.stringify(json, null, 2) + '\n');
  }

  start(mocha) {
    this.pending = [];
    this.failures = [];
    this.passes = [];
    this.tests = [];
  }

  testEnd(test) {
    const json = test.toJSON();

    if (test.skip)
      this.pending.push(json);
    else if (test.fail)
      this.failures.push(json);
    else
      this.passes.push(json);

    this.tests.push(json);
  }

  end(mocha) {
    this.json({
      stats: this.stats.toJSON(),
      tests: this.tests,
      pending: this.pending,
      failures: this.failures,
      passes: this.passes
    });
  }
}

JSONReporter.id = 'json';

/**
 * JSONStreamReporter
 */

class JSONStreamReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
  }

  json(json) {
    this.write(JSON.stringify(json) + '\n');
  }

  start(mocha) {
    this.json(['start', { total: this.stats.total }]);
  }

  testEnd(test) {
    this.json([
      test.fail ? 'fail' : 'pass',
      test.toJSON(true)
    ]);
  }

  end(mocha) {
    this.json(['end', this.stats.toJSON()]);
  }
}

JSONStreamReporter.id = 'json-stream';

/**
 * LandingReporter
 */

class LandingReporter extends Base {
  constructor(stream, options) {
    super(stream, options);

    this.crashed = -1;
    this.n = 0;
  }

  runway() {
    const {color, symbols} = this;
    const width = Math.max(0, this.width - 1);
    const line = symbols.dash.repeat(width);

    this.write('  ' + color('runway', line));
  }

  start(mocha) {
    this.crashed = -1;
    this.n = 0;
    this.write('\n\n\n  ');
    this.hide();
  }

  testEnd(test) {
    const {color, symbols} = this;
    const {plane, runway} = symbols;

    const col = this.crashed === -1
      ? (this.width * ++this.n / this.stats.total) >>> 0
      : this.crashed;

    let icon = color('plane', plane);

    if (test.fail) {
      icon = color('crash', plane);
      this.crashed = col;
    }

    if (this.isTTY)
      this.write(`\x1b[${this.width + 1}D\x1b[2A`);
    else
      this.write('\n');

    const x = Math.max(0, col - 1);
    const y = Math.max(0, this.width - col - 1);

    this.runway();
    this.write('\n');

    this.write('  '
      + color('runway', runway.repeat(x))
      + icon
      + color('runway', runway.repeat(y))
      + '\n');

    this.runway();
    this.write('\x1b[0m');
  }

  end(mocha) {
    this.show();
    this.write('\n');
    this.epilogue(mocha);
  }
}

LandingReporter.id = 'landing';

/**
 * ListReporter
 */

class ListReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.n = 0;
  }

  start(mocha) {
    this.write('\n');
    this.n = 0;
  }

  testStart(test) {
    const {color} = this;

    if (this.isTTY) {
      this.write('    '
        + color('pass', `${test.fullTitle()}:`)
        + ' ');
    }
  }

  testEnd(test) {
    const {color, symbols} = this;

    if (test.skip) {
      this.carriage();

      this.write('  '
        + color('checkmark', symbols.dash)
        + ' '
        + color('pending', `${test.fullTitle()}`)
        + '\n');

      return;
    }

    if (test.fail) {
      this.carriage();
      this.n += 1;

      this.write('  '
        + color('fail', `${this.n}) ${test.fullTitle()}`)
        + '\n');

      return;
    }

    this.carriage();

    this.write('  '
      + color('checkmark', symbols.ok)
      + ' '
      + color('pass', `${test.fullTitle()}:`)
      + ' '
      + color(test.speed, `${test.duration}ms`)
      + '\n');
  }

  end(mocha) {
    this.epilogue(mocha);
  }
}

ListReporter.id = 'list';

/**
 * MarkdownReporter
 */

class MarkdownReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.buffer = '';
  }

  title(suite) {
    return '#'.repeat(suite.depth) + ' ' + suite.title;
  }

  slug(str) {
    assert(typeof str === 'string');

    return str
      .toLowerCase()
      .replace(/ +/g, '-')
      .replace(/[^-\w]/g, '');
  }

  mapTOC(suite, obj) {
    const key = '$' + suite.title;

    if (!obj[key])
      obj[key] = { suite };

    for (const child of suite.suites)
      this.mapTOC(child, obj[key]);

    return obj;
  }

  stringifyTOC(obj, level) {
    level += 1;

    let buffer = '';
    let link;

    for (const key of Object.keys(obj)) {
      if (key === 'suite')
        continue;

      if (key !== '$') {
        link = `- [${key.substring(1)}]`;
        link += `(#${this.slug(obj[key].suite.fullTitle())})\n`;
        buffer += '  '.repeat(level - 2) + link;
      }

      buffer += this.stringifyTOC(obj[key], level);
    }

    return buffer;
  }

  generateTOC(suite) {
    const obj = this.mapTOC(suite, {});
    return this.stringifyTOC(obj, 0);
  }

  start(mocha) {
    this.buffer = '';
  }

  suiteStart(suite) {
    if (suite.root)
      return;

    const slug = this.slug(suite.fullTitle());

    this.buffer += `<a name="${slug}"></a>\n\n`;
    this.buffer += this.title(suite) + '\n\n';
  }

  testEnd(test) {
    if (test.fail || test.skip)
      return;

    const code = clean(test.body);

    this.buffer += test.title + '.\n';
    this.buffer += '\n``` js\n';
    this.buffer += code + '\n';
    this.buffer += '```\n\n';
  }

  end(mocha) {
    this.write('# TOC\n');
    this.write('\n');
    this.write(this.generateTOC(mocha.suite));
    this.write('\n');
    this.write(this.buffer.replace(/\n+$/, '\n'));
  }
}

MarkdownReporter.id = 'markdown';

/**
 * MinReporter
 */

class MinReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
  }

  start(mocha) {
    if (this.isTTY) {
      this.write('\x1b[2J');
      this.write('\x1b[1;3H');
    }
  }

  end(mocha) {
    this.epilogue(mocha);
  }
}

MinReporter.id = 'min';

/**
 * NyanReporter
 */

class NyanReporter extends Base {
  constructor(stream, options) {
    super(stream, options);

    this.nyanCatWidth = 11;
    this.colorIndex = 0;
    this.numberOfLines = 4;
    this.rainbowColors = this.generateColors();
    this.scoreboardWidth = 7;
    this.tick = 0;
    this.trajectories = [[], [], [], []];
  }

  start(mocha) {
    this.colorIndex = 0;
    this.tick = 0;
    this.trajectories = [[], [], [], []];

    this.hide();
    this.draw();
  }

  testEnd(test) {
    this.draw();
  }

  end(mocha) {
    this.show();

    for (let i = 0; i < this.numberOfLines; i++)
      this.write('\n');

    this.epilogue(mocha);
  }

  draw() {
    this.appendRainbow();
    this.drawScoreboard();
    this.drawRainbow();
    this.drawNyanCat();
    this.tick ^= 1;
  }

  drawScoreboard() {
    const {color} = this;
    const stats = this.stats;

    const draw = (col, n) => {
      this.write(' ' + color(col, n) + '\n');
    };

    draw('green', stats.passes);
    draw('fail', stats.failures);
    draw('pending', stats.pending);

    this.write('\n');

    this.cursorUp(this.numberOfLines);
  }

  appendRainbow() {
    const segment = this.tick ? '_' : '-';
    const rainbowified = this.rainbowify(segment);
    const trajectoryWidthMax = this.width - this.nyanCatWidth;

    for (let index = 0; index < this.numberOfLines; index++) {
      const trajectory = this.trajectories[index];

      if (trajectory.length >= trajectoryWidthMax)
        trajectory.shift();

      trajectory.push(rainbowified);
    }
  }

  drawRainbow() {
    for (const line of this.trajectories) {
      if (this.isTTY)
        this.write(`\x1b[${this.scoreboardWidth}C`);
      this.write(line.join('') + '\n');
    }

    this.cursorUp(this.numberOfLines);
  }

  drawNyanCat() {
    const startWidth = this.scoreboardWidth + this.trajectories[0].length;
    const dist = `\x1b[${startWidth}C`;

    let padding = '';
    let tail = '';

    if (this.isTTY)
      this.write(dist);

    this.write('_,------,\n');

    if (this.isTTY)
      this.write(dist);

    padding = this.tick ? '  ' : '   ';

    this.write(`_|${padding}/\\_/\\ \n`);

    if (this.isTTY)
      this.write(dist);

    padding = this.tick ? '_' : '__';
    tail = this.tick ? '~' : '^';

    this.write(`${tail}|${padding}${this.face()} \n`);

    if (this.isTTY)
      this.write(dist);

    padding = this.tick ? ' ' : '  ';

    this.write(`${padding}""  "" \n`);

    this.cursorUp(this.numberOfLines);
  }

  face() {
    const stats = this.stats;

    if (stats.failures > 0)
      return '( x .x)';

    if (stats.pending > 0)
      return '( o .o)';

    if (stats.passes > 0)
      return '( ^ .^)';

    return '( - .-)';
  }

  generateColors() {
    const colors = [];

    for (let i = 0; i < 6 * 7; i++) {
      const pi3 = Math.floor(Math.PI / 3);
      const n = i * (1.0 / 6);
      const r = Math.floor(3 * Math.sin(n) + 3);
      const g = Math.floor(3 * Math.sin(n + 2 * pi3) + 3);
      const b = Math.floor(3 * Math.sin(n + 4 * pi3) + 3);
      colors.push(36 * r + 6 * g + b + 16);
    }

    return colors;
  }

  rainbowify(str) {
    if (!this.colors || !this.isTTY)
      return str;

    const len = this.rainbowColors.length;
    const color = this.rainbowColors[this.colorIndex % len];

    this.colorIndex += 1;

    return `\x1b[38;5;${color}m${str}\x1b[0m`;
  }
}

NyanReporter.id = 'nyan';

/**
 * ProgressReporter
 */

class ProgressReporter extends Base {
  constructor(stream, options) {
    super(stream, options);

    const {symbols} = this;

    this.n = -1;
    this.open = symbols.open;
    this.complete = symbols.complete;
    this.incomplete = symbols.incomplete;
    this.close = symbols.close;
    this.verbose = false;

    if (typeof this.options.open === 'string')
      this.open = this.options.open;

    if (typeof this.options.complete === 'string')
      this.complete = this.options.complete;

    if (typeof this.options.incomplete === 'string')
      this.incomplete = this.options.incomplete;

    if (typeof this.options.close === 'string')
      this.close = this.options.close;

    if (typeof this.options.verbose === 'boolean')
      this.verbose = this.options.verbose;
  }

  start(mocha) {
    this.n = -1;
    this.write('\n');
    this.hide();
  }

  testEnd(test) {
    const {color} = this;
    const stats = this.stats;
    const percent = stats.tests / stats.total;
    const width = this.width;

    let n = (width * percent) >>> 0;
    let i = width - n;

    if (n === this.n && !this.verbose)
      return;

    this.n = n;

    if (this.isTTY) {
      this.carriage();
      this.write('\x1b[J');
    } else {
      this.write('\n');
    }

    n = Math.max(0, n - 1);
    i = Math.max(0, i - 1);

    this.write('  '
      + color('progress', this.open)
      + this.complete.repeat(n)
      + this.incomplete.repeat(i)
      + color('progress', this.close));

    if (this.verbose) {
      this.write(' '
        + color('progress', `${stats.tests} of ${stats.total}`));
    }
  }

  end(mocha) {
    this.show();
    this.write('\n');
    this.epilogue(mocha);
  }
}

ProgressReporter.id = 'progress';

/**
 * SpecReporter
 */

class SpecReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.n = 0;
  }

  start(mocha) {
    this.n = 0;
  }

  suiteStart(suite) {
    const {color} = this;

    if (suite.root)
      return;

    if (suite.depth === 1)
      this.write('\n');

    this.write('  '.repeat(suite.depth)
      + color('suite', suite.title)
      + '\n');
  }

  testEnd(test) {
    const {color, symbols} = this;
    const padding = '  '.repeat(test.depth);

    if (test.skip) {
      this.write(color('pending', padding
        + '  '
        + `${symbols.dash} ${test.title}`)
        + '\n');
      return;
    }

    if (test.fail) {
      this.n += 1;
      this.write(color('fail', padding
        + '  '
        + `${this.n}) ${test.title}`)
        + '\n');
      return;
    }

    this.write(padding
      + '  '
      + color('checkmark', symbols.ok)
      + ' '
      + color('pass', test.title));

    if (test.speed !== 'fast')
      this.write(' ' + color(test.speed, `(${test.duration}ms)`));

    this.write('\n');

    if (test.swallowed) {
      const message = toMessage(test.swallowed);

      this.write(padding
        + '    '
        + color('warning', symbols.bang)
        + ' '
        + 'swallowed error as per mocha behavior:'
        + '\n');

      this.write(padding
        + '      '
        + color('fail', message)
        + '\n');
    }
  }

  end(mocha) {
    this.epilogue(mocha);
  }
}

SpecReporter.id = 'spec';

/**
 * TapReporter
 */

class TapReporter extends Base {
  constructor(stream, options) {
    super(stream, options);
    this.n = 1;
    this.passes = 0;
    this.failures = 0;
  }

  title(test) {
    return test.fullTitle().replace(/#/g, '');
  }

  start(mocha) {
    this.n = 1;
    this.passes = 0;
    this.failures = 0;
    this.write(`1..${mocha.stats.total}\n`, 1);
  }

  testEnd(test) {
    this.n += 1;

    if (test.skip) {
      this.write(`ok ${this.n} ${this.title(test)} # SKIP -\n`);
      return;
    }

    if (test.fail) {
      const message = toMessage(test.error);
      const stack = toStack(test.error, this.fullTrace);

      this.failures += 1;

      this.write(`not ok ${this.n} ${this.title(test)}\n`);
      this.write(`  ${message}\n`);
      this.write('\n');

      if (stack.length > 0) {
        this.write(indent(stack, 1) + '\n');
        this.write('\n');
      }

      return;
    }

    this.passes += 1;
    this.write(`ok ${this.n} ${this.title(test)}\n`);
  }

  end(mocha) {
    this.write(`# tests ${this.passes + this.failures}\n`);
    this.write(`# pass ${this.passes}\n`);
    this.write(`# fail ${this.failures}\n`);
  }
}

TapReporter.id = 'tap';

/**
 * XUnitReporter
 */

class XUnitReporter extends Base {
  constructor(stream, options) {
    super(stream, options);

    this.suiteName = 'Mocha Tests';

    if (typeof this.options.suiteName === 'string')
      this.suiteName = this.options.suiteName;
  }

  end(mocha) {
    const testTag = this.tag('testsuite', {
      name: this.suiteName,
      tests: this.stats.tests,
      failures: this.stats.failures,
      errors: this.stats.failures,
      skipped: this.stats.pending,
      timestamp: new Date().toUTCString(),
      time: this.stats.duration / 1000
    }, false);

    this.write(testTag + '\n');

    for (const test of mocha.results)
      this.test(test);

    this.write('</testsuite>\n');
  }

  test(test) {
    const attrs = {
      classname: test.parent.fullTitle(),
      name: test.title,
      time: test.duration / 1000
    };

    if (test.skip) {
      const skipTag = this.tag('skipped', {}, true);
      const testTag = this.tag('testcase', attrs, false, skipTag);

      this.write(testTag + '\n');

      return;
    }

    if (test.fail) {
      const message = escape(toMessage(test.error));
      const stack = escape(toStack(test.error, this.fullTrace));

      const failTag = this.tag('failure', {}, false,
                               `${message}\n\n${stack}`);

      const testTag = this.tag('testcase', attrs, false, failTag);

      this.write(testTag + '\n');

      return;
    }

    this.write(this.tag('testcase', attrs, true) + '\n');
  }

  tag(name, attrs, close, content = null) {
    const end = close ? '/>' : '>';
    const pairs = [];

    for (const key of Object.keys(attrs)) {
      const value = attrs[key];
      pairs.push(`${key}="${escape(value)}"`);
    }

    let tag = '<' + name;

    if (pairs.length > 0)
      tag += ' ' + pairs.join(' ');

    tag += end;

    if (content)
      tag += content + '</' + name + end;

    return tag;
  }
}

XUnitReporter.id = 'xunit';

/**
 * Stream
 */

class Stream {
  constructor() {
    this.readable = false;
    this.writable = false;
    this.isTTY = false;
  }

  on(event, handler) {
    return this;
  }

  addListener(event, handler) {
    return this;
  }

  once(event, handler) {
    return this;
  }

  off(event, handler) {
    return this;
  }

  removeListener(event, handler) {
    return this;
  }

  removeAllListeners(event) {
    return this;
  }

  emit(event, ...args) {
    return this;
  }

  prependListener(event, handler) {
    return this;
  }

  prependOnceListener(event, handler) {
    return this;
  }

  listeners() {
    return [];
  }

  pause() {
    return this;
  }

  resume() {
    return this;
  }

  close() {
    return this;
  }

  destroy() {
    return this;
  }

  write(data) {
    return true;
  }

  end(data) {
    if (data != null)
      return this.write(data);
    return true;
  }

  pipe(dest) {
    return dest;
  }

  flush(func) {
    assert(typeof func === 'function');
    func();
  }
}

/**
 * SendStream
 */

class SendStream extends Stream {
  constructor(send, isTTY = false, columns = 75) {
    assert(typeof send === 'function');
    assert(typeof isTTY === 'boolean');
    assert((columns >>> 0) === columns);

    super();

    this.writable = true;
    this.send = send;
    this.isTTY = isTTY;
    this.columns = columns;
    this.buffer = '';
    this.sending = false;
    this.queue = '';
    this.flushers = [];
    this.onSend = this._onSend.bind(this);
  }

  write(str) {
    str = String(str);

    if (str.length === 0)
      return true;

    const lines = str.split('\n');

    assert(lines.length > 0);

    if (lines.length === 1) {
      this.buffer += lines[0];
      return false;
    }

    const last = lines.pop();
    const data = this.buffer + lines.join('\n');

    this.buffer = last;

    return this._write(data + '\n');
  }

  _write(str) {
    if (this.sending) {
      this.queue += str;
      return false;
    }

    this.sending = true;
    this.send(str, this.onSend);

    return true;
  }

  _onSend(err) {
    this.sending = false;

    if (this.queue.length === 0) {
      this.doFlush();
      return;
    }

    const str = this.queue;

    this.queue = '';
    this._write(str);
  }

  flush(func) {
    assert(typeof func === 'function');

    // Flush the line buffer first.
    if (this.buffer.length > 0) {
      const str = this.buffer;
      this.buffer = '';
      this._write(str);
    }

    if (this.queue.length === 0) {
      func();
      return;
    }

    this.flushers.push(func);
  }

  doFlush() {
    if (this.flushers.length === 0)
      return;

    const flushers = this.flushers.slice();

    this.flushers.length = 0;

    for (const func of flushers)
      func();
  }
}

/**
 * ConsoleStream
 */

class ConsoleStream extends Stream {
  constructor(console, isTTY = false) {
    super();

    if (!console || typeof console.log !== 'function')
      throw new Error('Must pass a console.');

    assert(typeof isTTY === 'boolean');

    this.writable = true;
    this.console = console;
    this.isTTY = isTTY;
    this.buffer = '';
  }

  write(str) {
    str = String(str);

    if (str.length === 0)
      return true;

    if (this.isTTY)
      str = str.replace(/\x1b\[m/g, '\x1b[0m');

    const lines = str.split('\n');

    assert(lines.length > 0);

    if (lines.length === 1) {
      this.buffer += lines[0];
      return false;
    }

    const last = lines.pop();
    const data = this.buffer + lines.join('\n');

    this.buffer = last;

    this.console.log(data);

    return true;
  }
}

/**
 * DOMStream
 */

class DOMStream extends Stream {
  constructor(node) {
    super();

    if (!node || !node.ownerDocument)
      throw new Error('Must pass a DOM element.');

    this.writable = true;
    this.isTTY = true;
    this.document = node.ownerDocument;
    this.node = node;
    this.replace = this._replace.bind(this);
    this.replaceURL = this._replaceURL.bind(this);

    this.url = new RegExp(''
      + '(https?://)' // Protocol
      + '([^:/?#\\s]+)' // Hostname
      + '(?::(\\d+))?' // Port
      + '(?:'
      + '(/[/\\w\\-&?#@!%=,.~]+)' // Path
      + '(?::(\\d+):(\\d+))?' // Line/Column
      + ')?',
    'g');

    this.init();
  }

  init() {
    this.node.style.cssText = `font-family: ${style.font};`;
    this.node.style.cssText = `color: ${style.fg};`;
    this.node.style.cssText = `background-color: ${style.bg};`;
    this.node.innerHTML = '';
  }

  scroll() {
    const {document} = this;

    let node = this.node;

    if (document.scrollingElement) {
      // Equivalent to the logic of:
      // if (node does not have vert scrollbar)
      if (node.scrollHeight <= node.clientHeight)
        node = document.scrollingElement;
    }

    node.scrollTop = node.scrollHeight;
  }

  write(str) {
    str = String(str);

    // Escape HTML.
    str = escape(str);
    str = str.replace(/ /g, '&nbsp;');
    str = str.replace(/\n/g, '<br>');

    // Convert CSI codes to HTML.
    if (this.isTTY)
      str = str.replace(/\x1b\[([^m]*)m/g, this.replace);

    // Replace URLs.
    str = str.replace(this.url, this.replaceURL);

    this.put(str);

    return true;
  }

  put(str) {
    const child = this.document.createElement('span');

    child.innerHTML = String(str);

    this.node.appendChild(child);
    this.scroll();
  }

  _replace(str, args) {
    assert(typeof str === 'string');
    assert(typeof args === 'string');

    let out = '';

    for (const code of args.split(';')) {
      if (code === '38' || code === '48')
        return '';
      out += this.convert(code);
    }

    return out;
  }

  convert(str) {
    let num = str >>> 0;

    if (num === 0
        || num === 22
        || num === 23
        || num === 24
        || num === 29
        || num === 39
        || num === 49) {
      return '</span>';
    }

    if (num === 1)
      return '<span style="font-weight:bold">';

    if (num === 2)
      return '<span style="font-style:oblique 10deg">';

    if (num === 3)
      return '<span style="font-style:italic">';

    if (num === 4)
      return '<span style="text-decoration:underline">';

    if (num === 9)
      return '<span style="text-decoration:line-through">';

    let prop = '';

    if (num >= 30 && num <= 37) {
      prop = 'color';
      num -= 30;
    } else if (num >= 40 && num <= 47) {
      prop = 'background-color';
      num -= 40;
    } else if (num >= 90 && num <= 97) {
      prop = 'color';
      num -= 90;
      num += 8;
    } else if (num >= 100 && num <= 107) {
      prop = 'background-color';
      num -= 100;
      num += 8;
    }

    if (num >= style.colors.length)
      return '';

    const value = style.colors[num];

    return `<span style="${prop}:${value}">`;
  }

  _replaceURL(url, proto, host, port, path, line, col) {
    if (path == null || line == null)
      return `<a href="${url}">${url}</a>`;

    if (port == null)
      port = '';

    if (port)
      port = ':' + port;

    path += `.html#L${line}`;

    return `<a href="${proto}${host}${port}${path}">${url}</a>`;
  }
}

/*
 * API (without globals)
 */

for (const name of ['before',
                    'after',
                    'beforeEach',
                    'afterEach',
                    'describe',
                    'it',
                    'xdescribe',
                    'xit',
                    'specify',
                    'run']) {
  Object.defineProperty(exports, name, {
    configurable: true,
    enumerable: true,
    get: () => global[name]
  });
}

/*
 * Expose
 */

exports.inspect = inspect;
exports.style = style;
exports.errorify = errorify;
exports.stackify = stackify;
exports.Runnable = Runnable;
exports.Mocha = Mocha;
exports.Suite = Suite;
exports.Executable = Executable;
exports.Hook = Hook;
exports.Test = Test;
exports.AbstractContext = AbstractContext;
exports.MochaContext = MochaContext;
exports.Context = Context;
exports.Job = Job;
exports.Stats = Stats;
exports.Base = Base;
exports.DocReporter = DocReporter;
exports.DotReporter = DotReporter;
exports.JSONReporter = JSONReporter;
exports.JSONStreamReporter = JSONStreamReporter;
exports.LandingReporter = LandingReporter;
exports.ListReporter = ListReporter;
exports.MarkdownReporter = MarkdownReporter;
exports.MinReporter = MinReporter;
exports.NyanReporter = NyanReporter;
exports.ProgressReporter = ProgressReporter;
exports.SpecReporter = SpecReporter;
exports.TapReporter = TapReporter;
exports.XUnitReporter = XUnitReporter;
exports.Stream = Stream;
exports.SendStream = SendStream;
exports.ConsoleStream = ConsoleStream;
exports.DOMStream = DOMStream;
