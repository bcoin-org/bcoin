# bmocha

Alternative implementation of [Mocha][mocha] (requires no external dependencies
for security purposes).

## Usage

Bmocha's CLI mimics Mocha's CLI for most features:

```
$ bmocha --help

  Usage: bmocha [options] [files]
         bmocha debug [options] [files]
         bmocha init <path> [options] [files]

  Commands:

    debug                    start bmocha with the node.js debugger enabled
    init <path>              initialize a client-side bmocha setup at <path>

  Options:

    --allow-multiple         allow multiple promise resolutions (default: false)
    --allow-uncaught         enable uncaught errors to propagate
                             (default: false)
    -A, --async-only         require all tests to use a callback or promise
                             (default: false)
    -B, --backend <value>    set the NODE_BACKEND environment variable
    -b, --bail               bail after first test failure (default: false)
    --check-leaks            check for global variable leaks (default: false)
    --chrome <path>          chrome binary to use for headless mode
    -c, --colors             force enabling of colors
    -C, --no-colors          force disabling of colors
    --compilers <ext>:<mod>  use the given module(s) to compile files
    --config <path>          path to config file (default: nearest rc file)
    --csp-source <src>       add content-security-policy source
                             (default: 'self')
    --delay                  delay initial execution of root suite
                             (default: false)
    --diff                   show diff on failure (default: true)
    -e, --env <name=val>     set environment variable (can be specified multiple
                             times)
    --exclude <file>         a file to ignore
    --exit                   force shutdown of the event loop after test run
                             (default: false)
    --extension <ext>        file extension(s) to load and/or watch
                             (default: js)
    -f, --fgrep <string>     only run tests containing <string>
    --file <file>            include a file to be ran during the suite
    --forbid-only            fail if exclusive test(s) encountered
                             (default: false)
    --forbid-pending         fail if pending test(s) encountered
                             (default: false)
    --full-trace             display full stack traces (default: false)
    -g, --grep <pattern>     only run tests matching <pattern>
    -G, --growl              enable growl notifications (default: false)
    --globals <names>        allow the given comma-delimited global <names>
    -H, --headless           run tests in headless chrome (default: false)
    -h, --help               output usage information
    -i, --invert             inverts --grep and --fgrep matches (default: false)
    --inline-diffs           display actual/expected differences inline (noop)
                             (default: false)
    --interfaces             display available interfaces
    -l, --listen             serve client-side test files (requires browserify)
                             (default: false)
    -m, --cmd <cmd>          set browser command (default: $BROWSER)
    --node <path>            path to node.js binary (default: process.execPath)
    -o, --open               open browser after serving (default: false)
    -O, --reporter-options   reporter-specific options
    --opts <path>            path to "mocha.opts" (default: ./test/mocha.opts)
    --package <path>         path to package.json for config
                             (default: ./package.json)
    -p, --port <port>        port to listen on (default: 8080)
    -R, --reporter <name>    specify the reporter to use (default: spec)
    -r, --require <name>     require the given module
    --recursive              include sub directories (default: false)
    --reporters              display available reporters
    --retries <times>        set numbers of time to retry a failed test case
                             (default: 0)
    -s, --slow <ms>          "slow" test threshold in milliseconds (default: 75)
    -S, --sort               sort test files (default: false)
    --ssl                    use ssl to listen (default: false)
    --ssl-cert <path>        path to ssl cert file
    --ssl-ignore             ignore certificate errors (headless mode only)
                             (default: false)
    --ssl-key <path>         path to ssl key file
    --swallow                swallow errors post-completion to mimic mocha
                             (default: true)
    -t, --timeout <ms>       set test-case timeout in milliseconds
                             (default: 2000)
    --timeouts               enables timeouts (default: true)
    -u, --ui <name>          specify user-interface (bdd) (default: bdd)
    -V, --version            output the version number
    -w, --watch              watch files in the current working directory
                             (default: false)
    --why                    display why node continues to run after the suite
                             has ended (similar to why-is-node-running)
    -z, --console            use console in browser (default: false)

  Environment Variables:

    BMOCHA_OPTIONS           space-separated list of command-line options
```

### Example

``` bash
$ bmocha --reporter spec test.js
```

## Docs

Because bmocha is more or less a full clone of mocha, the MochaJS docs should
be sufficient for any typical use-case. See [mochajs.org][mocha].

## Features

### Easily Auditable Code (the "why?")

There have been a number of NPM package attacks in the past. The most recent
being an attack on the popular `event-stream` library. There are many projects
with _financial_ components to them, cryptocurrency projects in particular.

Mocha pulls in a number of dependencies (23 with dedupes, and an even greater
amount of dev dependencies):

```
$ npm ls
mocha@5.2.0
├── browser-stdout@1.3.1
├── commander@2.15.1
├─┬ debug@3.1.0
│ └── ms@2.0.0
├── diff@3.5.0
├── escape-string-regexp@1.0.5
├─┬ glob@7.1.2
│ ├── fs.realpath@1.0.0
│ ├─┬ inflight@1.0.6
│ │ ├── once@1.4.0
│ │ └── wrappy@1.0.2
│ ├── inherits@2.0.3
│ ├── minimatch@3.0.4
│ ├─┬ once@1.4.0
│ │ └── wrappy@1.0.2
│ └── path-is-absolute@1.0.1
├── growl@1.10.5
├── he@1.1.1
├─┬ minimatch@3.0.4
│ └─┬ brace-expansion@1.1.11
│   ├── balanced-match@1.0.0
│   └── concat-map@0.0.1
├─┬ mkdirp@0.5.1
│ └── minimist@0.0.8
└─┬ supports-color@5.4.0
  └── has-flag@3.0.0
```

As maintainers of several cryptocurrency projects, we find this attack surface
to be far too large for comfort. Although we of course trust the mocha
developers, only one of its dependencies need be compromised in order to
potentially steal bitcoin or API keys.

As a result, bmocha pulls in _zero_ dependencies: what you see is what you get.
The code is a couple thousand lines, residing in `lib/` and `bin/`.

### Headless Chrome & Browser Support

If browserify is installed as a global or peer dependency, running tests in
headless chrome is as easy as:

``` bash
$ bmocha -H test.js
```

Chromium or chrome must be installed in one of the usual locations depending on
your OS. If both are installed, bmocha prefers chromium over chrome.

The tests will run in a browserify environment with some extra features:

- `console.{log,error,info,warn,dir}` and `process.{stdout,stderr}` will work
  as expected.
- `process.{exit,abort}` will work as expected.
- The `fs` module will work in "read-only" mode. All of the read calls,
  including `access`, `exists`, `stat`, `readdir`, and `readFile` will all work
  properly (sync and async). As a security measure, they will only be able to
  access your current working directory and nothing else.

If your chrome binary is somewhere non-standard, you are able to pass the
`--chrome` flag.

``` bash
$ bmocha --chrome="$(which google-chrome-unstable)" test.js
```

To run the tests in your default non-headless browser:

``` bash
$ bmocha -o test.js
```

Will open a browser window and display output in the DOM.

To run with the output written to the console instead:

``` bash
$ bmocha -oz test.js
```

To pass a custom browser to open, use `-m` instead of `-o`:

``` bash
$ bmocha -m 'chromium %s' test.js
```

Where `%s` is where you want the server's URL to be placed.

For example, to run chromium in app mode:

``` bash
$ bmocha -m 'chromium --app=%s' test.js
```

By default, bmocha will start an HTTP server listening on a random port. To
specify the port:

``` bash
$ bmocha -p 8080 -m 'chromium --app=%s' test.js
```

And finally, to simply start an http server without any browser action, the
`-l` flag is available:

``` bash
$ bmocha -lp 8080 test.js
```

#### Support for Workers

In the browser, your code may be using workers. To notify bmocha of this, a
global `register` call is exposed during test execution.

``` js
function createWorker() {
  if (process.env.BMOCHA) {
    // Usage: register([desired-url-path], [filesystem-path]);
    register('/worker.js', [__dirname, 'worker.js']);
  }

  return new Worker('/worker.js');
}
```

When `createWorker` is called, the bmocha server is notified that it should
compile and serve `${__dirname}/worker.js` as `/worker.js`.

### Arrow Functions

Bmocha supports arrow functions in a backwardly compatible way:

``` js
describe('Suite', function() {
  this.timeout(1000);

  it('should skip test', () => {
    this.skip();
    assert(1 === 0);
  });
});
```

``` js
describe('Suite', (self) => {
  self.timeout(1000);

  it('should skip test', () => {
    self.skip();
    assert(1 === 0);
  });
});
```

Both styles are valid. Note that the `this` style requires at least one outer
function defined as a regular `function` expression.

### ESM Support

Bmocha also includes out-of-the-box support for ESM:

``` bash
$ bmocha --experimental-modules ./test.mjs
```

### Fixes for Mocha legacy behavior

Since we're building from scratch with zero dependents, we have an opportunity
to fix some of the bugs in Mocha.

For example:

``` js
describe('Suite', () => {
  it('should fail', (cb) => {
    cb();
    throw new Error('foobar');
  });
});
```

```
$ mocha test.js


  Suite
    ✓ should fail


  1 passing (6ms)
```

The above passes in mocha and _swallows_ the error. We don't want to interfere
with existing mocha tests, but we can output a warning to the programmer:

```
$ bmocha test.js

  Suite
    ✓ should fail
      ! swallowed error as per mocha behavior:
        Error: foobar

  1 passing (4ms)
```

Likewise, the following tests also pass in mocha without issue:

``` js
describe('Suite', () => {
  it('should fail (unhandled rejection)', () => {
    new Promise((resolve, reject) => {
      reject(new Error('foobar'));
    });
  });

  it('should fail (resolve & resolve)', () => {
    return new Promise((resolve, reject) => {
      resolve(1);
      resolve(2);
    });
  });

  it('should fail (resolve & reject)', () => {
    return new Promise((resolve, reject) => {
      resolve(3);
      reject(new Error('foobar'));
    });
  });

  it('should fail (resolve & throw)', () => {
    return new Promise((resolve, reject) => {
      resolve(4);
      throw new Error('foobar');
    });
  });
});
```

```
$ mocha test.js


  Suite
    ✓ should fail (unhandled rejection)
    ✓ should fail (resolve & resolve)
    ✓ should fail (resolve & reject)
    ✓ should fail (resolve & throw)


  4 passing (7ms)
```

Bmocha will report and catch unhandled rejections, multiple resolutions, along
with other strange situations:

```
$ bmocha test.js

  Suite
    1) should fail (unhandled rejection)
    2) should fail (resolve & resolve)
    3) should fail (resolve & reject)
    4) should fail (resolve & throw)

  0 passing (4ms)
  4 failing

  1) Suite
       should fail (unhandled rejection):

      Unhandled Error: foobar

      reject(new Error('foobar'));
             ^

      at Promise (/home/bmocha/test.js:4:14)
      at new Promise (<anonymous>)
      at Context.it (/home/bmocha/test.js:3:5)

  2) Suite
       should fail (resolve & resolve):

      Uncaught Error: Multiple resolves detected for number.

      2

  3) Suite
       should fail (resolve & reject):

      Uncaught Error: Multiple rejects detected for error.

      Error: foobar
          at Promise (/home/bmocha/test.js:18:14)
          at new Promise (<anonymous>)
          at Context.it (/home/bmocha/test.js:16:12)

      reject(new Error('foobar'));
             ^

  4) Suite
       should fail (resolve & throw):

      Uncaught Error: Multiple rejects detected for error.

      Error: foobar
          at Promise (/home/bmocha/test.js:25:13)
          at new Promise (<anonymous>)
          at Context.it (/home/bmocha/test.js:23:12)

      throw new Error('foobar');
            ^
```

Mocha tends to die in very strange ways on uncaught errors. Take for instance:

``` js
describe('Suite', () => {
  it('should fail (setImmediate)', () => {
    setImmediate(() => {
      throw new Error('foobar 1');
    });
  });

  it('should not fail (setTimeout)', () => {
    setTimeout(() => {
      throw new Error('foobar 2');
    }, 1);
  });
});
```

```
$ mocha test.js


  Suite
    ✓ should fail (setImmediate)
    1) should fail (setImmediate)

  1 passing (5ms)
  1 failing

  1) Suite
       should fail (setImmediate):
     Uncaught Error: foobar 1
      at Immediate.setImmediate (test.js:4:13)



    ✓ should not fail (setTimeout)
```

The garbled output shown above is very confusing and not very user friendly.

In bmocha, the results are as such:

```
$ bmocha test.js

  Suite
    1) should fail (setImmediate)
    ✓ should not fail (setTimeout)

  1 passing (5ms)
  1 failing

  1) Suite
       should fail (setImmediate):

      Uncaught Error: foobar 1

      throw new Error('foobar 1');
            ^

      at Immediate.setImmediate (/home/bmocha/test.js:4:13)
      at processImmediate (timers.js:632:19)


  An error occurred outside of the test suite:

    Uncaught Error: foobar 2

    throw new Error('foobar 2');
          ^

    at Timeout.setTimeout [as _onTimeout] (/home/bmocha/test.js:10:13)
    at listOnTimeout (timers.js:324:15)
    at processTimers (timers.js:268:5)
```

A note on uncaught errors, unhandled rejections, and multiple resolutions:
Mocha does not even handle the latter, but it tends to die strangely on the
former two. In fact, it dies almost instantly. Bmocha will attempt to "attach"
uncaught errors to the currently running test and reject it. If there is no
currently running test, bmocha will buffer the error until the end, at which
point it will list all of the uncaught errors. If bmocha is no longer running
at all, the error will be output and the process will be exited.

This can lead to differing output on each run if your process has uncaught
errors. Running it again, bmocha was able to attach the error to the currently
running test:

```
$ bmocha test.js

  Suite
    1) should fail (setImmediate)
    2) should not fail (setTimeout)

  0 passing (4ms)
  2 failing

  1) Suite
       should fail (setImmediate):

      Uncaught Error: foobar 1

      throw new Error('foobar 1');
            ^

      at Immediate.setImmediate (/home/bmocha/test.js:4:13)
      at processImmediate (timers.js:632:19)

  2) Suite
       should not fail (setTimeout):

      Uncaught Error: foobar 2

      throw new Error('foobar 2');
            ^

      at Timeout.setTimeout [as _onTimeout] (/home/bmocha/test.js:10:13)
      at listOnTimeout (timers.js:324:15)
      at processTimers (timers.js:268:5)
```

Mocha also only _warns_ when _explicitly_ passed a non-existent test. This is a
shortcoming in CI situations which may only look at the exit code.

```
$ mocha test.js non-existent.js || echo 1
Warning: Could not find any test files matching pattern: non-existent.js


  Suite
    ✓ should pass


  1 passing (3ms)
```

Bmocha will fail outright:

```
$ bmocha test.js non-existent.js || echo 1
File not found: non-existent.js.
1
```

## Raw API

To explicitly run bmocha as a module:

### JS

Mocha accepts a `Stream` object for output.

``` js
const assert = require('assert');
const {Mocha} = require('bmocha');

const mocha = new Mocha({
  stream: process.stdout,
  reporter: 'nyan',
  fgrep: 'Foobar'
});

const code = await mocha.run(() => {
  describe('Foobar', function() {
    this.timeout(5000);

    it('should check 1 == 1', function() {
      this.retries(10);
      assert.equal(1, 1);
    });
  });
});

if (code !== 0)
  process.exit(code);
```

### Browser

Running in the browser is similar. To output to the DOM, a `DOMStream` object
is available:

``` js
const {Mocha, DOMStream} = require('bmocha');
const stream = new DOMStream(document.body);
const mocha = new Mocha(stream);

await mocha.run(...);
```

Likewise, a `ConsoleStream` object is available to output to the console:

``` js
const {Mocha, ConsoleStream} = require('bmocha');
const stream = new ConsoleStream(console);
const mocha = new Mocha(stream);

await mocha.run(...);
```

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[mocha]: https://mochajs.org/
