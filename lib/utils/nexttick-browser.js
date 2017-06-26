/*!
 * nexttick.js - nexttick for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on setimmediate.
 *
 * Copyright (c) 2012 Barnesandnoble.com, llc, Donavon West, and Domenic Denicola
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the 'Software'), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

'use strict';

var global = (function() {
  if (this)
    return this;

  if (typeof window !== 'undefined')
    return window;

  if (typeof self !== 'undefined')
    return self;

  if (typeof global !== 'undefined')
    return global;

  throw new Error('No global defined.');
})();

var document = global.document;
var nextHandle = 1;
var taskMap = {};
var running = false;
var nextTick;

/*
 * Task Runner
 */

function addTask(handler) {
  if (typeof handler !== 'function')
    throw new Error('callback must be a function.');

  taskMap[nextHandle] = handler;

  return nextHandle++;
}

function runTask(handle) {
  var task;

  if (running) {
    setTimeout(function() {
      runTask(handle);
    }, 1);
    return;
  }

  task = taskMap[handle];

  if (task) {
    running = true;
    try {
      task();
    } finally {
      delete taskMap[handle];
      running = false;
    }
  }
}

/*
 * Set Immediate Implementation
 */

function hasSetImmediate() {
  return typeof global.setImmediate === 'function';
}

function installSetImmediate() {
  return function nextTick(handler) {
    setImmediate(handler);
  };
}

/*
 * Next Tick Implementation
 */

function hasNextTick() {
  // Don't get fooled by browserify.
  return ({}).toString.call(global.process) === '[object process]';
}

function installNextTick() {
  return process.nextTick;
}

/*
 * Post Message Implementation
 */

function hasPostMessage() {
  var isAsync = false;
  var onMessage;

  // Be sure to exclude web workers.
  if (global.postMessage && !global.importScripts) {
    isAsync = true;
    onMessage = global.onmessage;
    global.onmessage = function() {
      isAsync = false;
    };
    global.postMessage('', '*');
    global.onmessage = onMessage;
  }

  return isAsync;
}

function installPostMessage() {
  var prefix = 'nextTick' + Math.random();
  var onMessage;

  onMessage = function(event) {
    if (event.source === global
        && typeof event.data === 'string'
        && event.data.indexOf(prefix) === 0) {
      runTask(+event.data.slice(prefix.length));
    }
  };

  if (global.addEventListener)
    global.addEventListener('message', onMessage, false);
  else
    global.attachEvent('onmessage', onMessage);

  return function nextTick(handler) {
    var handle = addTask(handler);
    global.postMessage(prefix + handle, '*');
  };
}

/*
 * Message Channel Implementation
 */

function hasMessageChannel() {
  return typeof global.MessageChannel === 'function';
}

function installMessageChannel() {
  var channel = new MessageChannel();

  channel.port1.onmessage = function(event) {
    runTask(event.data);
  };

  return function nextTick(handler) {
    var handle = addTask(handler);
    channel.port2.postMessage(handle);
  };
}

/*
 * Ready State Change Implementation
 */

function hasReadyState() {
  return document && ('onreadystatechange' in document.createElement('script'));
}

function installReadyState() {
  var html = document.documentElement;

  return function nextTick(handler) {
    var handle = addTask(handler);
    var script = document.createElement('script');

    script.onreadystatechange = function() {
      runTask(handle);
      script.onreadystatechange = null;
      html.removeChild(script);
      script = null;
    };

    html.appendChild(script);
  };
}

/*
 * Set Timeout Implementation
 */

function hasSetTimeout() {
  return typeof global.setTimeout === 'function';
}

function installSetTimeout() {
  return function nextTick(handler) {
    var handle = addTask(handler);
    setTimeout(function() {
      runTask(handle);
    }, 1);
  };
}

/*
 * Install
 */

if (hasSetImmediate()) {
  // `setImmediate` is already available.
  nextTick = installSetImmediate();
} else if (hasNextTick()) {
  // For Node.js before 0.9.
  nextTick = installNextTick();
} else if (hasPostMessage()) {
  // For non-IE10 modern browsers.
  nextTick = installPostMessage();
} else if (hasMessageChannel()) {
  // For web workers, where supported.
  nextTick = installMessageChannel();
} else if (hasReadyState()) {
  // For IE 6–8.
  nextTick = installReadyState();
} else if (hasSetTimeout()) {
  // For older browsers.
  nextTick = installSetTimeout();
} else {
  throw new Error('nextTick not supported.');
}

/*
 * Expose
 */

module.exports = nextTick;
