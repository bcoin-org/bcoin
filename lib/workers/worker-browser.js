/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/* jshint worker: true */

var bcoin, env;

self.importScripts('/bcoin.js');

bcoin = self.bcoin;

self.onmessage = function onmessage(event) {
  self.onmessage = function() {};

  env = JSON.parse(event.data);

  bcoin.set(env.BCOIN_WORKER_NETWORK);
  bcoin.workers.listen();
};
