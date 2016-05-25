/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/* jshint worker: true */

var bcoin, env;

if (typeof importScripts !== 'undefined') {
  self.importScripts('/bcoin.js');
  bcoin = self.bcoin;
  self.onmessage = function onmessage(event) {
    self.onmessage = function() {};

    env = JSON.parse(event.data);

    bcoin.network.set(env.BCOIN_WORKER_NETWORK);
    bcoin.workers.listen(+env.BCOIN_WORKER_ID, {
      debug: +env.BCOIN_WORKER_DEBUG === 1
    });
  };
} else {
  env = process.env;
  bcoin = require('./env');
  bcoin.network.set(env.BCOIN_WORKER_NETWORK);
  bcoin.workers.listen(+env.BCOIN_WORKER_ID, {
    debug: +env.BCOIN_WORKER_DEBUG === 1
  });
}
