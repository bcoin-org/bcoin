/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

var penv, env;

if (typeof importScripts !== 'undefined') {
  self.importScripts('/bcoin.js');
  self.onmessage = function onmessage(event) {
    self.onmessage = function() {};

    penv = JSON.parse(event.data);

    env = self.bcoin.env(penv.BCOIN_WORKER_NETWORK);
    env.workers.listen(+penv.BCOIN_WORKER_ID);
  };
} else {
  penv = process.env;
  env = require('./env')(penv.BCOIN_WORKER_NETWORK);
  env.workers.listen(+penv.BCOIN_WORKER_ID);
}
