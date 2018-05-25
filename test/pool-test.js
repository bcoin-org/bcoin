/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const Network = require('../lib/protocol/network');
const Pool = require('../lib/net/pool');

describe('Pool', function() {
  it('should listen on configured port', () => {
    const chain = {
      network: Network.primary,
      options: {
        checkpoints: true
      },
      on: (x) => {}
    };

    const logger = {
      context: (x) => {}
    };

    const pool = new Pool({
      network: Network.primary,
      chain: chain,
      host: '127.0.0.1',
      port: 8080,
      logger: logger
    });

    assert(pool.options.port === 8080);
  });
});
