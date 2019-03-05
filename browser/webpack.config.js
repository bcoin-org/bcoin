'use strict';

const webpack = require('webpack');
const str = JSON.stringify;
const env = process.env;

module.exports = {
  target: 'web',
  entry: {
    'app': './src/app',
    'worker': './src/worker'
  },
  output: {
    path: __dirname,
    filename: '[name].js'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['-browser.js', '.js', '.json']
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.BCOIN_NETWORK':
        str(env.BCOIN_NETWORK || 'main'),
      'process.env.BCOIN_WORKER_FILE':
        str(env.BCOIN_WORKER_FILE || '/bcoin-worker.js')
    })
  ]
};
