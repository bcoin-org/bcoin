'use strict';

const webpack = require('webpack')
const path = require('path');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const str = JSON.stringify;
const env = process.env;

module.exports = {
  target: 'web',
  entry: {
    'bcoin': './lib/bcoin-browser',
    'bcoin-master': './lib/workers/master'
  },
  output: {
    path: path.join(__dirname, 'browser'),
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
      'process.env.BCOIN_WORKER_URL':
        str(env.BCOIN_WORKER_URL || '/bcoin-worker.js'),
      'process.env.BCOIN_MASTER_URL':
        str(env.BCOIN_MASTER_URL || '/bcoin-master.js')
    }),
    new UglifyJsPlugin()
  ]
};
