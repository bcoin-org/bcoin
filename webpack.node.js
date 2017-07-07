'use strict';

const webpack = require('webpack')
const path = require('path');
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const str = JSON.stringify;
const env = process.env;

module.exports = {
  target: 'node',
  entry: {
    'bcoin': './lib/bcoin-browser',
    'bcoin-worker': './lib/workers/worker'
  },
  output: {
    path: __dirname,
    filename: '[name].js',
    libraryTarget: 'commonjs2'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['.node', '.js', '.json'],
    alias: {
      'bindings': path.resolve(__dirname, 'webpack', 'bindings.js')
    }
  },
  node: {
    __dirname: false,
    __filename: false
  },
  module: {
    rules: [{
      test: /\.node$/,
      loader: 'node-loader'
    }]
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.BCOIN_WORKER_FILE':
        str(env.BCOIN_WORKER_FILE || 'bcoin-worker.js')
    }),
    new webpack.IgnorePlugin(/^utf-8-validate|bufferutil$/),
    new UglifyJsPlugin({
      compress: {
        warnings: true
      }
    })
  ]
};
