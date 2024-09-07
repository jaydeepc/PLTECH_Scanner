const path = require('path');
const webpack = require('webpack');

module.exports = {
  entry: './src/index.js',
  target: 'node',
  output: {
    filename: 'scanner.js',
    path: path.resolve(__dirname, 'dist'),
    libraryTarget: 'commonjs2'
  },
  mode: 'production',
  plugins: [
    new webpack.BannerPlugin({ banner: '#!/usr/bin/env node', raw: true }),
  ],
  resolve: {
    fallback: {
      "fs": false,
      "path": require.resolve("path-browserify")
    }
  },
  externals: [
    /^eslint$/,
    function({ context, request }, callback) {
      if (/^eslint-plugin-security$/.test(request)) {
        return callback(null, 'commonjs ' + request);
      }
      callback();
    }
  ]
};