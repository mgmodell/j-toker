const HtmlWebPackPlugin = require('html-webpack-plugin');
const demoHtml = new HtmlWebPackPlugin({
  chunks: ['demo/index'],
  filename: './demo/index.html',
  minify: true,
  template: './demo/index.html',
});
