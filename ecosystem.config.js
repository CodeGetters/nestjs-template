module.exports = {
  apps: [
    {
      name: 'server',
      // 入口文件路径
      script: 'dist/main.js',
      env_production: {
        NODE_ENV: 'production',
      },
      env_development: {
        NODE_ENV: 'development',
      },
    },
  ],
};
