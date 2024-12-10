module.exports = {
  apps: [
    {
      name: 'server',
      // 入口文件路径
      script: 'dist/main.js',
      env: {
        DATABASE_URL:
          'postgresql://postgres.zwzuumzunlpzbxmpdiem:3VJxgKQzKXKF8xUVB1iV@aws-0-us-west-1.pooler.supabase.com:6543/postgres?pgbouncer=true',
        DIRECT_URL:
          'postgresql://postgres.zwzuumzunlpzbxmpdiem:3VJxgKQzKXKF8xUVB1iV@aws-0-us-west-1.pooler.supabase.com:5432/postgres',
      },
      env_production: {
        NODE_ENV: 'production',
      },
      env_development: {
        NODE_ENV: 'development',
      },
    },
  ],
};
