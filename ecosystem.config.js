// ecosystem.config.js — PM2 process manager configuration for PenChecker
// Usage: pm2 start ecosystem.config.js --env production
module.exports = {
  apps: [
    {
      name:            'penchecker',
      script:          'server/index.js',
      instances:       'max',          // Use all CPU cores (cluster mode)
      exec_mode:       'cluster',
      watch:           false,
      max_memory_restart: '512M',      // Restart if memory exceeds 512MB

      // Environment variables for production
      env_production: {
        NODE_ENV:      'production',
        PORT:          3000,
      },

      // Logging
      out_file:   './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs:  true,

      // Auto-restart on crash
      autorestart:  true,
      restart_delay: 4000,
      max_restarts:  10,

      // Graceful shutdown
      kill_timeout: 5000,

      // Monitor
      exp_backoff_restart_delay: 100,
    },
  ],
};
