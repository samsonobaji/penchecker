# PenChecker — Production Deployment Guide

## Prerequisites
- Node.js 18+ installed
- PM2 installed globally: `npm install -g pm2`
- Domain pointing to your server (for HTTPS)
- Nginx installed (optional but recommended)

---

## Step 1: Environment Configuration

Edit `.env` with your production values:

```bash
NODE_ENV=production
PORT=3000
JWT_SECRET=<generate a 64-char random string>
JWT_EXPIRES_IN=7d
DB_PATH=./data/penchecker.db

# SMTP (Gmail example — use App Password, not your main password)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx  # 16-char App Password
FROM_EMAIL=noreply@yourdomain.com

APP_URL=https://yourdomain.com
SCANNER_TIMEOUT=15000
SCANNER_MAX_REDIRECTS=5

# Optional — Gemini AI for AI assistant responses
GEMINI_API_KEY=your_gemini_api_key
```

Generate a secure JWT secret:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## Step 2: Install Dependencies

```bash
cd /path/to/penchecker
npm install --production
```

---

## Step 3: Create Log Directory

```bash
mkdir -p logs
```

---

## Step 4: Start with PM2

```bash
# Start in production mode
pm2 start ecosystem.config.js --env production

# Save PM2 process list (auto-restart on server reboot)
pm2 save

# Set PM2 to start on system boot
pm2 startup
# (copy and run the command it prints)
```

### Useful PM2 Commands
```bash
pm2 status               # View running processes
pm2 logs penchecker      # View live logs
pm2 restart penchecker   # Restart app
pm2 stop penchecker      # Stop app
pm2 monit                # Real-time monitoring dashboard
```

---

## Step 5: Nginx Reverse Proxy (Recommended)

Install Nginx and create a site config:

```nginx
# /etc/nginx/sites-available/penchecker
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Certificates (use Certbot/Let's Encrypt)
    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip compression
    gzip on;
    gzip_types text/css application/javascript application/json image/svg+xml;
    gzip_min_length 1000;

    # Static files with caching
    location ~* \.(html|css|js|ico|png|jpg|svg|woff2)$ {
        proxy_pass http://127.0.0.1:3000;
        expires 7d;
        add_header Cache-Control "public, max-age=604800";
    }

    # API proxy — no caching
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    # Everything else to Express
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and test:
```bash
sudo ln -s /etc/nginx/sites-available/penchecker /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Step 6: HTTPS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
# Certbot will auto-renew every 90 days
```

---

## Step 7: Firewall (UFW)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
# Block direct access to Node.js port
sudo ufw deny 3000
```

---

## Step 8: Database Backup

Set up a daily cron job to back up your SQLite database:

```bash
# Add to crontab (crontab -e)
0 2 * * * cp /path/to/penchecker/data/penchecker.db /backups/penchecker-$(date +\%Y\%m\%d).db
```

---

## Monitoring & Health Checks

- **PM2 Dashboard:** `pm2 monit`
- **Health API:** `GET https://yourdomain.com/api/health`
- **Logs:** `pm2 logs penchecker --lines 100`

---

## Updating the App

```bash
cd /path/to/penchecker
git pull                          # or deploy new files
npm install                       # install any new dependencies
pm2 restart penchecker            # zero-downtime restart
```
