'use strict';

(function () {
  // 1. Define custom SVG icons
  const icons = {
    dashboard: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>`,
    scan: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>`,
    history: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>`,
    domains: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
    ai: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>`,
    badge: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    reports: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>`,
    settings: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`,
    upgrade: `<svg class="sb-svg" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>`,
  };

  // 2. Inject modern styles
  const css = `
    /* Modernized Sidebar Style Override */
    .sb-logo-icon {
      background: none !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      padding: 0 !important;
      width: 32px !important;
      height: 32px !important;
    }
    .sidebar {
      transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1), background-color 0.3s ease !important;
    }
    .sb-nav {
      padding: 15px 12px !important;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .sb-section {
      font-family: var(--font-body), sans-serif !important;
      font-size: 0.72rem !important;
      font-weight: 700 !important;
      text-transform: uppercase !important;
      letter-spacing: 0.08em !important;
      color: var(--muted) !important;
      margin: 18px 14px 6px !important;
      opacity: 0.75;
    }
    .sb-link {
      display: flex !important;
      align-items: center !important;
      gap: 12px !important;
      padding: 10px 14px !important;
      border-radius: 10px !important;
      font-size: 0.88rem !important;
      font-weight: 500 !important;
      color: var(--muted2) !important;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
      position: relative !important;
      cursor: pointer !important;
      border: 1px solid transparent !important;
      text-decoration: none !important;
    }
    .sb-link:hover {
      background: var(--surface) !important;
      color: var(--white) !important;
      transform: translateX(4px);
    }
    .sb-link:active {
      transform: translateX(2px) scale(0.98);
    }
    .sb-link.active {
      background: linear-gradient(135deg, rgba(0, 229, 255, 0.12), rgba(0, 229, 255, 0.02)) !important;
      border-color: rgba(0, 229, 255, 0.15) !important;
      color: var(--cyan) !important;
      font-weight: 600 !important;
    }
    .sb-link.active::before {
      content: '';
      position: absolute;
      left: 0;
      top: 6px;
      bottom: 6px;
      width: 3px;
      background: var(--cyan);
      border-radius: 0 4px 4px 0;
    }
    .sb-icon {
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      width: 20px !important;
      height: 20px !important;
      margin: 0 !important;
      flex-shrink: 0 !important;
      color: inherit !important;
      transition: transform 0.25s ease !important;
    }
    .sb-link:hover .sb-icon {
      transform: scale(1.15) rotate(2deg);
    }
    .sb-svg {
      width: 18px;
      height: 18px;
      stroke-width: 2.2;
    }
    .sb-badge {
      margin-left: auto !important;
      background: rgba(0, 229, 255, 0.12) !important;
      border: 1px solid rgba(0, 229, 255, 0.25) !important;
      color: var(--cyan) !important;
      font-family: var(--font-mono) !important;
      font-size: 0.62rem !important;
      font-weight: 700 !important;
      border-radius: 6px !important;
      padding: 1px 6px !important;
      text-transform: uppercase;
    }
    
    /* Smooth page-wide stress-free transitions */
    body {
      transition: background-color 0.3s ease, color 0.3s ease;
    }
    .main {
      animation: fadeIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Topbar buttons micro-interactions */
    .tb-btn {
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
      position: relative !important;
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      overflow: visible !important;
      cursor: pointer !important;
    }
    .tb-btn:hover {
      background: var(--surface2) !important;
      border-color: rgba(0, 229, 255, 0.3) !important;
      color: var(--cyan) !important;
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 229, 255, 0.12);
    }
    .tb-btn:active {
      transform: translateY(0) scale(0.95);
    }
    .tb-btn svg {
      transition: transform 0.25s ease, color 0.25s ease !important;
      pointer-events: none;
    }
    .tb-btn#themeToggle:hover svg {
      transform: rotate(25deg) scale(1.1);
    }
    .tb-btn#notifBtn:hover svg {
      animation: tb-bell-wiggle 0.6s ease-in-out infinite;
    }
    @keyframes tb-bell-wiggle {
      0%, 100% { transform: rotate(0); }
      15% { transform: rotate(-10deg); }
      30% { transform: rotate(10deg); }
      45% { transform: rotate(-8deg); }
      60% { transform: rotate(8deg); }
      75% { transform: rotate(-4deg); }
      90% { transform: rotate(4deg); }
    }
  `;

  // Inject styles
  const styleEl = document.createElement('style');
  styleEl.textContent = css;
  document.head.appendChild(styleEl);

  // 3. Render HTML content
  function render() {
    const sb = document.getElementById('sidebar');
    if (!sb) return;

    const user = typeof PC !== 'undefined' ? PC.getUser() : null;
    const email = user?.email || localStorage.getItem('pc_user_email') || '';
    const fullName = user?.full_name || email.split('@')[0] || 'User';
    const firstName = fullName.split(' ')[0] || 'User';
    const disp = firstName.charAt(0).toUpperCase() + firstName.slice(1);
    const plan = user?.plan || 'free';
    const planCap = plan.charAt(0).toUpperCase() + plan.slice(1);

    const links = [
      { type: 'section', title: 'Main' },
      { type: 'link', title: 'Dashboard', url: 'dashboard.html', icon: icons.dashboard },
      { type: 'link', title: 'New Scan', url: 'dashboard-scan.html', icon: icons.scan },
      { type: 'link', title: 'Scan History', url: 'dashboard-history.html', icon: icons.history },
      { type: 'link', title: 'Domains', url: 'dashboard-domains.html', icon: icons.domains },
      { type: 'section', title: 'Tools' },
      { type: 'link', title: 'AI Assistant', url: 'dashboard-ai.html', icon: icons.ai },
      { type: 'link', title: 'Security Badges', url: 'dashboard-badges.html', icon: icons.badge },
      { type: 'link', title: 'Reports', url: 'dashboard-reports.html', icon: icons.reports },
      { type: 'section', title: 'Account' },
      { type: 'link', title: 'Settings', url: 'dashboard-settings.html', icon: icons.settings },
      { type: 'link', title: 'Upgrade', url: 'pricing.html', icon: icons.upgrade, badge: planCap }
    ];

    const currentPath = window.location.pathname;

    const navHtml = links.map(l => {
      if (l.type === 'section') {
        return `<div class="sb-section">${l.title}</div>`;
      }
      const isActive = currentPath.endsWith(l.url) || (l.url === 'dashboard.html' && (currentPath === '/dashboard' || currentPath.endsWith('/')));
      const badgeHtml = l.badge ? `<span class="sb-badge">${l.badge}</span>` : '';
      return `
        <a href="${l.url}" class="sb-link${isActive ? ' active' : ''}">
          <span class="sb-icon">${l.icon}</span>
          <span>${l.title}</span>
          ${badgeHtml}
        </a>
      `;
    }).join('');

    sb.innerHTML = `
      <div class="sb-logo" onclick="window.location.href='dashboard.html'" style="cursor:pointer">
        <div class="sb-logo-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="32" height="32">
            <defs>
              <linearGradient id="penchecker-grad-sidebar" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#00e5ff" />
                <stop offset="50%" stop-color="#7c3aed" />
                <stop offset="100%" stop-color="#00ff87" />
              </linearGradient>
              <filter id="penchecker-glow-sidebar" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>
            <path d="M50 12 L82 22 V52 C82 70 68 83 50 88 C32 83 18 70 18 52 V22 Z" fill="none" stroke="url(#penchecker-grad-sidebar)" stroke-width="3" stroke-linejoin="round" filter="url(#penchecker-glow-sidebar)" />
            <path d="M30 40 A 24 24 0 0 1 70 40" fill="none" stroke="#00e5ff" stroke-width="1.5" stroke-dasharray="4 3" opacity="0.8" />
            <path d="M36 48 A 16 16 0 0 1 64 48" fill="none" stroke="#7c3aed" stroke-width="1.5" stroke-dasharray="2 2" opacity="0.6" />
            <path d="M50 28 L62 54 L50 72 L38 54 Z" fill="url(#penchecker-grad-sidebar)" />
            <line x1="50" y1="38" x2="50" y2="60" stroke="#060608" stroke-width="2" stroke-linecap="round" />
            <circle cx="50" cy="34" r="2.5" fill="#00ff87" filter="url(#penchecker-glow-sidebar)" />
          </svg>
        </div>
        <div class="sb-logo-text">Pen<span>Checker</span></div>
      </div>
      <nav class="sb-nav">${navHtml}</nav>
      <div class="sb-bottom">
        <div class="sb-user" onclick="window.location.href='dashboard-settings.html'">
          <div class="sb-avatar" id="sbAvatar">${disp.charAt(0)}</div>
          <div style="overflow:hidden;">
            <div class="sb-uname" id="sbName">${fullName}</div>
            <div class="sb-uplan" id="sbPlan">${planCap} Plan</div>
          </div>
          <div style="margin-left:auto;color:var(--muted);font-size:0.7rem;">&rsaquo;</div>
        </div>
      </div>
    `;
  }

  // 4. Handle topbar icons dynamically (observer-based synchronization)
  function initTopbarIcons() {
    const tBtn = document.getElementById('themeToggle');
    const nBtn = document.getElementById('notifBtn');

    const sunIcon = `<svg class="tb-svg-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="color:var(--cyan);"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
    const moonIcon = `<svg class="tb-svg-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="color:var(--muted2);"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
    const bellIcon = `<svg class="tb-svg-icon" viewBox="0 0 24 24" width="18" height="18" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;color:var(--muted2);"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>`;

    if (tBtn) {
      const updateThemeToggle = () => {
        const isLight = document.body.classList.contains('light-theme');
        const expectedHTML = isLight ? sunIcon : moonIcon;
        if (tBtn.innerHTML !== expectedHTML) {
          tBtn.innerHTML = expectedHTML;
        }
      };

      // Run initially
      updateThemeToggle();

      // Observe theme button content resets
      const observer = new MutationObserver(() => {
        observer.disconnect();
        updateThemeToggle();
        observer.observe(tBtn, { childList: true, characterData: true, subtree: true });
      });
      observer.observe(tBtn, { childList: true, characterData: true, subtree: true });

      // Observe body class changes to switch icons instantly
      const bodyObserver = new MutationObserver(() => {
        observer.disconnect();
        updateThemeToggle();
        observer.observe(tBtn, { childList: true, characterData: true, subtree: true });
      });
      bodyObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });
    }

    if (nBtn) {
      const hasIcon = nBtn.querySelector('svg');
      if (!hasIcon) {
        const dot = nBtn.querySelector('#notifDot');
        nBtn.innerHTML = '';
        const tempSpan = document.createElement('span');
        tempSpan.innerHTML = bellIcon;
        const svgNode = tempSpan.firstElementChild;
        nBtn.appendChild(svgNode);
        if (dot) {
          nBtn.appendChild(dot);
        } else {
          const newDot = document.createElement('span');
          newDot.className = 'notif-dot';
          newDot.id = 'notifDot';
          newDot.style.display = 'none';
          nBtn.appendChild(newDot);
        }
      }
    }
  }

  // Run immediately and also hook on DOMContentLoaded
  render();
  initTopbarIcons();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      render();
      initTopbarIcons();
    });
  }
})();
