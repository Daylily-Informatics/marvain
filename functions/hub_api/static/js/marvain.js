/**
 * Marvain GUI JavaScript Utilities
 */

(function(window) {
  'use strict';

  const Marvain = {
    // Toast notification system
    toastContainer: null,
    activeModal: null,
    modalReturnFocus: new WeakMap(),

    init: function() {
      // Create toast container if not exists
      if (!this.toastContainer) {
        this.toastContainer = document.createElement('div');
        this.toastContainer.className = 'toast-container';
        this.toastContainer.setAttribute('aria-label', 'Notifications');
        document.body.appendChild(this.toastContainer);
      }
      this._initializeNavigation();
      this._initializeModals();
      document.querySelectorAll('.nav-link.active, .nav-dropdown-menu a.active').forEach(link => {
        link.setAttribute('aria-current', 'page');
      });
      console.log('[Marvain] Initialized');
    },

    announce: function(message) {
      const region = document.getElementById('marvain-announcer');
      if (!region) return;
      region.textContent = '';
      window.setTimeout(() => {
        region.textContent = String(message || '');
      }, 10);
    },

    /**
     * Show a toast notification
     * @param {string} type - success, error, warning, info
     * @param {string} title - Toast title
     * @param {string} message - Toast message
     * @param {number} duration - Duration in ms (default 5000)
     */
    showToast: function(type, title, message, duration) {
      duration = duration || 5000;

      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
      toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
      toast.setAttribute('aria-atomic', 'true');

      const content = document.createElement('div');
      content.className = 'toast-content';
      const heading = document.createElement('strong');
      heading.className = 'toast-title';
      heading.textContent = String(title || 'Notification');
      const body = document.createElement('span');
      body.className = 'toast-message';
      body.textContent = String(message || '');
      content.append(heading, body);

      const closeButton = document.createElement('button');
      closeButton.type = 'button';
      closeButton.className = 'toast-close';
      closeButton.setAttribute('aria-label', 'Dismiss notification');
      closeButton.textContent = '\u00d7';
      closeButton.addEventListener('click', () => toast.remove());
      toast.append(content, closeButton);

      this.toastContainer.appendChild(toast);
      this.announce((title || 'Notification') + ': ' + (message || ''));

      setTimeout(function() {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(function() { toast.remove(); }, 300);
      }, duration);
    },

    /**
     * Show loading overlay
     * @param {string} message - Loading message
     */
    showLoading: function(message) {
      let overlay = document.getElementById('marvain-loading');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'marvain-loading';
        overlay.className = 'loading-overlay';
        overlay.setAttribute('role', 'status');
        overlay.setAttribute('aria-live', 'polite');
        overlay.setAttribute('aria-atomic', 'true');
        document.body.appendChild(overlay);
      }
      overlay.innerHTML = 
        '<div class="loading-spinner" aria-hidden="true"></div>' +
        '<div class="loading-message">' + this.escapeHtml(message || 'Loading...') + '</div>';
      overlay.style.display = 'flex';
      const main = document.getElementById('main-content');
      if (main) main.setAttribute('aria-busy', 'true');
      this.announce(message || 'Loading');
    },

    /**
     * Hide loading overlay
     */
    hideLoading: function() {
      const overlay = document.getElementById('marvain-loading');
      if (overlay) {
        overlay.style.display = 'none';
      }
      const main = document.getElementById('main-content');
      if (main) main.setAttribute('aria-busy', 'false');
    },

    _initializeNavigation: function() {
      const toggle = document.getElementById('mobile-nav-toggle');
      const nav = document.getElementById('primary-navigation');
      if (toggle && nav) {
        toggle.addEventListener('click', () => {
          this._setMobileNavigation(toggle.getAttribute('aria-expanded') !== 'true');
        });
        nav.querySelectorAll('a').forEach(link => {
          link.addEventListener('click', () => this._setMobileNavigation(false));
        });
      }

      document.querySelectorAll('.nav-dropdown-toggle').forEach((button, index) => {
        button.setAttribute('aria-expanded', 'false');
        const menu = button.nextElementSibling;
        if (menu && !menu.id) {
          menu.id = 'nav-menu-' + String(index + 1);
        }
        if (menu && menu.id) button.setAttribute('aria-controls', menu.id);
        button.addEventListener('click', event => {
          event.stopPropagation();
          const dropdown = button.closest('.nav-dropdown');
          const opening = !dropdown.classList.contains('is-open');
          this._closeNavigationDropdowns(dropdown);
          dropdown.classList.toggle('is-open', opening);
          button.setAttribute('aria-expanded', String(opening));
          if (opening && menu) {
            const firstLink = menu.querySelector('a');
            if (firstLink) firstLink.focus();
          }
        });
        button.addEventListener('keydown', event => {
          if (event.key === 'ArrowDown') {
            event.preventDefault();
            button.click();
          }
        });
      });

      document.addEventListener('click', event => {
        if (!event.target.closest('.nav-dropdown')) this._closeNavigationDropdowns();
      });
      window.addEventListener('resize', () => {
        if (window.innerWidth > 900) this._setMobileNavigation(false);
      });
    },

    _setMobileNavigation: function(open) {
      const toggle = document.getElementById('mobile-nav-toggle');
      const nav = document.getElementById('primary-navigation');
      if (!toggle || !nav) return;
      nav.classList.toggle('is-open', open);
      document.body.classList.toggle('nav-open', open);
      toggle.setAttribute('aria-expanded', String(open));
      toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
      const icon = toggle.querySelector('i');
      if (icon) icon.className = open ? 'fas fa-times' : 'fas fa-bars';
      if (open) {
        const firstItem = nav.querySelector('a, button');
        if (firstItem) firstItem.focus();
      }
    },

    _closeNavigationDropdowns: function(except) {
      document.querySelectorAll('.nav-dropdown.is-open').forEach(dropdown => {
        if (dropdown === except) return;
        dropdown.classList.remove('is-open');
        const button = dropdown.querySelector('.nav-dropdown-toggle');
        if (button) button.setAttribute('aria-expanded', 'false');
      });
    },

    _initializeModals: function() {
      document.querySelectorAll('.modal[id], .modal-overlay[id]').forEach(modal => {
        this._prepareModal(modal);
      });
      document.addEventListener('keydown', event => {
        if (event.key === 'Escape') {
          if (this.activeModal && this._isVisible(this.activeModal)) {
            event.preventDefault();
            this.hideModal(this.activeModal.id);
            return;
          }
          this._setMobileNavigation(false);
          this._closeNavigationDropdowns();
          const toggle = document.getElementById('mobile-nav-toggle');
          if (toggle && window.innerWidth <= 900) toggle.focus();
        }
        if (event.key === 'Tab' && this.activeModal && this._isVisible(this.activeModal)) {
          this._trapModalFocus(event, this.activeModal);
        }
      });
    },

    _prepareModal: function(modal) {
      modal.setAttribute('aria-hidden', this._isVisible(modal) ? 'false' : 'true');
      const surface = this._modalSurface(modal);
      surface.setAttribute('role', 'dialog');
      surface.setAttribute('aria-modal', 'true');
      const heading = surface.querySelector('.modal-title, .modal-header h2, .modal-header h3');
      if (heading) {
        if (!heading.id) heading.id = modal.id + '-title';
        surface.setAttribute('aria-labelledby', heading.id);
      } else {
        surface.setAttribute('aria-label', 'Dialog');
      }
      surface.querySelectorAll('.modal-close, .modal-header button').forEach(button => {
        if (!button.getAttribute('aria-label')) button.setAttribute('aria-label', 'Close dialog');
      });
    },

    _modalSurface: function(modal) {
      if (modal.classList.contains('modal-overlay')) {
        return modal.querySelector('.modal') || modal;
      }
      return modal.querySelector('.modal-content') || modal;
    },

    _isVisible: function(element) {
      return Boolean(element && (element.offsetWidth || element.offsetHeight || element.getClientRects().length));
    },

    _focusableElements: function(container) {
      const selector = [
        'a[href]',
        'button:not([disabled])',
        'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])'
      ].join(',');
      return Array.from(container.querySelectorAll(selector)).filter(element => this._isVisible(element));
    },

    _trapModalFocus: function(event, modal) {
      const focusable = this._focusableElements(this._modalSurface(modal));
      if (!focusable.length) {
        event.preventDefault();
        this._modalSurface(modal).focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @returns {Promise<boolean>}
     */
    copyToClipboard: async function(text) {
      try {
        await navigator.clipboard.writeText(text);
        this.showToast('success', 'Copied', 'Text copied to clipboard', 2000);
        return true;
      } catch (err) {
        console.error('Failed to copy:', err);
        this.showToast('error', 'Error', 'Failed to copy to clipboard');
        return false;
      }
    },

    /**
     * Debounce function
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function}
     */
    debounce: function(func, wait) {
      let timeout;
      return function executedFunction() {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function() {
          func.apply(context, args);
        }, wait);
      };
    },

    /**
     * Format relative time
     * @param {string|Date} date - Date to format
     * @returns {string}
     */
    relativeTime: function(date) {
      const now = new Date();
      const then = new Date(date);
      const diff = Math.floor((now - then) / 1000);

      if (diff < 60) return 'just now';
      if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
      if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
      if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
      return then.toLocaleDateString();
    },

    /**
     * Escape HTML special characters
     * @param {string} str - String to escape
     * @returns {string}
     */
    escapeHtml: function(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },

    /**
     * Show a modal by ID
     * @param {string} modalId - The ID of the modal element to show
     */
    showModal: function(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        this._prepareModal(modal);
        this.modalReturnFocus.set(modal, document.activeElement);
        modal.style.display = 'flex';
        modal.classList.add('active');
        modal.setAttribute('aria-hidden', 'false');
        document.body.classList.add('modal-open');
        this.activeModal = modal;
        const surface = this._modalSurface(modal);
        if (!surface.hasAttribute('tabindex')) surface.setAttribute('tabindex', '-1');
        const focusable = this._focusableElements(surface);
        const preferred = Array.from(
          surface.querySelectorAll('[autofocus], input:not([type="hidden"]), select, textarea')
        ).find(element => this._isVisible(element) && !element.disabled);
        (preferred || focusable[0] || surface).focus();
      } else {
        console.warn('[Marvain] Modal not found:', modalId);
      }
    },

    /**
     * Hide a modal by ID
     * @param {string} modalId - The ID of the modal element to hide
     */
    hideModal: function(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.style.display = 'none';
        modal.classList.remove('active');
        modal.setAttribute('aria-hidden', 'true');
        this.activeModal = null;
        const anotherModal = Array.from(document.querySelectorAll('.modal[id], .modal-overlay[id]'))
          .find(candidate => candidate !== modal && this._isVisible(candidate));
        document.body.classList.toggle('modal-open', Boolean(anotherModal));
        // Reset form if there's one in the modal
        const form = modal.querySelector('form');
        if (form) {
          form.reset();
        }
        const returnFocus = this.modalReturnFocus.get(modal);
        this.modalReturnFocus.delete(modal);
        if (returnFocus && document.contains(returnFocus)) returnFocus.focus();
      }
    },

    /**
     * Make an authenticated API request
     * @param {string} url - URL to fetch
     * @param {Object} options - Fetch options
     * @returns {Promise<Object>}
     */
    api: async function(url, options) {
      options = options || {};
      options.headers = options.headers || {};
      options.headers['Content-Type'] = options.headers['Content-Type'] || 'application/json';
      options.credentials = 'same-origin';

      const response = await fetch(url, options);
      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(error.detail || 'Request failed');
      }
      return response.json();
    },

    // WebSocket client for real-time updates
    ws: null,
    wsCallbacks: {},
    wsReconnectAttempts: 0,
    wsMaxReconnectAttempts: 5,
    wsReconnectDelay: 1000,
    wsAuthenticated: false,
    wsAuthFailed: false,
    wsConnectInFlight: false,

    /**
     * Connect to WebSocket server
     * @param {string} url - WebSocket URL
     * @param {string} accessToken - Access token for authentication
     */
    wsConnect: function(url, accessToken) {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        console.log('[Marvain] WebSocket already connected');
        return;
      }
      if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
        console.log('[Marvain] WebSocket connection already in progress');
        return;
      }

      console.log('[Marvain] Connecting to WebSocket...');
      this.wsConnectInFlight = true;
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('[Marvain] WebSocket connected, sending hello...');
        this.wsConnectInFlight = false;
        this.wsReconnectAttempts = 0;
        // Send hello message with access token
        // Note: We emit 'connected' only after receiving a successful hello response
        this.wsSend({ action: 'hello', access_token: accessToken });
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          console.log('[Marvain] WebSocket message:', msg);

          // Handle hello response specially - only emit 'connected' after successful auth
          if (msg.type === 'hello') {
            if (msg.ok) {
              console.log('[Marvain] Authenticated successfully');
              this.wsAuthenticated = true;
              this._wsEmit('connected');
            } else {
              console.error('[Marvain] Authentication failed:', msg.error);
              this.wsAuthFailed = true;
              this._wsEmit('auth_failed', msg);
              // Close connection on auth failure
              this.ws.close();
              return;
            }
          }

          this._wsEmit('message', msg);
          // Emit specific action type (for request/response messages)
          if (msg.action) {
            this._wsEmit(msg.action, msg);
          }
          // Emit specific type (for broadcast messages)
          if (msg.type) {
            this._wsEmit(msg.type, msg);
            // Also emit category-level events for page refresh (skip hello and error types)
            if (msg.type !== 'hello' && msg.type !== 'error') {
              this._handleBroadcast(msg);
            }
          }
        } catch (e) {
          console.error('[Marvain] WebSocket parse error:', e);
        }
      };

      this.ws.onclose = (event) => {
        console.log('[Marvain] WebSocket closed:', event.code);
        this._wsEmit('disconnected', event);
        this.ws = null;
        this.wsAuthenticated = false;
        this.wsConnectInFlight = false;
        // Attempt reconnect
        if (this.wsAuthFailed) {
          // Auth failures need a fresh token; caller should fetch a new one and reconnect.
          this.wsAuthFailed = false;
          return;
        }
        if (this.wsReconnectAttempts < this.wsMaxReconnectAttempts) {
          this.wsReconnectAttempts++;
          const delay = this.wsReconnectDelay * Math.pow(2, this.wsReconnectAttempts - 1);
          console.log('[Marvain] Reconnecting in ' + delay + 'ms...');
          setTimeout(() => this.wsConnect(url, accessToken), delay);
        }
      };

      this.ws.onerror = (error) => {
        console.error('[Marvain] WebSocket error:', error);
        this._wsEmit('error', error);
      };
    },

    /**
     * Send a message through WebSocket
     * @param {Object} message - Message to send
     */
    wsSend: function(message) {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(message));
      } else {
        console.warn('[Marvain] WebSocket not connected');
      }
    },

    /**
     * Subscribe to WebSocket events
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
     */
    wsOn: function(event, callback) {
      if (!this.wsCallbacks[event]) {
        this.wsCallbacks[event] = [];
      }
      this.wsCallbacks[event].push(callback);
    },

    /**
     * Unsubscribe from WebSocket events
     * @param {string} event - Event name
     * @param {Function} callback - Callback function
     */
    wsOff: function(event, callback) {
      if (this.wsCallbacks[event]) {
        this.wsCallbacks[event] = this.wsCallbacks[event].filter(cb => cb !== callback);
      }
    },

    /**
     * Emit WebSocket event to subscribers
     * @private
     */
    _wsEmit: function(event, data) {
      if (this.wsCallbacks[event]) {
        this.wsCallbacks[event].forEach(cb => cb(data));
      }
    },

    /**
     * Handle broadcast messages for real-time UI updates
     * @private
     */
    _handleBroadcast: function(msg) {
      const type = msg.type;
      const payload = msg.payload || msg || {};

      // Debounce rapid updates (max 1 refresh per 500ms per type)
      if (!this._broadcastTimers) {
        this._broadcastTimers = {};
      }
      if (this._broadcastTimers[type]) {
        return; // Skip if we have a pending refresh
      }

      // Visual indicator that real-time update arrived
      this._showUpdateIndicator(type);

      // Schedule page-specific refresh based on broadcast type
      this._broadcastTimers[type] = setTimeout(() => {
        delete this._broadcastTimers[type];

        switch (type) {
          case 'events.new':
            // Refresh events list if on events page
            if (window.location.pathname.includes('/events')) {
              this._refreshPageSection('events-table');
            }
            break;

          case 'actions.updated':
            // Refresh actions list if on actions page
            if (window.location.pathname.includes('/actions')) {
              this._refreshPageSection('actions-table');
            }
            break;

          case 'presence.updated':
            // Update device status indicators on devices/remotes pages
            if (window.location.pathname.includes('/devices') ||
                window.location.pathname.includes('/remotes')) {
              this._updatePresenceIndicator(payload);
            }
            break;

          case 'memories.new':
            // Refresh memories list if on memories page
            if (window.location.pathname.includes('/memories')) {
              this._refreshPageSection('memories-table');
            }
            break;
        }
      }, 500);
    },

    /**
     * Show visual indicator that a real-time update arrived
     * @private
     */
    _showUpdateIndicator: function(type) {
      // Create a small toast or badge indicating new data
      const indicator = document.createElement('div');
      indicator.className = 'marvain-update-indicator';
      indicator.textContent = 'Update: ' + type.replace('.', ' ');
      indicator.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#6366f1;color:#fff;padding:8px 16px;border-radius:8px;font-size:12px;z-index:9999;opacity:0;transition:opacity 0.3s;';
      document.body.appendChild(indicator);

      // Fade in
      requestAnimationFrame(() => {
        indicator.style.opacity = '1';
      });

      // Fade out and remove after 2s
      setTimeout(() => {
        indicator.style.opacity = '0';
        setTimeout(() => indicator.remove(), 300);
      }, 2000);
    },

    /**
     * Refresh a page section by reloading the page
     * @private
     */
    _refreshPageSection: function(sectionId) {
      // For now, simply reload the page to get fresh data
      // In the future, this could be replaced with AJAX partial updates
      console.log('[Marvain] Refreshing page for section:', sectionId);
      window.location.reload();
    },

    /**
     * Update presence indicator for a device without full page reload
     * @private
     */
    _updatePresenceIndicator: function(payload) {
      const deviceId = payload.device_id || '';
      if (!deviceId) return;

      // Find the device row and update the status badge
      const row = document.querySelector('[data-device-id="' + deviceId + '"]');
      if (row) {
        const statusBadge = row.querySelector('.status-badge');
        if (statusBadge) {
          const status = String(payload.status || 'online').toLowerCase();
          statusBadge.className = status === 'offline'
            ? 'status-badge badge badge-warning'
            : 'status-badge badge badge-success';
          statusBadge.textContent = status;
        }
        const heartbeatCell = row.querySelector('.heartbeat-time');
        if (heartbeatCell && payload.last_heartbeat_at) {
          heartbeatCell.textContent = this.relativeTime(payload.last_heartbeat_at);
        }
      }
    },

    /**
     * Disconnect WebSocket
     */
    wsDisconnect: function() {
      this.wsMaxReconnectAttempts = 0; // Prevent reconnect
      if (this.ws) {
        this.ws.close();
        this.ws = null;
      }
    },

    /**
     * Check if WebSocket is connected
     * @returns {boolean}
     */
    wsIsConnected: function() {
      return this.ws && this.ws.readyState === WebSocket.OPEN;
    }
  };

  // Auto-initialize on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', function() {
    Marvain.init();
  });

  // Expose globally
  window.Marvain = Marvain;

})(window);
