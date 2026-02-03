/**
 * Marvain GUI JavaScript Utilities
 */

(function(window) {
  'use strict';

  const Marvain = {
    // Toast notification system
    toastContainer: null,

    init: function() {
      // Create toast container if not exists
      if (!this.toastContainer) {
        this.toastContainer = document.createElement('div');
        this.toastContainer.className = 'toast-container';
        document.body.appendChild(this.toastContainer);
      }
      console.log('[Marvain] Initialized');
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
      toast.innerHTML = 
        '<div style="flex:1;">' +
          '<strong style="display:block;">' + this.escapeHtml(title) + '</strong>' +
          '<span style="font-size:0.875rem;">' + this.escapeHtml(message) + '</span>' +
        '</div>' +
        '<button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;cursor:pointer;font-size:1.25rem;line-height:1;">&times;</button>';

      this.toastContainer.appendChild(toast);

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
        document.body.appendChild(overlay);
      }
      overlay.innerHTML = 
        '<div class="loading-spinner"></div>' +
        '<div style="color:var(--color-gray-200);">' + this.escapeHtml(message || 'Loading...') + '</div>';
      overlay.style.display = 'flex';
    },

    /**
     * Hide loading overlay
     */
    hideLoading: function() {
      const overlay = document.getElementById('marvain-loading');
      if (overlay) {
        overlay.style.display = 'none';
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
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
        // Focus the first input in the modal
        const firstInput = modal.querySelector('input, select, textarea');
        if (firstInput) {
          setTimeout(() => firstInput.focus(), 100);
        }
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
        document.body.style.overflow = '';
        // Reset form if there's one in the modal
        const form = modal.querySelector('form');
        if (form) {
          form.reset();
        }
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

      console.log('[Marvain] Connecting to WebSocket...');
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('[Marvain] WebSocket connected');
        this.wsReconnectAttempts = 0;
        // Send hello message with access token
        this.wsSend({ action: 'hello', access_token: accessToken });
        this._wsEmit('connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          console.log('[Marvain] WebSocket message:', msg);
          this._wsEmit('message', msg);
          // Emit specific action type (for request/response messages)
          if (msg.action) {
            this._wsEmit(msg.action, msg);
          }
          // Emit specific type (for broadcast messages)
          if (msg.type) {
            this._wsEmit(msg.type, msg);
            // Also emit category-level events for page refresh
            this._handleBroadcast(msg);
          }
        } catch (e) {
          console.error('[Marvain] WebSocket parse error:', e);
        }
      };

      this.ws.onclose = (event) => {
        console.log('[Marvain] WebSocket closed:', event.code);
        this._wsEmit('disconnected', event);
        this.ws = null;
        // Attempt reconnect
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
      const payload = msg.payload || {};

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
      if (!payload.device_id) return;

      // Find the device row and update the status badge
      const row = document.querySelector('[data-device-id="' + payload.device_id + '"]');
      if (row) {
        const statusBadge = row.querySelector('.status-badge');
        if (statusBadge) {
          statusBadge.className = 'status-badge badge badge-success';
          statusBadge.textContent = 'online';
        }
        const heartbeatCell = row.querySelector('.heartbeat-time');
        if (heartbeatCell && payload.last_heartbeat_at) {
          heartbeatCell.textContent = payload.last_heartbeat_at;
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

