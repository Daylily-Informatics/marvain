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
          // Also emit specific action type
          if (msg.action) {
            this._wsEmit(msg.action, msg);
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

