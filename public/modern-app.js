/**
 * Modern enhancements for ResiLIVE
 */

// Theme Management
const ThemeManager = {
    themes: ['dark', 'light', 'ocean', 'forest'],
    currentTheme: 'dark',
    
    init() {
        // Load saved theme or default to dark
        this.currentTheme = localStorage.getItem('resilive-theme') || 'dark';
        this.applyTheme(this.currentTheme);
        
        // Setup theme dropdown
        const themeButton = document.getElementById('themeButton');
        const themeDropdown = document.getElementById('themeDropdown');
        
        if (themeButton && themeDropdown) {
            // Toggle dropdown
            themeButton.addEventListener('click', (e) => {
                e.stopPropagation();
                themeDropdown.classList.toggle('hidden');
            });
            
            // Theme option clicks
            document.querySelectorAll('.theme-option').forEach(option => {
                option.addEventListener('click', (e) => {
                    const theme = e.currentTarget.getAttribute('data-theme');
                    this.applyTheme(theme);
                    themeDropdown.classList.add('hidden');
                });
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', () => {
                themeDropdown.classList.add('hidden');
            });
        }
    },
    
    applyTheme(theme) {
        this.currentTheme = theme;
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('resilive-theme', theme);
        
        // Update active state in dropdown
        document.querySelectorAll('.theme-option').forEach(option => {
            if (option.getAttribute('data-theme') === theme) {
                option.classList.add('active');
            } else {
                option.classList.remove('active');
            }
        });
    },
    
};

// Dashboard Manager
const DashboardManager = {
    updateInterval: null,
    
    init() {
        this.updateDashboardStats();
        // Update stats every 30 seconds
        this.updateInterval = setInterval(() => this.updateDashboardStats(), 30000);
        
        // Setup show/hide dashboard based on community selection
        this.setupDashboardToggle();
    },
    
    async updateDashboardStats() {
        try {
            // Calculate stats from existing data
            const totalResidents = this.calculateTotalResidents();
            const activeCodes = this.calculateActiveCodes();
            const recentAccess = await this.fetchRecentAccess();
            const totalCommunities = communities.length;
            
            // Update UI with animation
            this.animateValue('totalResidents', totalResidents);
            this.animateValue('activeCodes', activeCodes);
            this.animateValue('recentAccess', recentAccess);
            this.animateValue('totalCommunities', totalCommunities);
        } catch (error) {
            console.error('Error updating dashboard stats:', error);
        }
    },
    
    calculateTotalResidents() {
        let total = 0;
        communities.forEach(community => {
            if (community.addresses) {
                community.addresses.forEach(address => {
                    if (address.people) {
                        total += address.people.length;
                    }
                });
            }
        });
        return total;
    },
    
    calculateActiveCodes() {
        let total = 0;
        const now = new Date();
        communities.forEach(community => {
            if (community.addresses) {
                community.addresses.forEach(address => {
                    if (address.people) {
                        address.people.forEach(person => {
                            if (person.codes) {
                                person.codes.forEach(code => {
                                    const expiryDate = new Date(code.expiresAt);
                                    if (expiryDate > now) {
                                        total++;
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
        return total;
    },
    
    async fetchRecentAccess() {
        try {
            const response = await fetch('/api/logs/today-count', {
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                return data.count || 0;
            }
        } catch (error) {
            console.error('Error fetching recent access:', error);
        }
        return 0;
    },
    
    animateValue(elementId, endValue, duration = 1000) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const startValue = parseInt(element.textContent) || 0;
        const startTime = performance.now();
        
        const updateValue = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const currentValue = Math.floor(startValue + (endValue - startValue) * easeOutQuart);
            
            element.textContent = currentValue.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(updateValue);
            }
        };
        
        requestAnimationFrame(updateValue);
    },
    
    setupDashboardToggle() {
        // Show dashboard when no community is selected
        const updateDashboardVisibility = () => {
            const dashboard = document.getElementById('dashboard');
            const communityDetails = document.getElementById('communityDetails');
            const communityName = document.getElementById('communityName');
            
            if (!dashboard || !communityDetails) return;
            
            if (selectedCommunity) {
                dashboard.classList.add('hidden');
                communityDetails.classList.remove('hidden');
            } else {
                dashboard.classList.remove('hidden');
                communityDetails.classList.add('hidden');
                // Update community name to prompt
                if (communityName) {
                    communityName.textContent = 'Please select a community';
                    communityName.classList.remove('hidden');
                }
            }
        };
        
        // Override the selectCommunity function
        if (typeof window.selectCommunity === 'function') {
            const originalSelectCommunity = window.selectCommunity;
            window.selectCommunity = function(community) {
                originalSelectCommunity.call(this, community);
                updateDashboardVisibility();
                // Update stats when community is selected
                if (window.ModernEnhancements && window.ModernEnhancements.DashboardManager) {
                    window.ModernEnhancements.DashboardManager.updateDashboardStats();
                }
            };
        }
        
        // Initial visibility
        setTimeout(() => updateDashboardVisibility(), 100);
    },
    
    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
};

// Loading States Manager
const LoadingManager = {
    createSkeleton(type = 'text', customClass = '') {
        const skeleton = document.createElement('div');
        skeleton.className = `skeleton skeleton-${type} ${customClass}`;
        
        switch(type) {
            case 'card':
                skeleton.style.height = '120px';
                skeleton.style.borderRadius = 'var(--radius-lg)';
                break;
            case 'list-item':
                skeleton.style.height = '48px';
                skeleton.style.marginBottom = '8px';
                skeleton.style.borderRadius = 'var(--radius-md)';
                break;
            case 'text':
            default:
                skeleton.style.height = '20px';
                skeleton.style.width = '60%';
                skeleton.style.borderRadius = 'var(--radius-sm)';
                break;
        }
        
        return skeleton;
    },
    
    showListSkeleton(containerId, count = 5) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        container.innerHTML = '';
        for (let i = 0; i < count; i++) {
            container.appendChild(this.createSkeleton('list-item'));
        }
    },
    
    createSpinner() {
        const spinner = document.createElement('div');
        spinner.className = 'spinner';
        return spinner;
    }
};

// Micro Interactions
const MicroInteractions = {
    init() {
        // Add ripple effect to buttons
        this.setupRippleEffect();
        
        // Add hover sounds (optional - requires audio files)
        this.setupHoverEffects();
        
        // Add success/error animations
        this.setupFeedbackAnimations();
    },
    
    setupRippleEffect() {
        document.addEventListener('click', (e) => {
            const button = e.target.closest('button');
            if (!button) return;
            
            const ripple = document.createElement('span');
            ripple.className = 'ripple';
            
            const rect = button.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = e.clientX - rect.left - size / 2;
            const y = e.clientY - rect.top - size / 2;
            
            ripple.style.width = ripple.style.height = size + 'px';
            ripple.style.left = x + 'px';
            ripple.style.top = y + 'px';
            
            button.style.position = 'relative';
            button.style.overflow = 'hidden';
            button.appendChild(ripple);
            
            setTimeout(() => ripple.remove(), 600);
        });
    },
    
    setupHoverEffects() {
        // Add subtle scale animation on hover for interactive elements
        const interactiveElements = document.querySelectorAll('button, .clickable, .stats-card');
        interactiveElements.forEach(element => {
            element.addEventListener('mouseenter', () => {
                element.style.transition = 'transform 0.2s ease';
            });
        });
    },
    
    setupFeedbackAnimations() {
        // Success animation
        window.showSuccess = (message) => {
            const notification = this.createNotification(message, 'success');
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.transform = 'translateX(400px)';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        };
        
        // Error animation
        window.showError = (message) => {
            const notification = this.createNotification(message, 'error');
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.transform = 'translateX(400px)';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        };
    },
    
    createNotification(message, type) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            background: ${type === 'success' ? 'var(--color-success)' : 'var(--color-danger)'};
            color: white;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            transform: translateX(400px);
            transition: transform 0.3s ease;
            z-index: 10000;
        `;
        
        // Trigger animation
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        return notification;
    }
};

// Add ripple effect CSS
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
    .ripple {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.5);
        transform: scale(0);
        animation: ripple-animation 0.6s ease-out;
    }
    
    @keyframes ripple-animation {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(rippleStyle);

// Initialize all modern features when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    ThemeManager.init();
    DashboardManager.init();
    MicroInteractions.init();
    
    // Hook into existing data loading
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        return originalFetch.apply(this, args).then(response => {
            // Update dashboard when communities are loaded
            if (args[0] === '/api/communities' && response.ok) {
                setTimeout(() => {
                    if (window.ModernEnhancements && window.ModernEnhancements.DashboardManager) {
                        window.ModernEnhancements.DashboardManager.updateDashboardStats();
                    }
                }, 100);
            }
            return response;
        });
    };
});

// Export for use in main app.js
window.ModernEnhancements = {
    ThemeManager,
    DashboardManager,
    LoadingManager,
    MicroInteractions
};