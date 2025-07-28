/**
 * Modern enhancements for ResiLIVE
 */

// Theme Management
const ThemeManager = {
    themes: ['dark', 'light', 'ocean', 'forest'],
    currentThemeIndex: 0,
    
    init() {
        // Load saved theme or default to dark
        const savedTheme = localStorage.getItem('resilive-theme') || 'dark';
        const themeIndex = this.themes.indexOf(savedTheme);
        this.currentThemeIndex = themeIndex >= 0 ? themeIndex : 0;
        this.applyTheme(this.themes[this.currentThemeIndex]);
        
        // Setup theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }
    },
    
    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('resilive-theme', theme);
        this.updateThemeIcon(theme);
    },
    
    toggleTheme() {
        this.currentThemeIndex = (this.currentThemeIndex + 1) % this.themes.length;
        const newTheme = this.themes[this.currentThemeIndex];
        this.applyTheme(newTheme);
        
        // Add rotation animation to toggle button
        const themeToggle = document.getElementById('themeToggle');
        themeToggle.style.transform = 'scale(1.1) rotate(180deg)';
        setTimeout(() => {
            themeToggle.style.transform = '';
        }, 300);
    },
    
    updateThemeIcon(theme) {
        const themeToggle = document.getElementById('themeToggle');
        if (!themeToggle) return;
        
        // Update icon based on theme
        const svg = themeToggle.querySelector('svg');
        if (theme === 'light') {
            svg.innerHTML = `
                <circle cx="12" cy="12" r="5"></circle>
                <line x1="12" y1="1" x2="12" y2="3"></line>
                <line x1="12" y1="21" x2="12" y2="23"></line>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                <line x1="1" y1="12" x2="3" y2="12"></line>
                <line x1="21" y1="12" x2="23" y2="12"></line>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
            `;
        } else if (theme === 'ocean') {
            svg.innerHTML = `
                <path d="M12 2.69l5.66 5.66a8 8 0 11-11.31 0z"></path>
            `;
        } else if (theme === 'forest') {
            svg.innerHTML = `
                <path d="M12 3l4.5 9H7.5L12 3z"></path>
                <path d="M12 7l3 6H9l3-6z"></path>
            `;
        } else {
            // Dark theme - moon icon
            svg.innerHTML = `
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"></path>
            `;
        }
    }
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
            
            if (selectedCommunity) {
                dashboard.classList.add('hidden');
                communityDetails.classList.remove('hidden');
            } else {
                dashboard.classList.remove('hidden');
                communityDetails.classList.add('hidden');
            }
        };
        
        // Listen for community selection changes
        const originalSelectCommunity = window.selectCommunity;
        window.selectCommunity = function(community) {
            originalSelectCommunity.call(this, community);
            updateDashboardVisibility();
        };
        
        // Initial visibility
        updateDashboardVisibility();
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
});

// Export for use in main app.js
window.ModernEnhancements = {
    ThemeManager,
    DashboardManager,
    LoadingManager,
    MicroInteractions
};