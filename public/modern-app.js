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
        
        // Setup settings dropdown
        const settingsButton = document.getElementById('settingsButton');
        const settingsDropdown = document.getElementById('settingsDropdown');
        
        if (settingsButton && settingsDropdown) {
            // Toggle dropdown
            settingsButton.addEventListener('click', (e) => {
                e.stopPropagation();
                settingsDropdown.classList.toggle('hidden');
            });
            
            // Theme option clicks
            document.querySelectorAll('.theme-option').forEach(option => {
                option.addEventListener('click', (e) => {
                    const theme = e.currentTarget.getAttribute('data-theme');
                    this.applyTheme(theme);
                });
            });
            
            // Settings menu options
            document.getElementById('settingsUsersBtn').addEventListener('click', () => {
                settingsDropdown.classList.add('hidden');
                document.getElementById('showUsersBtn').click();
            });
            
            document.getElementById('settingsLogsBtn').addEventListener('click', () => {
                settingsDropdown.classList.add('hidden');
                document.getElementById('showLogsBtn').click();
            });
            
            // Close dropdown when clicking outside
            document.addEventListener('click', () => {
                settingsDropdown.classList.add('hidden');
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
    MicroInteractions.init();
});

// Export for use in main app.js
window.ModernEnhancements = {
    ThemeManager,
    LoadingManager,
    MicroInteractions
};