/**
 * Animation utilities for ResiLIVE
 */

const AnimationUtils = {
    // Show loading overlay
    showLoading(container, text = 'Loading') {
        const loadingOverlay = document.createElement('div');
        loadingOverlay.className = 'loading-overlay';
        loadingOverlay.innerHTML = `
            <div class="loading-content">
                <div class="loading-spinner"></div>
                <div class="loading-text">${text}<span class="loading-dots"></span></div>
            </div>
        `;
        
        if (typeof container === 'string') {
            container = document.getElementById(container);
        }
        
        if (container) {
            container.style.position = 'relative';
            container.appendChild(loadingOverlay);
        }
        
        return loadingOverlay;
    },
    
    // Hide loading overlay
    hideLoading(container) {
        if (typeof container === 'string') {
            container = document.getElementById(container);
        }
        
        if (container) {
            const loadingOverlay = container.querySelector('.loading-overlay');
            if (loadingOverlay) {
                loadingOverlay.style.opacity = '0';
                setTimeout(() => {
                    if (loadingOverlay.parentNode) {
                        loadingOverlay.parentNode.removeChild(loadingOverlay);
                    }
                }, 200);
            }
        }
    },
    
    // Show skeleton loading for lists
    showSkeletonLoading(container, itemCount = 3) {
        if (typeof container === 'string') {
            container = document.getElementById(container);
        }
        
        if (container) {
            container.innerHTML = '';
            for (let i = 0; i < itemCount; i++) {
                const skeletonItem = document.createElement('div');
                skeletonItem.className = 'skeleton-item';
                container.appendChild(skeletonItem);
            }
        }
    },
    
    // Animate element entrance
    animateIn(element, animationType = 'fadeInUp', delay = 0) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        
        if (element) {
            // Remove any existing animation classes
            element.classList.remove('fadeInUp', 'fadeInLeft', 'fadeInRight', 'slideInDown');
            
            setTimeout(() => {
                element.classList.add(animationType);
                // Clean up animation class after completion
                setTimeout(() => {
                    element.classList.remove(animationType);
                }, 500);
            }, delay);
        }
    },
    
    // Animate element exit
    animateOut(element, animationType = 'fadeOut', callback) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        
        if (element) {
            element.style.opacity = '0';
            element.style.transform = 'translateY(-10px)';
            element.style.transition = 'all 0.2s ease';
            
            setTimeout(() => {
                if (callback) callback();
            }, 200);
        }
    },
    
    // Stagger animation for multiple elements
    staggerAnimation(elements, animationType = 'fadeInUp', staggerDelay = 100) {
        if (typeof elements === 'string') {
            elements = document.querySelectorAll(elements);
        }
        
        elements.forEach((element, index) => {
            this.animateIn(element, animationType, index * staggerDelay);
        });
    },
    
    // Add pulse animation to element
    pulse(element) {
        if (typeof element === 'string') {
            element = document.getElementById(element);
        }
        
        if (element) {
            element.classList.add('pulse');
            setTimeout(() => {
                element.classList.remove('pulse');
            }, 1000);
        }
    },
    
    // Community transition effect
    transitionCommunity(callback) {
        const mainContent = document.querySelector('main');
        const communityName = document.getElementById('communityName');
        const addressList = document.getElementById('addressList');
        
        // Execute callback immediately to ensure functionality works
        if (callback) callback();
        
        // Add subtle animations without blocking
        setTimeout(() => {
            if (communityName) {
                this.animateIn(communityName, 'slideInDown');
            }
            
            if (addressList) {
                this.animateIn(addressList, 'fadeInLeft', 50);
                
                // Stagger animate address items
                setTimeout(() => {
                    const addressItems = addressList.querySelectorAll('.address-item');
                    this.staggerAnimation(addressItems, 'fadeInUp', 30);
                }, 100);
            }
        }, 50);
    },
    
    // Button loading state
    setButtonLoading(button, isLoading, originalText) {
        if (typeof button === 'string') {
            button = document.getElementById(button);
        }
        
        if (button) {
            if (isLoading) {
                button.disabled = true;
                button.dataset.originalText = originalText || button.textContent;
                button.innerHTML = `
                    <div class="loading-spinner loading-spinner-inline"></div>
                    Loading...
                `;
            } else {
                button.disabled = false;
                button.textContent = button.dataset.originalText || originalText || 'Submit';
            }
        }
    }
};

// Export for global access
window.AnimationUtils = AnimationUtils;