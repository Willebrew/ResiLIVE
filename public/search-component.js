/**
 * Advanced Search and Filter Component for ResiLIVE
 */

const SearchComponent = {
    searchInput: null,
    filterDropdown: null,
    searchResults: null,
    searchTimeout: null,
    
    init() {
        this.createSearchUI();
        this.setupEventListeners();
    },
    
    createSearchUI() {
        // Add search button to topbar right
        const topbarRight = document.querySelector('.topbar-right');
        if (topbarRight) {
            const searchToggleBtn = document.createElement('button');
            searchToggleBtn.id = 'searchToggleBtn';
            searchToggleBtn.className = 'topnav-btn';
            searchToggleBtn.innerHTML = `
                <svg class="search-btn-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/>
                </svg>
                <span class="search-btn-text">Search</span>
            `;
            searchToggleBtn.addEventListener('click', () => this.toggleSearch());
            
            // Insert as first button in topbar-right
            topbarRight.insertBefore(searchToggleBtn, topbarRight.firstChild);
        }
        
        // Create search container
        const searchContainer = document.createElement('div');
        searchContainer.className = 'search-container hidden';
        searchContainer.innerHTML = `
            <div class="search-overlay-header">
                <div class="search-wrapper">
                    <svg class="search-icon" width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd"/>
                    </svg>
                    <input type="text" id="globalSearch" placeholder="Search communities, addresses, residents, or codes..." class="search-input">
                    <button class="search-filter-btn" id="filterToggle">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd"/>
                        </svg>
                    </button>
                    <button class="search-close-btn" id="searchCloseBtn">
                        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                        </svg>
                    </button>
                </div>
                <div class="search-filters hidden" id="searchFilters">
                    <div class="filter-group">
                        <div class="filter-group-label">Search in</div>
                        <div class="filter-toggles">
                            <label class="filter-chip active">
                                <input type="checkbox" name="searchType" value="communities" checked>
                                <span>Communities</span>
                            </label>
                            <label class="filter-chip active">
                                <input type="checkbox" name="searchType" value="addresses" checked>
                                <span>Addresses</span>
                            </label>
                            <label class="filter-chip active">
                                <input type="checkbox" name="searchType" value="residents" checked>
                                <span>Residents</span>
                            </label>
                            <label class="filter-chip active">
                                <input type="checkbox" name="searchType" value="codes" checked>
                                <span>Access Codes</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
            <div class="search-results hidden" id="searchResults"></div>
        `;
        
        // Insert as first child of body
        document.body.insertBefore(searchContainer, document.body.firstChild);
        
        // Store references
        this.searchInput = document.getElementById('globalSearch');
        this.searchResults = document.getElementById('searchResults');
    },
    
    setupEventListeners() {
        // Search input with debouncing
        this.searchInput.addEventListener('input', (e) => {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => {
                this.performSearch(e.target.value);
            }, 500);
        });
        
        // Filter toggle
        document.getElementById('filterToggle').addEventListener('click', () => {
            document.getElementById('searchFilters').classList.toggle('hidden');
        });
        
        // Filter chip toggles
        document.querySelectorAll('.filter-chip').forEach(chip => {
            chip.addEventListener('click', (e) => {
                e.preventDefault();
                const checkbox = chip.querySelector('input[type="checkbox"]');
                const isChecked = !checkbox.checked;
                
                checkbox.checked = isChecked;
                chip.classList.toggle('active', isChecked);
                
                if (this.searchInput.value) {
                    this.performSearch(this.searchInput.value);
                }
            });
        });
        
        
        // Close button
        document.getElementById('searchCloseBtn').addEventListener('click', () => {
            this.closeSearch();
        });
        
        // Escape key to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !document.querySelector('.search-container').classList.contains('hidden')) {
                this.closeSearch();
            }
        });
        
        // Event delegation for search result clicks
        this.searchResults.addEventListener('click', (e) => {
            const resultItem = e.target.closest('.search-result-item');
            if (!resultItem) return;
            
            const action = resultItem.dataset.action;
            const communityId = resultItem.dataset.communityId;
            const addressId = resultItem.dataset.addressId;
            const personId = resultItem.dataset.personId;
            const codeId = resultItem.dataset.codeId;
            
            switch(action) {
                case 'community':
                    SearchComponent.selectCommunity(communityId);
                    break;
                case 'address':
                    SearchComponent.selectAddress(communityId, addressId);
                    break;
                case 'resident':
                    SearchComponent.selectResident(communityId, addressId, personId);
                    break;
                case 'code':
                    SearchComponent.selectCode(communityId, addressId, personId, codeId);
                    break;
            }
        });
    },
    
    async performSearch(query) {
        if (!query || query.length < 2) {
            this.searchResults.classList.add('hidden');
            return;
        }
        
        // Show loading state
        this.searchResults.innerHTML = '<div class="search-loading"><div class="spinner"></div> Searching...</div>';
        this.searchResults.classList.remove('hidden');
        
        // Get active filters
        const filters = this.getActiveFilters();
        
        // Perform search
        const results = await this.searchData(query, filters);
        
        // Display results
        this.displayResults(results);
    },
    
    getActiveFilters() {
        const searchTypes = Array.from(document.querySelectorAll('input[name="searchType"]:checked'))
            .map(cb => cb.value);
        
        return {
            types: searchTypes
        };
    },
    
    async searchData(query, filters) {
        const results = {
            communities: [],
            addresses: [],
            residents: [],
            codes: []
        };
        
        const queryLower = query.toLowerCase();
        
        // Search communities
        if (filters.types.includes('communities')) {
            communities.forEach(community => {
                if (community.name.toLowerCase().includes(queryLower)) {
                    results.communities.push({
                        type: 'community',
                        name: community.name,
                        id: community.id,
                        addressCount: community.addresses ? community.addresses.length : 0
                    });
                }
            });
        }
        
        // Search addresses and residents
        communities.forEach(community => {
            if (community.addresses) {
                community.addresses.forEach(address => {
                    // Search addresses
                    if (filters.types.includes('addresses') && 
                        address.street.toLowerCase().includes(queryLower)) {
                        results.addresses.push({
                            type: 'address',
                            street: address.street,
                            community: community.name,
                            communityId: community.id,
                            addressId: address.id,
                            residentCount: address.people ? address.people.length : 0
                        });
                    }
                    
                    // Search residents and codes
                    if (address.people) {
                        address.people.forEach(person => {
                            // Search residents
                            if (filters.types.includes('residents') && 
                                person.username.toLowerCase().includes(queryLower)) {
                                results.residents.push({
                                    type: 'resident',
                                    username: person.username,
                                    playerId: person.playerId,
                                    address: address.street,
                                    community: community.name,
                                    communityId: community.id,
                                    addressId: address.id,
                                    personId: person.id
                                });
                            }
                            
                            // Search codes
                            if (filters.types.includes('codes') && person.codes) {
                                person.codes.forEach(code => {
                                    const isExpired = new Date(code.expiresAt) < new Date();
                                    
                                    if (code.code.toLowerCase().includes(queryLower) || 
                                        code.description.toLowerCase().includes(queryLower)) {
                                        results.codes.push({
                                            type: 'code',
                                            code: code.code,
                                            description: code.description,
                                            expired: isExpired,
                                            owner: person.username,
                                            address: address.street,
                                            community: community.name,
                                            communityId: community.id,
                                            addressId: address.id,
                                            personId: person.id,
                                            codeId: code.id
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
        
        return results;
    },
    
    displayResults(results) {
        const totalResults = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
        
        if (totalResults === 0) {
            this.searchResults.innerHTML = '<div class="search-no-results">No results found</div>';
            return;
        }
        
        let html = `<div class="search-results-header">${totalResults} results found</div>`;
        
        // Display communities
        if (results.communities.length > 0) {
            html += '<div class="search-section"><h4>Communities</h4>';
            results.communities.forEach(item => {
                html += `
                    <div class="search-result-item hover-lift" data-action="community" data-community-id="${item.id}">
                        <svg class="result-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z"/>
                        </svg>
                        <div class="result-content">
                            <div class="result-title">${item.name}</div>
                            <div class="result-subtitle">${item.addressCount} addresses</div>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        }
        
        // Display addresses
        if (results.addresses.length > 0) {
            html += '<div class="search-section"><h4>Addresses</h4>';
            results.addresses.forEach(item => {
                html += `
                    <div class="search-result-item hover-lift" data-action="address" data-community-id="${item.communityId}" data-address-id="${item.addressId}">
                        <svg class="result-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M5.05 4.05a7 7 0 119.9 9.9L10 18.9l-4.95-4.95a7 7 0 010-9.9zM10 11a2 2 0 100-4 2 2 0 000 4z" clip-rule="evenodd"/>
                        </svg>
                        <div class="result-content">
                            <div class="result-title">${item.street}</div>
                            <div class="result-subtitle">${item.community} • ${item.residentCount} residents</div>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        }
        
        // Display residents
        if (results.residents.length > 0) {
            html += '<div class="search-section"><h4>Residents</h4>';
            results.residents.forEach(item => {
                html += `
                    <div class="search-result-item hover-lift" data-action="resident" data-community-id="${item.communityId}" data-address-id="${item.addressId}" data-person-id="${item.personId}">
                        <svg class="result-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"/>
                        </svg>
                        <div class="result-content">
                            <div class="result-title">${item.username}</div>
                            <div class="result-subtitle">${item.address} • ${item.community}</div>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        }
        
        // Display codes
        if (results.codes.length > 0) {
            html += '<div class="search-section"><h4>Access Codes</h4>';
            results.codes.forEach(item => {
                html += `
                    <div class="search-result-item hover-lift ${item.expired ? 'expired' : ''}" 
                         data-action="code" data-community-id="${item.communityId}" data-address-id="${item.addressId}" data-person-id="${item.personId}" data-code-id="${item.codeId}">
                        <svg class="result-icon" width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M18 8a6 6 0 01-7.743 5.743L10 14l-1 1-1 1H6v2H2v-4l4.257-4.257A6 6 0 1118 8zm-6-4a1 1 0 100 2 2 2 0 012 2 1 1 0 102 0 4 4 0 00-4-4z" clip-rule="evenodd"/>
                        </svg>
                        <div class="result-content">
                            <div class="result-title">${item.code} - ${item.description}</div>
                            <div class="result-subtitle">${item.owner} • ${item.community} ${item.expired ? '• EXPIRED' : ''}</div>
                        </div>
                    </div>
                `;
            });
            html += '</div>';
        }
        
        this.searchResults.innerHTML = html;
    },
    
    selectCommunity(communityId) {
        const community = communities.find(c => c.id === communityId);
        if (community) {
            window.selectCommunity(communityId);
            this.closeSearch();
            // Highlight the community after navigation
            setTimeout(() => {
                // Make all address items immediately visible
                document.querySelectorAll('.address-item.animate-in').forEach(item => {
                    item.classList.remove('animate-in');
                    item.style.opacity = '1';
                    item.style.transform = 'none';
                });
                
                const communityElement = document.querySelector('.community-info');
                if (communityElement) {
                    communityElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    communityElement.classList.add('highlight-flash');
                    setTimeout(() => communityElement.classList.remove('highlight-flash'), 2000);
                }
            }, 500);
        }
    },
    
    selectAddress(communityId, addressId) {
        const community = communities.find(c => c.id === communityId);
        if (community) {
            window.selectCommunity(communityId);
            // Expand and highlight the address
            setTimeout(() => {
                // Make all address items immediately visible
                document.querySelectorAll('.address-item.animate-in').forEach(item => {
                    item.classList.remove('animate-in');
                    item.style.opacity = '1';
                    item.style.transform = 'none';
                });
                
                const addressElement = document.querySelector(`.address-item[data-address-id="${addressId}"] .address-text`);
                const addressContainer = document.querySelector(`.address-item[data-address-id="${addressId}"]`);
                if (addressElement) {
                    addressElement.click();
                    if (addressContainer) {
                        // Remove animate-in class to make it immediately visible
                        addressContainer.classList.remove('animate-in');
                        addressContainer.style.opacity = '1';
                        addressContainer.style.transform = 'none';
                        
                        addressContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        addressContainer.classList.add('highlight-flash');
                        setTimeout(() => addressContainer.classList.remove('highlight-flash'), 2000);
                    }
                }
            }, 500);
        }
        this.closeSearch();
    },
    
    selectResident(communityId, addressId, personId) {
        this.selectAddress(communityId, addressId);
        // Highlight resident after address expands
        setTimeout(() => {
            const personElement = document.querySelector(`.user-id-list li[data-person-id="${personId}"]`);
            
            if (personElement) {
                personElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                personElement.classList.add('highlight-flash');
                setTimeout(() => personElement.classList.remove('highlight-flash'), 2000);
            } else {
                // Try once more after a delay
                setTimeout(() => {
                    const retryElement = document.querySelector(`.user-id-list li[data-person-id="${personId}"]`);
                    if (retryElement) {
                        retryElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        retryElement.classList.add('highlight-flash');
                        setTimeout(() => retryElement.classList.remove('highlight-flash'), 2000);
                    }
                }, 500);
            }
        }, 1000);
    },
    
    selectCode(communityId, addressId, personId, codeId) {
        this.selectResident(communityId, addressId, personId);
        // Highlight code after navigation
        setTimeout(() => {
            const codeElement = document.querySelector(`.code-list li[data-code-id="${codeId}"]`);
            if (codeElement) {
                codeElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
                codeElement.classList.add('highlight-flash');
                setTimeout(() => codeElement.classList.remove('highlight-flash'), 2000);
            }
        }, 800);
    },
    
    toggleSearch() {
        const searchContainer = document.querySelector('.search-container');
        if (searchContainer) {
            searchContainer.classList.toggle('hidden');
            if (!searchContainer.classList.contains('hidden')) {
                this.searchInput.focus();
            }
        }
    },
    
    closeSearch() {
        const searchContainer = document.querySelector('.search-container');
        if (searchContainer) {
            searchContainer.classList.add('hidden');
            this.searchInput.value = '';
            this.searchResults.classList.add('hidden');
        }
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    SearchComponent.init();
});

// Export for global access
window.SearchComponent = SearchComponent;