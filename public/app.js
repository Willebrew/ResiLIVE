/**
 * Array to store community objects.
 * @type {Array<Object>}
 */
let communities = [];

/**
 * Currently selected community object.
 * @type {Object|null}
 */
let selectedCommunity = null;

/**
 * Currently selected address object.
 * @type {Object|null}
 */
let selectedAddress = null;

/**
 * Flag indicating if the user is an admin.
 * @type {boolean}
 */
let isAdmin = false;

/**
 * Array to store user objects.
 * @type {*[]}
 */
let users = [];

/**
 * Variable to store the CSRF token.
 * @type {string}
 */
let csrfToken;

/**
 * Variable to store the current user ID.
 * @type {null}
 */
let currentUserId = null;

/**
 * Variable to store the current username.
 * @type {null}
 */
let currentUsername = null;
window.codeExpiryFlatpickr = null; // For Flatpickr instance

/**
 * Event listener for the DOMContentLoaded event to fetch the CSRF token when the document is fully loaded.
 */
document.addEventListener('DOMContentLoaded', async () => {
    await fetchCsrfToken();
    checkLoginStatus();
    // Set up event listeners for UI elements.
    setupUIEventListeners();
});

/**
 * Fetches the CSRF token from the server and stores it in the csrfToken variable.
 */
async function fetchCsrfToken() {
    try {
        const response = await fetch('/csrf-token');
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        const data = await response.json();
        csrfToken = data.csrfToken;
        const csrfInput = document.getElementById('csrfToken');
        if (csrfInput) {
            csrfInput.value = csrfToken;
        }
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
    }
}

/**
 * Updates the view of the community action menu (checkbox and Trigger Relay button visibility).
 */
function updateCommunityMenuView() {
    const communityMenuBtn = document.getElementById('communityMenuBtn');
    const communityActionMenu = document.getElementById('communityActionMenu'); 
    const communityOpenGateMenuBtnContainer = document.getElementById('communityOpenGateMenuBtnContainer'); 

    // Ensure the old menu item for "Trigger Relay" is definitely hidden
    if (communityOpenGateMenuBtnContainer) {
        communityOpenGateMenuBtnContainer.classList.add('hidden');
    }

    if (!selectedCommunity) {
        if (communityMenuBtn) communityMenuBtn.classList.add('hidden');
        if (communityActionMenu) {
            communityActionMenu.classList.add('hidden');
            communityActionMenu.classList.remove('community-action-menu-positioned');
        }
        // Ensure the gate button container is also hidden if no community
        if (communityOpenGateMenuBtnContainer) communityOpenGateMenuBtnContainer.classList.add('hidden'); 
        return;
    }

    // If a community is selected, the menu button should be visible
    if (communityMenuBtn) communityMenuBtn.classList.remove('hidden');

    const remoteGateControlToggle = document.getElementById('remoteGateControlToggle');
    const remoteControlBtn = document.getElementById('remoteControlBtn');
    
    if (remoteGateControlToggle) {
        remoteGateControlToggle.checked = !!selectedCommunity.remoteGateControlEnabled;
    }
    
    // Update the button's active state
    if (remoteControlBtn) {
        if (selectedCommunity.remoteGateControlEnabled) {
            remoteControlBtn.classList.add('active');
        } else {
            remoteControlBtn.classList.remove('active');
        }
    }

    // if (communityOpenGateMenuBtnContainer) {
    //     // Use toggle for cleaner add/remove based on condition
    //     communityOpenGateMenuBtnContainer.classList.toggle('hidden', !selectedCommunity.remoteGateControlEnabled);
    // }

    const externalOpenGateBtnContainer = document.getElementById('externalOpenGateBtnContainer');
    if (externalOpenGateBtnContainer) {
        externalOpenGateBtnContainer.innerHTML = ''; // Clear any previous button
        if (selectedCommunity && selectedCommunity.remoteGateControlEnabled) {
            const openGateBtn = document.createElement('button');
            openGateBtn.textContent = 'Trigger Relay';
            openGateBtn.className = 'community-open-gate-btn'; // Use existing class for styling
            openGateBtn.addEventListener('click', () => {
                openCommunityGate(selectedCommunity.name);
                // Optionally, hide the main community menu after clicking
                // const communityActionMenu = document.getElementById('communityActionMenu'); // Already declared above
                if (communityActionMenu) {
                    communityActionMenu.classList.add('hidden');
                    communityActionMenu.classList.remove('community-action-menu-positioned');
                }
            });
            externalOpenGateBtnContainer.appendChild(openGateBtn);
        }
    }
}

/**
 * Updates the username displayed in the UI (for the user menu).
 * Also sets the user circle initial and full name.
 * @param {string} username - The username to display.
 */
function updateUserName(username) {
    currentUsername = username || 'Guest';
    const userCircle = document.getElementById('userCircle');
    if (userCircle) {
        userCircle.textContent = currentUsername.charAt(0).toUpperCase() || '?';
    }
    const userFullName = document.getElementById('userFullName');
    if (userFullName) {
        userFullName.textContent = 'Welcome, ' + currentUsername;
    }
}

/**
 * Checks the login status of the user and updates the UI accordingly.
 */
async function checkLoginStatus() {
    try {
        const response = await fetch('/api/check-auth');
        if (response.ok) {
            const data = await response.json();
            currentUserId = data.userId;
            updateUserName(data.username);
            isAdmin = data.role === 'admin' || data.role === 'superuser';
            
            // Set authentication status for ThemeManager
            if (typeof ThemeManager !== 'undefined') {
                ThemeManager.setAuthenticated(true);
                
                // Apply theme from server
                const serverTheme = data.theme || 'dark';
                ThemeManager.applyInitialTheme(serverTheme);
            }
            
            const allowedUsersManagement = document.getElementById('allowedUsersManagement');
            if (isAdmin) {
                if (allowedUsersManagement) allowedUsersManagement.classList.remove('hidden'); // CSP Refactor
            } else {
                if (allowedUsersManagement) {
                    allowedUsersManagement.remove();
                }
                const addCommunityBtn = document.getElementById('12');
                const showUsersBtn = document.getElementById('showUsersBtn');
                if (addCommunityBtn) addCommunityBtn.remove();
                if (showUsersBtn) showUsersBtn.remove();
            }
            fetchData();
        } else {
            // Not authenticated - apply theme from localStorage before redirect
            if (typeof ThemeManager !== 'undefined') {
                const localTheme = localStorage.getItem('resilive-theme') || 'dark';
                ThemeManager.applyInitialTheme(localTheme);
            }
            updateUserName('Guest');
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('Error checking login status:', error);
        updateUserName('Logged Out');
    }
}

/**
 * Sets up event listeners for UI elements including hamburger, user menu, Change Password, and Logout buttons.
 */
function setupUIEventListeners() {
    // Hamburger button for sidebar toggle on mobile
    const hamburgerBtn = document.getElementById('hamburgerBtn');
    const sidebar = document.querySelector('.sidebar');
    
    if (hamburgerBtn && sidebar) {
        hamburgerBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            sidebar.classList.toggle('sidebar-open');
        });
        
        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', (e) => {
            // Only handle clicks outside sidebar on mobile
            if (window.innerWidth <= 900) {
                if (!sidebar.contains(e.target) && !hamburgerBtn.contains(e.target) && sidebar.classList.contains('sidebar-open')) {
                    sidebar.classList.remove('sidebar-open');
                }
            }
        });
    }

    // User menu toggle on user circle click
    const userCircle = document.getElementById('userCircle');
    const userMenu = document.getElementById('userMenu');
    const settingsDropdown = document.getElementById('settingsDropdown');
    
    if (userCircle && userMenu) {
        userCircle.addEventListener('click', (e) => {
            e.stopPropagation();
            userMenu.classList.toggle('show');
            // Close settings dropdown when opening user menu
            if (settingsDropdown) {
                settingsDropdown.classList.add('hidden');
            }
        });
        document.addEventListener('click', (evt) => {
            if (!userMenu.contains(evt.target) && evt.target !== userCircle) {
                userMenu.classList.remove('show');
            }
        });
    }

    // Hook up Change Password button
    const changePasswordBtn = document.getElementById('changePasswordBtn');
    if (changePasswordBtn) {
        changePasswordBtn.addEventListener('click', changePassword);
    }

    // Hook up Logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Hook up Show Logs and Show Users buttons
    const showLogsBtn = document.getElementById('showLogsBtn');
    if (showLogsBtn) {
        showLogsBtn.addEventListener('click', () => {
            showLogs(selectedCommunity ? selectedCommunity.name : '');
        });
    }
    const showUsersBtn = document.getElementById('showUsersBtn');
    if (showUsersBtn) {
        showUsersBtn.addEventListener('click', showUsersPopup);
    }

    // Hook up Add Address button
    const addAddressBtn = document.getElementById('addAddressBtn');
    if (addAddressBtn) {
        addAddressBtn.addEventListener('click', addAddress);
    }

    // Community Action Menu Logic
    const communityMenuBtn = document.getElementById('communityMenuBtn');
    const communityActionMenu = document.getElementById('communityActionMenu');

    if (communityMenuBtn && communityActionMenu) {
        communityMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation(); 
            const isActuallyHidden = communityActionMenu.classList.contains('hidden');
            if (isActuallyHidden) {
                // Dynamic positioning
                const btnRect = communityMenuBtn.getBoundingClientRect();
                communityActionMenu.style.left = btnRect.left + 'px'; 
                communityActionMenu.style.top = (btnRect.top + 2) + 'px';
                // Show immediately
                communityActionMenu.classList.remove('hidden');
                communityActionMenu.classList.add('community-action-menu-positioned');
            } else {
                // Hide immediately
                communityActionMenu.classList.add('hidden');
                communityActionMenu.classList.remove('community-action-menu-positioned');
            }
        });

        // Hide menu when clicking outside
        document.addEventListener('click', (evt) => {
            // Check if the menu is currently visible (not hidden)
            if (!communityActionMenu.classList.contains('hidden') && 
                !communityActionMenu.contains(evt.target) && 
                evt.target !== communityMenuBtn) {
                // Hide immediately
                communityActionMenu.classList.add('hidden');
                communityActionMenu.classList.remove('community-action-menu-positioned');
            }
        });
    }

    // Use event delegation for community menu items
    if (communityActionMenu) {
        communityActionMenu.addEventListener('click', async (e) => {
            const button = e.target.closest('button');
            if (!button) return;
            
            // Handle rename community
            if (button.closest('#renameCommunityOption')) {
                e.preventDefault();
                e.stopPropagation();
                
                if (!selectedCommunity) return;
                
                // Hide the community menu
                communityActionMenu.classList.add('hidden');
                communityActionMenu.classList.remove('community-action-menu-positioned');
                
                // Show the rename popup
                const renameCommunityModal = document.getElementById('renameCommunityModal');
                const renameCommunityInput = document.getElementById('renameCommunityInput');
                
                if (renameCommunityModal && renameCommunityInput) {
                    renameCommunityInput.value = selectedCommunity.name;
                    renameCommunityModal.classList.remove('hidden');
                    renameCommunityModal.classList.add('popup-visible');
                    renameCommunityInput.focus();
                    renameCommunityInput.select();
                }
            }
        });
    }
    
    // Setup rename community popup handlers
    const setupRenameCommunityHandlers = () => {
        const renameCommunityModal = document.getElementById('renameCommunityModal');
        const renameCommunityInput = document.getElementById('renameCommunityInput');
        const confirmRenameCommunityBtn = document.getElementById('confirmRenameCommunityBtn');
        const cancelRenameCommunityBtn = document.getElementById('cancelRenameCommunityBtn');
        const closeRenameCommunityBtn = document.getElementById('closeRenameCommunityBtn');
        
        const closeModal = () => {
            if (renameCommunityModal) {
                renameCommunityModal.classList.add('hidden');
                renameCommunityModal.classList.remove('popup-visible');
            }
        };
        
        const handleRename = async () => {
            if (!selectedCommunity || !renameCommunityInput) return;
            
            const newName = renameCommunityInput.value.trim();
            if (newName && newName !== '') {
                const oldName = selectedCommunity.name;
                
                // Close modal
                closeModal();
                
                // Optimistically update UI
                selectedCommunity.name = newName;
                document.getElementById('communityName').textContent = selectedCommunity.name;
                const communityInArray = communities.find(c => c.id === selectedCommunity.id);
                if (communityInArray) {
                    communityInArray.name = selectedCommunity.name;
                }
                renderCommunities();

                try {
                    const response = await fetch(`/api/communities/${selectedCommunity.id}/name`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrfToken,
                        },
                        body: JSON.stringify({ name: selectedCommunity.name }),
                    });
                    if (!response.ok) {
                        // Revert on error
                        selectedCommunity.name = oldName;
                        document.getElementById('communityName').textContent = oldName;
                        if (communityInArray) communityInArray.name = oldName;
                        renderCommunities();
                        const errorData = await response.json();
                        alert(`Error renaming community: ${errorData.error || 'Unknown error'}`);
                    }
                } catch (error) {
                    // Revert on error
                    selectedCommunity.name = oldName;
                    document.getElementById('communityName').textContent = oldName;
                    if (communityInArray) communityInArray.name = oldName;
                    renderCommunities();
                    alert(`Error renaming community: ${error.message}`);
                }
            } else {
                alert('Invalid community name. Ensure it is not empty.');
            }
        };
        
        // Event listeners
        if (confirmRenameCommunityBtn) {
            confirmRenameCommunityBtn.addEventListener('click', handleRename);
        }
        
        if (cancelRenameCommunityBtn) {
            cancelRenameCommunityBtn.addEventListener('click', closeModal);
        }
        
        if (closeRenameCommunityBtn) {
            closeRenameCommunityBtn.addEventListener('click', closeModal);
        }
        
        // Enter key support
        if (renameCommunityInput) {
            renameCommunityInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    handleRename();
                }
            });
        }
    };
    
    // Initialize rename handlers
    setupRenameCommunityHandlers();

    // "Remote Gate Control" button
    const remoteControlBtn = document.getElementById('remoteControlBtn');
    if (remoteControlBtn) {
        remoteControlBtn.addEventListener('click', async () => {
            if (!selectedCommunity) return;
            
            // Toggle the state
            const remoteGateControlToggle = document.getElementById('remoteGateControlToggle');
            if (remoteGateControlToggle) {
                remoteGateControlToggle.checked = !remoteGateControlToggle.checked;
                remoteGateControlToggle.dispatchEvent(new Event('change'));
            }
        });
    }
    
    // "Remote Gate Control" toggle (hidden checkbox)
    const remoteGateControlToggle = document.getElementById('remoteGateControlToggle');
    if (remoteGateControlToggle) {
        remoteGateControlToggle.addEventListener('change', async () => {
            if (!selectedCommunity) return;
            const isEnabled = remoteGateControlToggle.checked;
            selectedCommunity.remoteGateControlEnabled = isEnabled;
            updateCommunityMenuView(); // Update UI (shows/hides Trigger Relay button in menu)

            try {
                const response = await fetch(`/api/communities/${selectedCommunity.id}/remote-gate-control`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken,
                    },
                    body: JSON.stringify({ enabled: isEnabled }),
                });
                if (!response.ok) {
                    // Revert on error
                    selectedCommunity.remoteGateControlEnabled = !isEnabled;
                    remoteGateControlToggle.checked = !isEnabled;
                    updateCommunityMenuView();
                    const errorData = await response.json();
                    alert(`Error updating remote gate control: ${errorData.error || 'Unknown error'}`);
                }
            } catch (error) {
                // Revert on error
                selectedCommunity.remoteGateControlEnabled = !isEnabled;
                remoteGateControlToggle.checked = !isEnabled;
                updateCommunityMenuView();
                alert(`Error updating remote gate control: ${error.message}`);
            }
        });
    }

    // "Trigger Relay" button in menu
    // const communityOpenGateMenuBtnContainer = document.getElementById('communityOpenGateMenuBtnContainer');
    // if (communityOpenGateMenuBtnContainer && communityOpenGateMenuBtnContainer.firstElementChild) {
    //     communityOpenGateMenuBtnContainer.firstElementChild.addEventListener('click', () => {
    //         if (selectedCommunity && selectedCommunity.remoteGateControlEnabled) {
    //             openCommunityGate(selectedCommunity.name);
    //             if (communityActionMenu) { // CSP Refactor
    //                 communityActionMenu.classList.add('hidden');
    //                 communityActionMenu.classList.remove('community-action-menu-positioned');
    //             }
    //         } else if (selectedCommunity) {
    //             // This case should ideally not be hit if the button is hidden when not enabled, but as a fallback:
    //             alert('Remote gate control is not enabled for this community.');
    //         }
    //     });
    // }

    // Refactored popup button event listeners
    const closeLogPopupBtn = document.getElementById('closeLogPopupBtn');
    if (closeLogPopupBtn) {
        closeLogPopupBtn.addEventListener('click', closeLogPopup);
    }

    const addUserBtn = document.getElementById('addUserBtn');
    if (addUserBtn) {
        addUserBtn.addEventListener('click', addUser);
    }

    const closeUsersPopupBtn = document.getElementById('closeUsersPopupBtn');
    if (closeUsersPopupBtn) {
        closeUsersPopupBtn.addEventListener('click', closeUsersPopup);
    }

    // Refactored sidebar button event listeners
    const addCommunityBtn = document.getElementById('12'); // This is the button with id '12'
    if (addCommunityBtn) {
        addCommunityBtn.addEventListener('click', addCommunity);
    }

    // New access management button
    const manageUsersBtn = document.getElementById('manageUsersBtn');
    if (manageUsersBtn) {
        manageUsersBtn.addEventListener('click', openAccessManagementPopup);
    }

    // Access management popup events
    const closeAccessPopupBtn = document.getElementById('closeAccessPopupBtn');
    if (closeAccessPopupBtn) {
        closeAccessPopupBtn.addEventListener('click', closeAccessManagementPopup);
    }

    const grantAccessBtn = document.getElementById('grantAccessBtn');
    if (grantAccessBtn) {
        grantAccessBtn.addEventListener('click', grantSelectedUsersAccess);
    }

    const userSearchInput = document.getElementById('userSearchInput');
    if (userSearchInput) {
        userSearchInput.addEventListener('input', debounce(searchUsers, 300));
        userSearchInput.addEventListener('focus', showUserSearchResults);
        userSearchInput.addEventListener('blur', () => {
            setTimeout(hideUserSearchResults, 200);
        });
    }

    // Legacy support for old buttons (can be removed later)
    const updateAllowedUsersBtn = document.getElementById('updateAllowedUsersBtn');
    if (updateAllowedUsersBtn) {
        updateAllowedUsersBtn.addEventListener('click', updateAllowedUsers);
    }

    const removeSelectedUsersBtn = document.getElementById('removeSelectedUsersBtn');
    if (removeSelectedUsersBtn) {
        removeSelectedUsersBtn.addEventListener('click', removeSelectedUsers);
    }

    // Event listener for "Save Code" button in the Add Code Modal
    const saveCodeBtn = document.getElementById('saveCodeBtn');
    if (saveCodeBtn) {
        saveCodeBtn.addEventListener('click', async () => {
            const addCodeModal = document.getElementById('addCodeModal');
            const addressId = addCodeModal.dataset.addressId; // Retrieve stored addressId
            const description = document.getElementById('codeDescriptionInput').value;
            const codeValue = document.getElementById('codeValueInput').value; // Renamed to avoid conflict
            const expiryDateInstance = window.codeExpiryFlatpickr; // Get the flatpickr instance

            // Determine expiresAt value; if no date is selected, leave it undefined (no expiry)
            let expiresAt;
            if (expiryDateInstance && expiryDateInstance.selectedDates.length > 0) {
                expiresAt = expiryDateInstance.selectedDates[0].toISOString();
            }

            if (description && codeValue && addressId) {
                try {
                    // Ensure selectedCommunity and selectedCommunity.id are valid
                    if (!selectedCommunity || !selectedCommunity.id) {
                        alert('Error: No community selected. Cannot add code.');
                        console.error('Error: selectedCommunity or selectedCommunity.id is not set.');
                        return;
                    }
                    const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/codes`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': csrfToken
                        },
                        body: JSON.stringify({ description, code: codeValue, expiresAt }),
                        credentials: 'include'
                    });
                    if (response.ok) {
                        const newCode = await response.json();
                        const address = selectedCommunity.addresses.find(a => a.id === addressId);
                        if (address) {
                            if (!address.codes) {
                                address.codes = [];
                            }
                            address.codes.push(newCode);
                            renderCodes(address); // Re-render codes for that specific address
                        }
                        closeAddCodeModal(); // Use helper function to close and clean up
                    } else {
                        const errorData = await response.json();
                        console.error('Failed to add code:', errorData.error || response.statusText);
                        alert('Failed to add code: ' + (errorData.error || response.statusText));
                    }
                } catch (error) {
                    console.error('Error adding code:', error);
                    alert('An error occurred while adding the code.');
                }
            } else {
                alert('Please fill in the required fields: description and code.');
            }
        });
    }

    // Event listener for "Cancel" button in the Add Code Modal
    const cancelAddCodeBtn = document.getElementById('cancelAddCodeBtn');
    if (cancelAddCodeBtn) {
        cancelAddCodeBtn.addEventListener('click', closeAddCodeModal);
    }
    
    // Event listener for close icon button in the Add Code Modal
    const closeAddCodeBtn = document.getElementById('closeAddCodeBtn');
    if (closeAddCodeBtn) {
        closeAddCodeBtn.addEventListener('click', closeAddCodeModal);
    }
    
    // Event listeners for Add User ID Modal
    const cancelAddUserIdBtn = document.getElementById('cancelAddUserIdBtn');
    if (cancelAddUserIdBtn) {
        cancelAddUserIdBtn.addEventListener('click', closeAddUserIdModal);
    }
    
    const closeAddUserIdBtn = document.getElementById('closeAddUserIdBtn');
    if (closeAddUserIdBtn) {
        closeAddUserIdBtn.addEventListener('click', closeAddUserIdModal);
    }
    
    const saveUserIdBtn = document.getElementById('saveUserIdBtn');
    if (saveUserIdBtn) {
        saveUserIdBtn.addEventListener('click', saveUserIdFromModal);
    }
    
    // Event listeners for Add Address Modal
    const cancelAddAddressBtn = document.getElementById('cancelAddAddressBtn');
    if (cancelAddAddressBtn) {
        cancelAddAddressBtn.addEventListener('click', closeAddAddressModal);
    }
    
    const closeAddAddressBtn = document.getElementById('closeAddAddressBtn');
    if (closeAddAddressBtn) {
        closeAddAddressBtn.addEventListener('click', closeAddAddressModal);
    }
    
    const saveAddressBtn = document.getElementById('saveAddressBtn');
    if (saveAddressBtn) {
        saveAddressBtn.addEventListener('click', saveAddressFromModal);
    }
    
    // Toggle button for relay control
    const addressHasGateBtn = document.getElementById('addressHasGateBtn');
    if (addressHasGateBtn) {
        addressHasGateBtn.addEventListener('click', function() {
            const hasGateInput = document.getElementById('addressHasGateInput');
            const isActive = this.classList.contains('active');
            
            if (isActive) {
                this.classList.remove('active');
                hasGateInput.value = 'false';
            } else {
                this.classList.add('active');
                hasGateInput.value = 'true';
            }
        });
    }
    
    // Event listeners for Add Community Modal
    const cancelAddCommunityBtn = document.getElementById('cancelAddCommunityBtn');
    if (cancelAddCommunityBtn) {
        cancelAddCommunityBtn.addEventListener('click', closeAddCommunityModal);
    }
    
    const closeAddCommunityBtn = document.getElementById('closeAddCommunityBtn');
    if (closeAddCommunityBtn) {
        closeAddCommunityBtn.addEventListener('click', closeAddCommunityModal);
    }
    
    const saveCommunityBtn = document.getElementById('saveCommunityBtn');
    if (saveCommunityBtn) {
        saveCommunityBtn.addEventListener('click', saveCommunityFromModal);
    }
}

/**
 * Fetches users from the server and updates the UI.
 */
async function fetchUsers() {
    try {
        const response = await fetch('/api/users');
        if (response.ok) {
            users = await response.json();
            renderUsers();
        } else {
            console.error('Failed to fetch users');
        }
    } catch (error) {
        console.error('Error fetching users:', error);
    }
}

/**
 * Toggles a user's role between admin and user.
 * @param {string} userId - The ID of the user to toggle role.
 */
async function toggleUserRole(userId) {
    try {
        const response = await fetch(`/api/users/${userId}/role`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });
        if (response.ok) {
            const data = await response.json();
            const userIndex = users.findIndex(u => u.id === userId);
            if (userIndex !== -1) {
                users[userIndex].role = data.newRole;
                if (data.newRole === 'admin') {
                    const username = users[userIndex].username;
                    communities.forEach(community => {
                        community.allowedUsers = community.allowedUsers.filter(
                            allowedUser => allowedUser !== username
                        );
                    });
                    if (selectedCommunity) {
                        renderAllowedUsers();
                    }
                }
                renderUsers();
            }
        } else {
            const errorData = await response.json();
            alert(errorData.error || 'Failed to update user role');
        }
    } catch (error) {
        console.error('Error toggling user role:', error);
        alert('An error occurred while updating user role');
    }
}

/**
 * Renders the list of users in the UI.
 */
function renderUsers() {
    const usersList = document.getElementById('usersList');
    usersList.innerHTML = ''; // Clear existing list items
    users.forEach(user => {
        if (user.id !== currentUserId && user.role !== 'superuser') {
            const userElement = document.createElement('div');
            userElement.className = 'user-item';

            const usernameSpan = document.createElement('span');
            usernameSpan.textContent = user.username;
            userElement.appendChild(usernameSpan);

            const controlsDiv = document.createElement('div');
            controlsDiv.className = 'user-controls';

            const roleButton = document.createElement('button');
            roleButton.className = `role-btn ${user.role === 'admin' ? 'admin' : 'user'}`;
            roleButton.title = user.role === 'admin' ? 'Remove admin' : 'Make admin';
            roleButton.innerHTML = user.role === 'admin' ? 
                '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd"/></svg>' : 
                '<svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"/></svg>';
            roleButton.addEventListener('click', () => toggleUserRole(user.id));
            controlsDiv.appendChild(roleButton);

            const removeUserButton = document.createElement('button');
            removeUserButton.className = 'remove-btn';
            removeUserButton.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
            removeUserButton.title = 'Remove user';
            removeUserButton.addEventListener('click', () => removeUser(user.id));
            controlsDiv.appendChild(removeUserButton);

            userElement.appendChild(controlsDiv);
            usersList.appendChild(userElement);
        }
    });
}

/**
 * Adds a new user by sending a POST request to the server.
 */
async function addUser() {
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const addButton = document.getElementById('addUserBtn');
    
    if (username && password) {
        try {
            // Show loading state on button
            if (window.AnimationUtils) {
                AnimationUtils.setButtonLoading(addButton, true, 'Add User');
            }
            
            const response = await fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });
            if (response.ok) {
                fetchUsers();
                document.getElementById('newUsername').value = '';
                document.getElementById('newPassword').value = '';
                alert('User added successfully');
            } else {
                const errorData = await response.json();
                console.error('Failed to add user:', errorData.error);
                alert(errorData.error || 'Failed to add user. Please try again.');
            }
        } catch (error) {
            console.error('Error adding user:', error);
            alert('An error occurred while adding the user. Please try again.');
        } finally {
            // Reset button loading state
            if (window.AnimationUtils) {
                AnimationUtils.setButtonLoading(addButton, false, 'Add User');
            }
        }
    } else {
        alert('Please enter both username and password.');
    }
}

/**
 * Removes a user by sending a DELETE request to the server.
 * @param {string} userId - The ID of the user to be removed.
 */
async function removeUser(userId) {
    if (confirm('Are you sure you want to remove this user?')) {
        try {
            const response = await fetch(`/api/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                fetchUsers();
                alert('User removed successfully');
                if (data.updatedCommunities && Array.isArray(data.updatedCommunities)) {
                    data.updatedCommunities.forEach(updatedCommunity => {
                        const communityIndex = communities.findIndex(c => c.id === updatedCommunity.id);
                        if (communityIndex !== -1) {
                            communities[communityIndex].allowedUsers = updatedCommunity.allowedUsers;
                        }
                    });
                    if (selectedCommunity && data.updatedCommunities.some(c => c.id === selectedCommunity.id)) {
                        renderAllowedUsers();
                    }
                }
            } else {
                const errorData = await response.json();
                console.error('Failed to remove user:', errorData.error);
                alert(errorData.error || 'Failed to remove user. Please try again.');
            }
        } catch (error) {
            console.error('Error removing user:', error);
            alert('An error occurred while removing the user. Please try again.');
        }
    }
}

/**
 * Fetches community data from the server and updates the UI.
 */
async function fetchData() {
    try {
        // Show skeleton loading for community list
        if (window.AnimationUtils) {
            AnimationUtils.showSkeletonLoading('communityList', 3);
        }
        
        const response = await fetch('/api/communities');
        if (response.status === 401) {
            window.location.href = '/login.html';
            return;
        }
        communities = await response.json();
        renderCommunities();
        const addAddressBtn = document.getElementById('addAddressBtn');
        const addressesHeader = document.querySelector('main h3'); 
        if (communities.length > 0) {
            if (addAddressBtn) addAddressBtn.classList.remove('hidden'); // CSP Refactor
            if (addressesHeader) addressesHeader.classList.remove('hidden'); // CSP Refactor
            selectCommunity(communities[0].id);
        } else {
            if (addAddressBtn) addAddressBtn.classList.add('hidden'); // CSP Refactor
            if (addressesHeader) addressesHeader.classList.add('hidden'); // CSP Refactor
            document.getElementById('communityName').textContent = 'Please create a Community';
            updateCommunityMenuView(); // Ensure menu is hidden if no communities
        }
        if (communities.length >= 8) {
            const addButton = document.getElementById('12');
            if (addButton) {
                addButton.remove();
            }
        }
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

/**
 * Logs out the user by sending a POST request to the server.
 */
async function logout() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });
        if (response.ok) {
            window.location.href = '/login.html';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error logging out:', error);
    }
}

/**
 * Changes the password for the currently logged-in user.
 */
async function changePassword() {
    const currentPassword = prompt('Enter current password:');
    const newPassword = prompt('Enter new password:');
    const confirmPassword = prompt('Confirm new password:');
    if (!currentPassword || !newPassword || !confirmPassword) {
        alert('All fields are required');
        return;
    }
    if (newPassword !== confirmPassword) {
        alert('New passwords do not match');
        return;
    }
    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ currentPassword, newPassword }),
            credentials: 'include'
        });
        const data = await response.json();
        if (response.ok) {
            alert(data.message);
        } else {
            alert(data.error || 'Failed to change password');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        alert('An error occurred while changing password');
    }
}

/**
 * Displays logs for a specific community.
 * @param {string} communityName - The name of the community.
 */
function showLogs(communityName) {
    if (!communityName) {
        alert('No community selected');
        return;
    }
    if (window.logUpdateInterval) { clearInterval(window.logUpdateInterval); } // Clear existing refresh interval
    const logPopupEl = document.getElementById('logPopup');
    document.getElementById('logPopupTitle').textContent = `Logs for ${communityName}`;
    if (logPopupEl) logPopupEl.classList.add('popup-visible'); // CSP Refactor
    updateLogs(communityName);

    // Set an interval to refresh logs every 10 seconds if the popup is still open
    window.logUpdateInterval = setInterval(() => {
        const currentLogPopupEl = document.getElementById('logPopup'); // Re-fetch in case of DOM changes
        if (currentLogPopupEl && currentLogPopupEl.classList.contains('popup-visible')) { // CSP Refactor
            updateLogs(communityName);
        } else {
            // If popup was closed by other means, clear this interval
            if(window.logUpdateInterval) clearInterval(window.logUpdateInterval);
        }
    }, 10000); // 10 seconds

    // Automatically close the log popup after 5 minutes
    if (window.logPopupTimeout) {
        clearTimeout(window.logPopupTimeout);
    }
    window.logPopupTimeout = setTimeout(() => {
        console.log('Log popup automatically closing due to timeout.');
        closeLogPopup();
    }, 5 * 60 * 1000); // 5 minutes
}

/**
 * Displays users in the system.
 */
function showUsersPopup() {
    const usersPopupEl = document.getElementById('usersPopup');
    if (usersPopupEl) usersPopupEl.classList.add('popup-visible'); // CSP Refactor
    fetchUsers();
}

/**
 * Closes the log popup and clears the log update interval and auto-close timeout.
 */
function closeLogPopup() {
    if (window.logPopupTimeout) { clearTimeout(window.logPopupTimeout); } // Clear auto-close timeout
    const logPopupEl = document.getElementById('logPopup');
    if (logPopupEl) logPopupEl.classList.remove('popup-visible'); // CSP Refactor
    if (window.logUpdateInterval) {
        clearInterval(window.logUpdateInterval); // Clear any potential polling interval
    }
}

/**
 * Closes the user management popup.
 */
function closeUsersPopup() {
    const usersPopupEl = document.getElementById('usersPopup');
    if (usersPopupEl) usersPopupEl.classList.remove('popup-visible'); // CSP Refactor
}

/**
 * Fetches and updates logs for a specific community.
 * @param {string} communityName - The name of the community.
 */
async function updateLogs(communityName) {
    try {
        const response = await fetch(`/api/communities/${encodeURIComponent(communityName)}/logs`);
        if (response.ok) {
            const logs = await response.json();
            displayLogs(logs);
        } else {
            console.error('Failed to fetch logs:', response.statusText);
        }
    } catch (error) {
        console.error('Error fetching logs:', error);
    }
}

/**
 * Displays logs in the UI.
 * @param {Array<Object>} logs - The logs to display.
 */
function displayLogs(logs) {
    const logContent = document.getElementById('logContent');
    logContent.innerHTML = '';

    // Sort logs descending by timestamp
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    logs.forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        // Format timestamp more compactly
        const date = new Date(log.timestamp);
        const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true };
        const dateOptions = { month: 'short', day: 'numeric' };
        const time = date.toLocaleTimeString('en-US', timeOptions);
        const dateStr = date.toLocaleDateString('en-US', dateOptions);
        const timestamp = `${dateStr} ${time}`;
        
        let actionClass = 'action-allowed'; // Default to allowed (green)
        // Ensure log.action exists and is a string before calling toLowerCase()
        if (log.action && typeof log.action === 'string' && log.action.toLowerCase().includes("denied")) {
            actionClass = 'action-denied'; // Set to denied (red) if applicable
            logEntry.classList.add('action-denied'); // Add class to entry for bar color
        }

        // Ensure log.action is a string for safe display in innerHTML; display number as is.
        const actionText = (typeof log.action === 'string' || typeof log.action === 'number') ? String(log.action) : '(empty action)';
        
        // Escape HTML to prevent XSS and preserve text
        const escapeHtml = (text) => {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        };
        
        // Check if action text is long (more than 60 characters - reduced for better UX)
        const isLongEntry = actionText.length > 60;
        // Only add expander on desktop (screens wider than 768px)
        const isMobile = window.innerWidth <= 768;
        const needsExpander = isLongEntry && !isMobile;

        // Add expandable class if needed
        if (needsExpander) {
            logEntry.classList.add('expandable');
        }

        // Create elements instead of using innerHTML for better control
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'timestamp';
        timestampSpan.textContent = timestamp;
        
        const playerSpan = document.createElement('span');
        playerSpan.className = 'player';
        playerSpan.textContent = log.player;
        
        const actionSpan = document.createElement('span');
        actionSpan.className = `action ${actionClass} ${isLongEntry ? 'truncated' : ''}`;
        actionSpan.textContent = actionText;
        
        logEntry.appendChild(timestampSpan);
        logEntry.appendChild(playerSpan);
        logEntry.appendChild(actionSpan);
        
        // Add expand indicator if needed
        if (needsExpander) {
            const expandIndicator = document.createElement('span');
            expandIndicator.className = 'expand-indicator';
            expandIndicator.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
            logEntry.appendChild(expandIndicator);
            
            // Add click handler
            logEntry.addEventListener('click', function() {
                this.classList.toggle('expanded');
            });
        }
        
        logContent.appendChild(logEntry);
    });
}

/**
 * Renders the list of communities in the UI.
 */
function renderCommunities() {
    const communityList = document.getElementById('communityList');
    communityList.innerHTML = ''; // Clear existing list items
    communities.forEach(community => {
        const li = document.createElement('li');

        if (isAdmin) {
            const removeButton = document.createElement('button');
            removeButton.className = 'remove-btn-sidebar';
            removeButton.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
            removeButton.title = 'Remove community';
            removeButton.addEventListener('click', (event) => {
                event.stopPropagation(); // Prevent li click event from firing
                removeCommunity(community.id);
            });
            li.appendChild(removeButton);
        }

        const nameSpan = document.createElement('span');
        nameSpan.textContent = community.name;
        li.appendChild(nameSpan);

        li.addEventListener('click', () => {
            selectCommunity(community.id);
        });

        if (selectedCommunity && community.id === selectedCommunity.id) {
            li.classList.add('active');
        }
        communityList.appendChild(li);
    });
}

/**
 * Selects a community by its ID and updates the UI.
 * @param {string} communityId - The ID of the community to select.
 */
function selectCommunity(communityId) {
    selectedCommunity = communities.find(c => c.id === communityId);
    selectedAddress = null;
    
    // Add transition effect to main content
    const mainContent = document.querySelector('main');
    const communityNameElement = document.getElementById('communityName');
    
    if (mainContent && window.AnimationUtils) {
        mainContent.classList.add('transitioning');
    }
    
    // Update content with slight delay for smooth transition
    setTimeout(() => {
        renderAddresses();
        if (selectedCommunity) {
            communityNameElement.textContent = selectedCommunity.name;
        }
        
        // Remove transition class and add animations
        if (mainContent) {
            mainContent.classList.remove('transitioning');
            
            if (window.AnimationUtils) {
                // Animate community name
                AnimationUtils.animateIn(communityNameElement, 'slideInDown', 0);
                
                // Address items will animate automatically with their built-in delays
            }
        }
    }, 100);

    // Initialize remoteGateControlEnabled if it's not defined
    if (typeof selectedCommunity.remoteGateControlEnabled === 'undefined') {
        selectedCommunity.remoteGateControlEnabled = false; // Default to false
    }

    const communityMenuBtn = document.getElementById('communityMenuBtn');
    // Visibility of communityMenuBtn is now handled by updateCommunityMenuView using classes.
    // Ensure the menu itself is hidden by default when a new community is selected
    const communityActionMenu = document.getElementById('communityActionMenu');
    if (communityActionMenu) { // CSP Refactor
        communityActionMenu.classList.add('hidden');
        communityActionMenu.classList.remove('community-action-menu-positioned');
    }
    // Ensure the menu button is visible if a community is selected (handled by updateCommunityMenuView)
    // const communityMenuBtn = document.getElementById('communityMenuBtn');
    // if (communityMenuBtn) {
    //      communityMenuBtn.classList.remove('hidden'); 
    // }

    updateCommunityMenuView(); // Update menu items based on selected community's state

    renderCommunities();
    renderAllowedUsers();
}

/**
 * Sends a command to open the gate for the specified community.
 * @param {string} communityName - The name of the community.
 */
async function openCommunityGate(communityName) {
    if (!communityName) {
        alert('No community specified for opening the gate.');
        return;
    }

    if (!csrfToken) {
        alert('CSRF token not available. Please refresh the page.');
        return;
    }

    try {
        const response = await fetch('/api/command/open-gate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ community: communityName }),
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            // Success - no alert needed
        } else {
            const errorData = await response.json();
            alert(`Failed to send gate command: ${errorData.error || response.statusText}`);
        }
    } catch (error) {
        console.error('Error sending gate command:', error);
        alert('An error occurred while sending the gate command. Please check the console for details.');
    }
}

/**
 * Renders the list of addresses for the selected community.
 */
function renderAddresses() {
    const addressList = document.getElementById('addressList');
    addressList.innerHTML = ''; // Clear existing list items

    if (selectedCommunity && selectedCommunity.addresses) {
        selectedCommunity.addresses.forEach((address, index) => {
            const li = document.createElement('li');
            li.className = 'address-item animate-in';
            li.setAttribute('data-address-id', address.id);
            li.style.animationDelay = `${index * 0.05}s`;
            if (address.isNew) {
                li.classList.add('new-address');
                // Add animation for new address
                if (window.AnimationUtils) {
                    setTimeout(() => {
                        AnimationUtils.animateIn(li, 'fadeInUp');
                        AnimationUtils.pulse(li);
                    }, 100);
                }
                setTimeout(() => {
                    // address.isNew is a temporary client-side flag, no need to persist this change via API
                    const currentAddress = selectedCommunity.addresses.find(a => a.id === address.id);
                    if (currentAddress) delete currentAddress.isNew;
                    li.classList.remove('new-address'); // Also remove the class after timeout
                }, 300);
            }

            // Create address-main div
            const addressMainDiv = document.createElement('div');
            addressMainDiv.className = 'address-main';

            const removeAddressBtn = document.createElement('button');
            removeAddressBtn.className = 'remove-btn';
            removeAddressBtn.textContent = 'Remove';
            removeAddressBtn.addEventListener('click', () => removeAddress(address.id));
            addressMainDiv.appendChild(removeAddressBtn);

            const addressTextSpan = document.createElement('span');
            addressTextSpan.className = 'address-text';
            addressTextSpan.textContent = address.street;
            addressTextSpan.addEventListener('click', () => toggleAddressDetails(address.id));
            addressMainDiv.appendChild(addressTextSpan);

            li.appendChild(addressMainDiv);

            // Create address-details div
            const addressDetailsDiv = document.createElement('div');
            addressDetailsDiv.className = 'address-details';
            addressDetailsDiv.id = `details-${address.id}`;

            // Users section
            const userIdsDiv = document.createElement('div');
            userIdsDiv.className = 'user-ids';
            const userIdsH4 = document.createElement('h4');
            userIdsH4.textContent = 'Users:';
            userIdsDiv.appendChild(userIdsH4);
            const userIdListUl = document.createElement('ul');
            userIdListUl.className = 'user-id-list';
            userIdsDiv.appendChild(userIdListUl); // ul will be populated by renderUserIds
            const addUserIdBtn = document.createElement('button');
            addUserIdBtn.className = 'add-btn';
            addUserIdBtn.textContent = 'Add User';
            addUserIdBtn.addEventListener('click', () => addUserId(address.id));
            userIdsDiv.appendChild(addUserIdBtn);
            addressDetailsDiv.appendChild(userIdsDiv);

            // Codes section
            const codesDiv = document.createElement('div');
            codesDiv.className = 'codes';
            const codesH4 = document.createElement('h4');
            codesH4.textContent = 'Codes:';
            codesDiv.appendChild(codesH4);
            const codeListUl = document.createElement('ul');
            codeListUl.className = 'code-list';
            codesDiv.appendChild(codeListUl); // ul will be populated by renderCodes
            const addCodeBtn = document.createElement('button');
            addCodeBtn.className = 'add-btn';
            addCodeBtn.textContent = 'Add Code';
            addCodeBtn.addEventListener('click', () => addCode(address.id));
            codesDiv.appendChild(addCodeBtn);
            addressDetailsDiv.appendChild(codesDiv);

            li.appendChild(addressDetailsDiv);
            addressList.appendChild(li);

            // Call renderUserIds and renderCodes to populate the respective lists
            renderUserIds(address);
            renderCodes(address);

            // Add "Trigger Relay" button if address.hasGate is true
            if (address.hasGate === true) {
                // Create gate controls section
                const gateControlsDiv = document.createElement('div');
                gateControlsDiv.className = 'gate-controls';
                
                const gateH4 = document.createElement('h4');
                gateH4.textContent = 'Access Control:';
                gateControlsDiv.appendChild(gateH4);
                
                const openGateAddressBtn = document.createElement('button');
                openGateAddressBtn.textContent = 'Trigger Relay';
                openGateAddressBtn.className = 'add-btn address-open-gate-btn';
                openGateAddressBtn.addEventListener('click', async () => {
                    // Store original text
                    const originalText = openGateAddressBtn.textContent;
                    
                    // Set loading state
                    openGateAddressBtn.textContent = 'Triggering...';
                    openGateAddressBtn.disabled = true;
                    openGateAddressBtn.classList.add('loading');
                    
                    try {
                        await openAddressGate(selectedCommunity.name, address.street);
                    } finally {
                        // Restore original state after a brief delay
                        setTimeout(() => {
                            openGateAddressBtn.textContent = originalText;
                            openGateAddressBtn.disabled = false;
                            openGateAddressBtn.classList.remove('loading');
                        }, 1000);
                    }
                });
                gateControlsDiv.appendChild(openGateAddressBtn);

                // Add Pairing Mode button (10 second relay hold for RFID pairing)
                const pairingModeBtn = document.createElement('button');
                pairingModeBtn.textContent = 'Pairing Mode';
                pairingModeBtn.className = 'add-btn pairing-mode-btn';
                pairingModeBtn.style.marginLeft = '8px';
                pairingModeBtn.addEventListener('click', async () => {
                    const originalText = pairingModeBtn.textContent;
                    pairingModeBtn.textContent = 'Pairing (10s)...';
                    pairingModeBtn.disabled = true;
                    pairingModeBtn.classList.add('loading');

                    try {
                        await activatePairingMode(selectedCommunity.name, address.street);
                    } finally {
                        // Keep button disabled for 10 seconds while relay is open
                        setTimeout(() => {
                            pairingModeBtn.textContent = originalText;
                            pairingModeBtn.disabled = false;
                            pairingModeBtn.classList.remove('loading');
                        }, 10000);
                    }
                });
                gateControlsDiv.appendChild(pairingModeBtn);

                addressDetailsDiv.appendChild(gateControlsDiv);
            }
        });
    }
}

/**
 * Sends a command to open the gate for a specific address within a community.
 * @param {string} communityName - The name of the community.
 * @param {string} streetAddress - The street address for which to open the gate.
 */
async function openAddressGate(communityName, streetAddress) {
    if (!communityName || !streetAddress) {
        alert('Community name and street address are required for opening the gate.');
        return;
    }

    if (!csrfToken) {
        alert('CSRF token not available. Please refresh the page.');
        return;
    }

    try {
        const response = await fetch('/api/command/open-gate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ community: communityName, address: streetAddress }),
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            // Success - no alert needed
        } else {
            const errorData = await response.json();
            alert(`Failed to send gate command for address: ${errorData.error || response.statusText}`);
        }
    } catch (error) {
        console.error('Error sending address gate command:', error);
        alert('An error occurred while sending the address gate command. Please check the console.');
    }
}

/**
 * Activates pairing mode for an address (10 second relay hold for RFID pairing).
 * @param {string} communityName - The name of the community.
 * @param {string} streetAddress - The street address for pairing mode.
 */
async function activatePairingMode(communityName, streetAddress) {
    if (!communityName || !streetAddress) {
        alert('Community name and street address are required for pairing mode.');
        return;
    }

    if (!csrfToken) {
        alert('CSRF token not available. Please refresh the page.');
        return;
    }

    try {
        const response = await fetch('/api/command/pairing-mode', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ community: communityName, address: streetAddress }),
            credentials: 'include'
        });

        if (!response.ok) {
            const errorData = await response.json();
            alert(`Failed to activate pairing mode: ${errorData.error || response.statusText}`);
        }
    } catch (error) {
        console.error('Error activating pairing mode:', error);
        alert('An error occurred while activating pairing mode. Please check the console.');
    }
}

/**
 * Toggles the visibility of address details.
 * @param {string} addressId - The ID of the address.
 */
function toggleAddressDetails(addressId) {
    const detailsElement = document.getElementById(`details-${addressId}`);
    const addressItem = detailsElement.closest('.address-item');
    
    // Add smooth transition effect
    if (detailsElement.classList.contains('show')) {
        // Closing
        detailsElement.classList.remove('show');
        if (addressItem && window.AnimationUtils) {
            setTimeout(() => {
                AnimationUtils.pulse(addressItem);
            }, 150);
        }
    } else {
        // Opening
        detailsElement.classList.add('show');
        if (addressItem && window.AnimationUtils) {
            setTimeout(() => {
                // Animate user IDs and codes
                const userItems = detailsElement.querySelectorAll('.user-id-list li, .code-list li');
                AnimationUtils.staggerAnimation(userItems, 'fadeInUp', 50);
            }, 200);
        }
    }
}

/**
 * Renders the list of user IDs for a given address.
 * @param {Object} address - The address object.
 */
function renderUserIds(address) {
    const userIdList = document.querySelector(`#details-${address.id} .user-id-list`);
    if (!userIdList) return; // Guard against null if the structure isn't ready
    userIdList.innerHTML = ''; // Clear existing items

    if (address.people) {
        address.people.forEach(person => {
            const li = document.createElement('li');
            li.setAttribute('data-person-id', person.id);

            const removePersonBtn = document.createElement('button');
            removePersonBtn.className = 'remove-btn-user';
            removePersonBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
            removePersonBtn.title = `Remove user ${person.username}`;
            removePersonBtn.addEventListener('click', () => removeUserId(address.id, person.id));
            li.appendChild(removePersonBtn);

            const personDetailsSpan = document.createElement('span');
            personDetailsSpan.textContent = `${person.username} (ID: ${person.playerId})`;
            li.appendChild(personDetailsSpan);

            userIdList.appendChild(li);
        });
    }
}

/**
 * Renders the list of codes for a given address.
 * @param {Object} address - The address object.
 */
function renderCodes(address) {
    const codeList = document.querySelector(`#details-${address.id} .code-list`);
    if (!codeList) return; // Guard against null
    codeList.innerHTML = ''; // Clear existing items

    if (address.codes) {
        address.codes.forEach(code => {
            const li = document.createElement('li');
            li.setAttribute('data-code-id', code.id);

            const removeCodeBtn = document.createElement('button');
            removeCodeBtn.className = 'remove-btn-user';
            removeCodeBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
            removeCodeBtn.title = `Remove code ${code.description}`;
            removeCodeBtn.addEventListener('click', () => removeCode(address.id, code.id));
            li.appendChild(removeCodeBtn);

            const codeDetailsSpan = document.createElement('span');
            codeDetailsSpan.textContent = `${code.description} (Code: ${code.code}, Expires: ${new Date(code.expiresAt).toLocaleString()})`;
            li.appendChild(codeDetailsSpan);

            codeList.appendChild(li);
        });
    }
}

/**
 * Adds a new community by prompting for a name and sending a POST request.
 */
/**
 * Shows the custom add community popup
 */
function showAddCommunityModal() {
    if (communities.length >= 8) {
        alert('Maximum number of communities reached');
        return;
    }
    
    const modal = document.getElementById('addCommunityModal');
    const nameInput = document.getElementById('communityNameInput');
    const descriptionInput = document.getElementById('communityDescriptionInput');
    
    // Clear previous values
    nameInput.value = '';
    descriptionInput.value = '';
    
    // Show modal
    modal.classList.add('popup-visible');
    
    // Focus first input
    setTimeout(() => nameInput.focus(), 100);
}

/**
 * Closes the add community modal
 */
function closeAddCommunityModal() {
    const modal = document.getElementById('addCommunityModal');
    modal.classList.remove('popup-visible');
}

/**
 * Saves the community from the modal
 */
async function saveCommunityFromModal() {
    const name = document.getElementById('communityNameInput').value.trim();
    const description = document.getElementById('communityDescriptionInput').value.trim();
    
    if (!name) {
        alert('Please enter a community name');
        return;
    }
    
    try {
        // Show loading overlay on sidebar
        if (window.AnimationUtils) {
            AnimationUtils.showLoading('communityList', 'Creating community');
        }
        
        const response = await fetch('/api/communities', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ name, description }),
            credentials: 'include'
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Failed to add community');
        }
        if (data.community) {
            communities.push(data.community);
            renderCommunities();
            selectCommunity(data.community.id);
            updateAddCommunityButtonVisibility();
            const addAddressBtn = document.getElementById('addAddressBtn');
            const addressesHeader = document.querySelector('main h3');
            if (communities.length > 0) {
                addAddressBtn.style.display = 'block';
                addressesHeader.style.display = 'block';
            }
            closeAddCommunityModal();
        } else {
            throw new Error('Invalid server response');
        }
    } catch (error) {
        console.error('Error adding community:', error);
        alert(error.message || 'An error occurred while adding the community');
    } finally {
        // Hide loading overlay
        if (window.AnimationUtils) {
            AnimationUtils.hideLoading('communityList');
        }
    }
}

async function addCommunity() {
    showAddCommunityModal();
}

/**
 * Removes a community by its ID after user confirmation.
 * @param {string} communityId - The ID of the community.
 */
async function removeCommunity(communityId) {
    if (confirm('Are you sure you want to remove this community?')) {
        try {
            const response = await fetch(`/api/communities/${communityId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (response.ok) {
                communities = communities.filter(c => c.id !== communityId);
                renderCommunities();
                const addAddressBtn = document.getElementById('addAddressBtn');
                const addressesHeader = document.querySelector('main h3');
                if (communities.length > 0) {
                    selectCommunity(communities[0].id);
                    addAddressBtn.style.display = 'block';
                    addressesHeader.style.display = 'block';
                } else {
                    selectedCommunity = null;
                    renderAddresses();
                    addAddressBtn.style.display = 'none';
                    addressesHeader.style.display = 'none';
                    document.getElementById('communityName').textContent = 'Please create a Community';
                    updateCommunityMenuView(); // Ensure menu is hidden if last community is removed
                }
                updateAddCommunityButtonVisibility();
            } else {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to remove community');
            }
        } catch (error) {
            console.error('Error removing community:', error);
            alert(error.message || 'An error occurred while removing the community. Please try again.');
        }
    }
}

/**
 * Updates the visibility of the "Add Community" button based on the number of communities.
 */
function updateAddCommunityButtonVisibility() {
    const MAX_COMMUNITIES = 8;
    const sidebarTop = document.querySelector('.sidebar-top');
    let addButton = document.getElementById('12');
    if (communities.length >= MAX_COMMUNITIES) {
        if (addButton) addButton.remove();
    } else {
        if (!addButton) {
            addButton = document.createElement('button');
            addButton.id = '12';
            addButton.className = 'add-btn';
            addButton.onclick = addCommunity;
            addButton.textContent = '+';
            const communityList = document.getElementById('communityList');
            if (communityList && communityList.nextSibling) {
                sidebarTop.insertBefore(addButton, communityList.nextSibling);
            } else {
                sidebarTop.appendChild(addButton);
            }
        }
    }
}

/**
 * Shows the custom add address popup
 */
function showAddAddressModal() {
    if (!selectedCommunity) return;
    
    const modal = document.getElementById('addAddressModal');
    const streetInput = document.getElementById('addressStreetInput');
    const hasGateInput = document.getElementById('addressHasGateInput');
    const hasGateBtn = document.getElementById('addressHasGateBtn');
    
    // Clear previous values
    streetInput.value = '';
    hasGateInput.value = 'false';
    hasGateBtn.classList.remove('active');
    
    // Show modal
    modal.classList.add('popup-visible');
    
    // Focus first input
    setTimeout(() => streetInput.focus(), 100);
}

/**
 * Closes the add address modal
 */
function closeAddAddressModal() {
    const modal = document.getElementById('addAddressModal');
    modal.classList.remove('popup-visible');
}

/**
 * Saves the address from the modal
 */
async function saveAddressFromModal() {
    const street = document.getElementById('addressStreetInput').value.trim();
    const hasGate = document.getElementById('addressHasGateInput').value === 'true';
    
    if (!street) {
        alert('Please enter a street address');
        return;
    }
    
    try {
        const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ street, hasGate }),
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error('Failed to add address');
        }
        const newAddress = await response.json();
        newAddress.isNew = true;
        if (!selectedCommunity.addresses) {
            selectedCommunity.addresses = [];
        }
        selectedCommunity.addresses.push(newAddress);
        renderAddresses();
        closeAddAddressModal();
    } catch (error) {
        console.error('Error adding address:', error);
        alert('Failed to add address. Please try again.');
    }
}

/**
 * Adds a new address to the selected community.
 */
async function addAddress() {
    showAddAddressModal();
}

/**
 * Removes an address from the selected community.
 * @param {string} addressId - The ID of the address.
 */
async function removeAddress(addressId) {
    if (!selectedCommunity) return;
    if (confirm('Are you sure you want to remove this address?')) {
        try {
            const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error('Failed to delete address');
            }
            selectedCommunity.addresses = selectedCommunity.addresses.filter(a => a.id !== addressId);
            renderAddresses();
        } catch (error) {
            console.error('Error removing address:', error);
            alert('Failed to remove address. Please try again.');
        }
    }
}

/**
 * Shows the custom add user ID popup
 * @param {string} addressId - The ID of the address.
 */
function showAddUserIdModal(addressId) {
    const modal = document.getElementById('addUserIdModal');
    const usernameInput = document.getElementById('userIdUsernameInput');
    const playerIdInput = document.getElementById('userIdPlayerIdInput');
    
    // Clear previous values
    usernameInput.value = '';
    playerIdInput.value = '';
    
    // Store addressId for later use
    modal.dataset.addressId = addressId;
    
    // Show modal
    modal.classList.add('popup-visible');
    
    // Focus first input
    setTimeout(() => usernameInput.focus(), 100);
}

/**
 * Closes the add user ID modal
 */
function closeAddUserIdModal() {
    const modal = document.getElementById('addUserIdModal');
    modal.classList.remove('popup-visible');
}

/**
 * Saves the user ID from the modal
 */
async function saveUserIdFromModal() {
    const modal = document.getElementById('addUserIdModal');
    const addressId = modal.dataset.addressId;
    const username = document.getElementById('userIdUsernameInput').value.trim();
    const playerId = document.getElementById('userIdPlayerIdInput').value.trim();
    
    if (!username || !playerId) {
        alert('Please fill in both fields');
        return;
    }
    
    const address = selectedCommunity.addresses.find(a => a.id === addressId);
    if (!address) return;
    
    try {
        const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/people`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ username, playerId }),
            credentials: 'include'
        });
        if (response.ok) {
            const newUserId = await response.json();
            if (!address.people) {
                address.people = [];
            }
            address.people.push(newUserId);
            renderUserIds(address);
            closeAddUserIdModal();
        } else {
            console.error('Failed to add user ID:', response.statusText);
            alert('Failed to add resident');
        }
    } catch (error) {
        console.error('Error adding user ID:', error);
        alert('Failed to add resident');
    }
}

/**
 * Adds a new user ID to an address.
 * @param {string} addressId - The ID of the address.
 */
async function addUserId(addressId) {
    showAddUserIdModal(addressId);
}

/**
 * Removes a user ID from an address.
 * @param {string} addressId - The ID of the address.
 * @param {string} userIdId - The ID of the user ID.
 */
async function removeUserId(addressId, userIdId) {
    const address = selectedCommunity.addresses.find(a => a.id === addressId);
    if (!address) return;
    if (confirm('Are you sure you want to remove this user ID?')) {
        try {
            const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/people/${userIdId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (response.ok) {
                address.people = address.people.filter(u => u.id !== userIdId);
                renderUserIds(address);
            } else {
                console.error('Failed to remove user ID:', response.statusText);
            }
        } catch (error) {
            console.error('Error removing user ID:', error);
        }
    }
}

/**
 * Closes the Add Code modal and cleans up
 */
function closeAddCodeModal() {
    const addCodeModal = document.getElementById('addCodeModal');
    const codeDescriptionInput = document.getElementById('codeDescriptionInput');
    const codeValueInput = document.getElementById('codeValueInput');
    
    // Clear fields
    codeDescriptionInput.value = '';
    codeValueInput.value = '';
    
    // Clear and destroy Flatpickr
    if (window.codeExpiryFlatpickr) {
        window.codeExpiryFlatpickr.clear();
        window.codeExpiryFlatpickr.destroy();
        window.codeExpiryFlatpickr = null;
    }
    
    // Hide modal using class
    addCodeModal.classList.remove('popup-visible');
    // Clean up dataset
    delete addCodeModal.dataset.addressId;
}

/**
 * Adds a new code to an address.
 * @param {string} addressId - The ID of the address.
 */
async function addCode(addressId) {
    const addCodeModal = document.getElementById('addCodeModal');
    const codeDescriptionInput = document.getElementById('codeDescriptionInput');
    const codeValueInput = document.getElementById('codeValueInput');
    const codeExpiryInput = document.getElementById('codeExpiryInput');

    // Clear previous values
    codeDescriptionInput.value = '';
    codeValueInput.value = '';
    codeExpiryInput.value = '';

    // Store addressId in the modal's dataset to be accessible by the save button's event handler
    addCodeModal.dataset.addressId = addressId;

    // Destroy previous Flatpickr instance if it exists
    if (window.codeExpiryFlatpickr) {
        window.codeExpiryFlatpickr.destroy();
    }
    
    // Initialize Flatpickr on the expiry input
    window.codeExpiryFlatpickr = flatpickr(codeExpiryInput, {
        enableTime: true,
        dateFormat: "Y-m-d H:i",
        altInput: true,
        altFormat: "F j, Y H:i",
    });

    // Show modal using class
    addCodeModal.classList.add('popup-visible');
}

/**
 * Removes a code from an address.
 * @param {string} addressId - The ID of the address.
 * @param {string} codeId - The ID of the code.
 */
async function removeCode(addressId, codeId) {
    const address = selectedCommunity.addresses.find(a => a.id === addressId);
    if (!address) return;
    if (confirm('Are you sure you want to remove this code?')) {
        try {
            const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/codes/${codeId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'include'
            });
            if (response.ok) {
                address.codes = address.codes.filter(c => c.id !== codeId);
                renderCodes(address);
            } else {
                console.error('Failed to remove code:', response.statusText);
            }
        } catch (error) {
            console.error('Error removing code:', error);
        }
    }
}

/**
 * Updates the list of allowed users for the selected community.
 */
async function updateAllowedUsers() {
    if (!selectedCommunity) {
        alert('No community selected');
        return;
    }
    const allowedUsersInput = document.getElementById('allowedUsersInput').value;
    const newAllowedUsers = allowedUsersInput.split(',').map(user => user.trim()).filter(Boolean);
    const allowedUsersSet = new Set([...selectedCommunity.allowedUsers, ...newAllowedUsers]);
    try {
        const response = await fetch(`/api/communities/${selectedCommunity.id}/allowed-users`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ allowedUsers: Array.from(allowedUsersSet) }),
            credentials: 'include'
        });
        if (response.ok) {
            const data = await response.json();
            if (data.warning) {
                alert(data.warning);
            }
            selectedCommunity.allowedUsers = data.validUsers;
            renderAllowedUsers();
            document.getElementById('allowedUsersInput').value = '';
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.error}`);
        }
    } catch (error) {
        console.error('Error updating allowed users:', error);
        alert('An error occurred while updating allowed users. Please try again.');
    }
}

/**
 * Renders the list of allowed users for the selected community.
 */
function renderAllowedUsers() {
    const allowedUsersDropdown = document.getElementById('allowedUsersDropdown');
    if (!allowedUsersDropdown) return;
    allowedUsersDropdown.innerHTML = '';
    if (selectedCommunity && selectedCommunity.allowedUsers) {
        selectedCommunity.allowedUsers.forEach(user => {
            const option = document.createElement('option');
            option.value = user;
            option.textContent = user;
            allowedUsersDropdown.appendChild(option);
        });
    }
    const allowedUsersManagement = document.getElementById('allowedUsersManagement');
    if (allowedUsersManagement) {
        if (selectedCommunity && isAdmin) { // CSP Refactor: Only show if a community is selected AND user is admin
            allowedUsersManagement.classList.remove('hidden');
        } else {
            allowedUsersManagement.classList.add('hidden');
        }
    }
}

/**
 * Removes the selected users from the allowed users list and updates the server.
 */
function removeSelectedUsers() {
    const allowedUsersDropdown = document.getElementById('allowedUsersDropdown');
    if (!allowedUsersDropdown) return;
    Array.from(allowedUsersDropdown.selectedOptions).forEach(option => {
        selectedCommunity.allowedUsers = selectedCommunity.allowedUsers.filter(u => u !== option.value);
    });
    updateAllowedUsers();
}

function promptForGateConfirmation() {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmHasGateModal');
        const yesBtn = document.getElementById('confirmHasGateYesBtn');
        const noBtn = document.getElementById('confirmHasGateNoBtn');

        // Function to handle cleanup
        function cleanupAndResolve(value) {
            modal.style.display = 'none';
            // Clone and replace buttons to remove event listeners
            // This is crucial to prevent multiple listeners from accumulating
            // if the modal is shown multiple times.
            const newYesBtn = yesBtn.cloneNode(true);
            yesBtn.parentNode.replaceChild(newYesBtn, yesBtn);

            const newNoBtn = noBtn.cloneNode(true);
            noBtn.parentNode.replaceChild(newNoBtn, noBtn);
            
            resolve(value);
        }

        // Get the fresh button references for attaching events this time
        const currentYesBtn = document.getElementById('confirmHasGateYesBtn');
        const currentNoBtn = document.getElementById('confirmHasGateNoBtn');

        currentYesBtn.onclick = () => cleanupAndResolve(true);
        currentNoBtn.onclick = () => cleanupAndResolve(false);

        // Optional: handle closing modal via ESC key or clicking outside
        // For simplicity, this is omitted but could be added for better UX.

        // Show the modal
        modal.style.display = 'block';
    });
}

// Fetch initial CSRF token and data (already set up in DOMContentLoaded above)
// fetchData(); // Called by checkLoginStatus

/********************************************************
  NEW ACCESS MANAGEMENT SYSTEM
*********************************************************/

let selectedUsersForAccess = [];
let searchResultsVisible = false;

/**
 * Utility function for debouncing
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Opens the access management popup
 */
async function openAccessManagementPopup() {
    if (!selectedCommunity) {
        alert('Please select a community first');
        return;
    }

    const popup = document.getElementById('accessManagementPopup');
    const communityName = document.getElementById('accessCommunityName');
    
    if (communityName) {
        communityName.textContent = selectedCommunity.name;
    }
    
    // Fetch users if not already loaded
    if (!users || users.length === 0) {
        await fetchUsers();
    }
    
    renderCurrentAccessList();
    clearUserSelection();
    
    popup.classList.remove('hidden');
    popup.style.display = 'block';
}

/**
 * Closes the access management popup
 */
function closeAccessManagementPopup() {
    const popup = document.getElementById('accessManagementPopup');
    if (popup) {
        popup.classList.add('hidden');
        popup.style.display = 'none';
    }
    
    // Clear search and selections
    clearUserSelection();
    hideUserSearchResults();
}

// Close popup with Escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        const popup = document.getElementById('accessManagementPopup');
        if (popup && !popup.classList.contains('hidden')) {
            closeAccessManagementPopup();
        }
    }
});

/**
 * Renders the current access list
 */
function renderCurrentAccessList() {
    const accessList = document.getElementById('currentAccessList');
    if (!accessList) return;

    accessList.innerHTML = '';

    if (!selectedCommunity || !selectedCommunity.allowedUsers || selectedCommunity.allowedUsers.length === 0) {
        accessList.innerHTML = '<div class="empty-access-message">No users have access to this community yet.</div>';
        return;
    }

    selectedCommunity.allowedUsers.forEach(username => {
        const user = users.find(u => u.username === username);
        const userItem = document.createElement('div');
        userItem.className = 'user-access-item';
        
        const userInfo = document.createElement('div');
        userInfo.className = 'user-access-info';
        
        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        avatar.textContent = username.charAt(0).toUpperCase();
        
        const details = document.createElement('div');
        details.className = 'user-details';
        
        const name = document.createElement('div');
        name.className = 'user-name';
        name.textContent = username;
        
        const role = document.createElement('div');
        role.className = 'user-role';
        role.textContent = user ? user.role : 'User';
        
        details.appendChild(name);
        details.appendChild(role);
        userInfo.appendChild(avatar);
        userInfo.appendChild(details);
        
        const removeBtn = document.createElement('button');
        removeBtn.className = 'remove-access-btn';
        removeBtn.textContent = 'Remove';
        removeBtn.onclick = () => removeUserAccess(username);
        
        // Don't allow removing admin access
        if (user && (user.role === 'admin' || user.role === 'superuser')) {
            removeBtn.disabled = true;
            removeBtn.textContent = 'Protected';
        }
        
        userItem.appendChild(userInfo);
        userItem.appendChild(removeBtn);
        accessList.appendChild(userItem);
    });
}

/**
 * Removes access for a specific user
 */
async function removeUserAccess(username) {
    if (!selectedCommunity) return;

    try {
        selectedCommunity.allowedUsers = selectedCommunity.allowedUsers.filter(u => u !== username);
        
        const response = await fetch(`/api/communities/${selectedCommunity.id}/allowed-users`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ allowedUsers: selectedCommunity.allowedUsers }),
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            if (data.warning) {
                alert(data.warning);
            }
            selectedCommunity.allowedUsers = data.validUsers;
            renderCurrentAccessList();
            renderAllowedUsers(); // Update legacy view if visible
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.error}`);
            // Revert on error
            selectedCommunity.allowedUsers.push(username);
        }
    } catch (error) {
        console.error('Error removing user access:', error);
        alert('Failed to remove user access');
        // Revert on error
        selectedCommunity.allowedUsers.push(username);
    }
}

/**
 * Searches for users based on input
 */
function searchUsers() {
    const searchInput = document.getElementById('userSearchInput');
    const searchResults = document.getElementById('userSearchResults');
    
    if (!searchInput || !searchResults) {
        console.error('Search input or results container not found');
        return;
    }
    
    const query = searchInput.value.trim().toLowerCase();
    
    if (query.length < 1) {
        hideUserSearchResults();
        return;
    }
    
    // Ensure users array exists and has data
    if (!users || users.length === 0) {
        console.warn('No users available for search');
        const noUsersResult = document.createElement('div');
        noUsersResult.className = 'user-search-item';
        noUsersResult.textContent = 'No users available';
        searchResults.innerHTML = '';
        searchResults.appendChild(noUsersResult);
        showUserSearchResults();
        return;
    }
    
    // Ensure selectedCommunity exists and has allowedUsers
    const allowedUsers = selectedCommunity && selectedCommunity.allowedUsers ? selectedCommunity.allowedUsers : [];
    
    // Filter users that don't already have access, match the search, and are not admin/superuser
    const filteredUsers = users.filter(user => {
        const hasAccess = allowedUsers.includes(user.username);
        const matchesSearch = user.username.toLowerCase().includes(query);
        const isAdminOrSuperuser = user.role === 'admin' || user.role === 'superuser';
        return !hasAccess && matchesSearch && !isAdminOrSuperuser;
    });
    
    console.log(`Search query: "${query}", Found ${filteredUsers.length} users`);
    
    renderUserSearchResults(filteredUsers);
    showUserSearchResults();
}

/**
 * Renders user search results
 */
function renderUserSearchResults(filteredUsers) {
    const searchResults = document.getElementById('userSearchResults');
    if (!searchResults) return;
    
    searchResults.innerHTML = '';
    
    if (filteredUsers.length === 0) {
        const noResults = document.createElement('div');
        noResults.className = 'user-search-item';
        noResults.textContent = 'No users found';
        searchResults.appendChild(noResults);
        return;
    }
    
    filteredUsers.forEach(user => {
        const userItem = document.createElement('div');
        userItem.className = 'user-search-item';
        
        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        avatar.style.width = '24px';
        avatar.style.height = '24px';
        avatar.style.fontSize = '0.75rem';
        avatar.textContent = user.username.charAt(0).toUpperCase();
        
        const nameSpan = document.createElement('span');
        nameSpan.textContent = user.username;
        
        userItem.appendChild(avatar);
        userItem.appendChild(nameSpan);
        
        userItem.onclick = () => selectUserForAccess(user);
        
        searchResults.appendChild(userItem);
    });
}

/**
 * Shows user search results
 */
function showUserSearchResults() {
    const searchResults = document.getElementById('userSearchResults');
    if (searchResults && searchResults.children.length > 0) {
        searchResults.classList.remove('hidden');
        searchResultsVisible = true;
    }
}

/**
 * Hides user search results
 */
function hideUserSearchResults() {
    const searchResults = document.getElementById('userSearchResults');
    if (searchResults) {
        searchResults.classList.add('hidden');
        searchResultsVisible = false;
    }
}

/**
 * Selects a user for access
 */
function selectUserForAccess(user) {
    if (!selectedUsersForAccess.find(u => u.username === user.username)) {
        selectedUsersForAccess.push(user);
        renderSelectedUsersChips();
        updateGrantAccessButton();
    }
    
    // Clear search
    const searchInput = document.getElementById('userSearchInput');
    if (searchInput) {
        searchInput.value = '';
    }
    hideUserSearchResults();
}

/**
 * Renders selected users as chips
 */
function renderSelectedUsersChips() {
    const chipsContainer = document.getElementById('selectedUsersChips');
    if (!chipsContainer) return;
    
    chipsContainer.innerHTML = '';
    
    selectedUsersForAccess.forEach(user => {
        const chip = document.createElement('div');
        chip.className = 'user-chip';
        
        const nameSpan = document.createElement('span');
        nameSpan.textContent = user.username;
        
        const removeBtn = document.createElement('button');
        removeBtn.innerHTML = '×';
        removeBtn.onclick = () => removeUserFromSelection(user.username);
        
        chip.appendChild(nameSpan);
        chip.appendChild(removeBtn);
        chipsContainer.appendChild(chip);
    });
}

/**
 * Removes a user from selection
 */
function removeUserFromSelection(username) {
    selectedUsersForAccess = selectedUsersForAccess.filter(u => u.username !== username);
    renderSelectedUsersChips();
    updateGrantAccessButton();
}

/**
 * Updates the grant access button state
 */
function updateGrantAccessButton() {
    const grantBtn = document.getElementById('grantAccessBtn');
    if (!grantBtn) return;
    
    if (selectedUsersForAccess.length > 0) {
        grantBtn.disabled = false;
        grantBtn.textContent = `Grant Access (${selectedUsersForAccess.length})`;
    } else {
        grantBtn.disabled = true;
        grantBtn.textContent = 'Grant Access';
    }
}

/**
 * Grants access to selected users
 */
async function grantSelectedUsersAccess() {
    if (!selectedCommunity || selectedUsersForAccess.length === 0) return;
    
    const usernames = selectedUsersForAccess.map(u => u.username);
    const newAllowedUsers = [...selectedCommunity.allowedUsers, ...usernames];
    
    try {
        const response = await fetch(`/api/communities/${selectedCommunity.id}/allowed-users`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ allowedUsers: newAllowedUsers }),
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.warning) {
                alert(data.warning);
            }
            selectedCommunity.allowedUsers = data.validUsers;
            renderCurrentAccessList();
            renderAllowedUsers(); // Update legacy view if visible
            clearUserSelection();
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.error}`);
        }
    } catch (error) {
        console.error('Error granting user access:', error);
        alert('Failed to grant user access');
    }
}

/**
 * Clears user selection
 */
function clearUserSelection() {
    selectedUsersForAccess = [];
    renderSelectedUsersChips();
    updateGrantAccessButton();
    
    const searchInput = document.getElementById('userSearchInput');
    if (searchInput) {
        searchInput.value = '';
    }
}

// Export functions for global access (used by search component)
window.selectCommunity = selectCommunity;
