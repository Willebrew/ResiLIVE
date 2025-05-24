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
            if (isAdmin) {
                document.getElementById('allowedUsersManagement').style.display = 'block';
            } else {
                const allowedUsersManagement = document.getElementById('allowedUsersManagement');
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
    if (hamburgerBtn) {
        hamburgerBtn.addEventListener('click', () => {
            document.querySelector('.sidebar').classList.toggle('sidebar-open');
        });
    }

    // User menu toggle on user circle click
    const userCircle = document.getElementById('userCircle');
    const userMenu = document.getElementById('userMenu');
    if (userCircle && userMenu) {
        userCircle.addEventListener('click', (e) => {
            e.stopPropagation();
            userMenu.classList.toggle('show');
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

    const updateAllowedUsersBtn = document.getElementById('updateAllowedUsersBtn');
    if (updateAllowedUsersBtn) {
        updateAllowedUsersBtn.addEventListener('click', updateAllowedUsers);
    }

    const removeSelectedUsersBtn = document.getElementById('removeSelectedUsersBtn');
    if (removeSelectedUsersBtn) {
        removeSelectedUsersBtn.addEventListener('click', removeSelectedUsers);
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
            roleButton.textContent = user.role === 'admin' ? '👑' : '👤';
            roleButton.addEventListener('click', () => toggleUserRole(user.id));
            controlsDiv.appendChild(roleButton);

            const removeUserButton = document.createElement('button');
            removeUserButton.className = 'remove-btn';
            removeUserButton.textContent = '-';
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
    if (username && password) {
        try {
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
            addAddressBtn.style.display = 'block';
            addressesHeader.style.display = 'block';
            selectCommunity(communities[0].id);
        } else {
            addAddressBtn.style.display = 'none';
            addressesHeader.style.display = 'none';
            document.getElementById('communityName').textContent = 'Please create a Community';
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
    document.getElementById('logPopupTitle').textContent = `Logs for ${communityName}`;
    document.getElementById('logPopup').style.display = 'block';
    updateLogs(communityName);

    // Set an interval to refresh logs every 10 seconds if the popup is still open
    window.logUpdateInterval = setInterval(() => {
        if (document.getElementById('logPopup').style.display === 'block') {
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
    document.getElementById('usersPopup').style.display = 'block';
    fetchUsers();
}

/**
 * Closes the log popup and clears the log update interval and auto-close timeout.
 */
function closeLogPopup() {
    if (window.logPopupTimeout) { clearTimeout(window.logPopupTimeout); } // Clear auto-close timeout
    document.getElementById('logPopup').style.display = 'none';
    if (window.logUpdateInterval) {
        clearInterval(window.logUpdateInterval); // Clear any potential polling interval
    }
}

/**
 * Closes the user management popup.
 */
function closeUsersPopup() {
    document.getElementById('usersPopup').style.display = 'none';
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
        const timestamp = new Date(log.timestamp).toLocaleString();

        // If the log action contains "Access denied", style it in red; otherwise use the default.
        const actionStyle = log.action.includes("Access denied")
            ? 'color: #FF3B30;'
            : 'color: var(--color-btn-add-bg);';

        logEntry.innerHTML = `
            <span class="timestamp">${timestamp}</span><br>
            <span class="player">${log.player}</span>: 
            <span class="action" style="${actionStyle}">${log.action}</span>
        `;
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
            removeButton.innerHTML = '&times;'; // Use innerHTML for HTML entities like &times;
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
    renderAddresses();
    document.getElementById('communityName').textContent = selectedCommunity.name;
    renderCommunities();
    renderAllowedUsers();
}

/**
 * Renders the list of addresses for the selected community.
 */
function renderAddresses() {
    const addressList = document.getElementById('addressList');
    addressList.innerHTML = ''; // Clear existing list items

    if (selectedCommunity && selectedCommunity.addresses) {
        selectedCommunity.addresses.forEach(address => {
            const li = document.createElement('li');
            li.className = 'address-item';
            if (address.isNew) {
                li.classList.add('new-address');
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

            // User IDs section
            const userIdsDiv = document.createElement('div');
            userIdsDiv.className = 'user-ids';
            const userIdsH4 = document.createElement('h4');
            userIdsH4.textContent = 'User IDs:';
            userIdsDiv.appendChild(userIdsH4);
            const userIdListUl = document.createElement('ul');
            userIdListUl.className = 'user-id-list';
            userIdsDiv.appendChild(userIdListUl); // ul will be populated by renderUserIds
            const addUserIdBtn = document.createElement('button');
            addUserIdBtn.className = 'add-btn';
            addUserIdBtn.textContent = 'Add User ID';
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
        });
    }
}

/**
 * Toggles the visibility of address details.
 * @param {string} addressId - The ID of the address.
 */
function toggleAddressDetails(addressId) {
    const detailsElement = document.getElementById(`details-${addressId}`);
    detailsElement.classList.toggle('show');
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

            const removePersonBtn = document.createElement('button');
            removePersonBtn.className = 'remove-btn';
            removePersonBtn.textContent = '-';
            removePersonBtn.title = `Remove user ${person.username}`;
            removePersonBtn.addEventListener('click', () => removeUserId(address.id, person.id));
            li.appendChild(removePersonBtn);

            const personDetailsSpan = document.createElement('span');
            personDetailsSpan.textContent = `${person.username} (Player ID: ${person.playerId})`;
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

            const removeCodeBtn = document.createElement('button');
            removeCodeBtn.className = 'remove-btn';
            removeCodeBtn.textContent = '-';
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
async function addCommunity() {
    if (communities.length >= 8) {
        alert('Maximum number of communities reached');
        return;
    }
    const name = prompt('Enter community name (no spaces allowed):');
    if (name) {
        if (name.includes(' ')) {
            alert('Community name cannot contain spaces. Please try again.');
            return;
        }
        try {
            const response = await fetch('/api/communities', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ name }),
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
            } else {
                throw new Error('Invalid server response');
            }
        } catch (error) {
            console.error('Error adding community:', error);
            alert(error.message || 'An error occurred while adding the community');
        }
    }
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
 * Adds a new address to the selected community.
 */
async function addAddress() {
    if (!selectedCommunity) return;
    const street = prompt('Enter address:');
    if (street) {
        try {
            const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ street }),
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
        } catch (error) {
            console.error('Error adding address:', error);
            alert('Failed to add address. Please try again.');
        }
    }
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
 * Adds a new user ID to an address.
 * @param {string} addressId - The ID of the address.
 */
async function addUserId(addressId) {
    const address = selectedCommunity.addresses.find(a => a.id === addressId);
    if (!address) return;
    const username = prompt('Enter username:');
    const playerId = prompt('Enter player ID:');
    if (username && playerId) {
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
            } else {
                console.error('Failed to add user ID:', response.statusText);
            }
        } catch (error) {
            console.error('Error adding user ID:', error);
        }
    }
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
 * Adds a new code to an address.
 * @param {string} addressId - The ID of the address.
 */
async function addCode(addressId) {
    const address = selectedCommunity.addresses.find(a => a.id === addressId);
    if (!address) return;
    const description = prompt('Enter code description:');
    const code = prompt('Enter code:');
    const expiresAt = prompt('Enter expiration date and time (YYYY-MM-DD HH:MM):');
    if (description && code && expiresAt) {
        try {
            const response = await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/codes`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ description, code, expiresAt: new Date(expiresAt).toISOString() }),
                credentials: 'include'
            });
            if (response.ok) {
                const newCode = await response.json();
                if (!address.codes) {
                    address.codes = [];
                }
                address.codes.push(newCode);
                renderCodes(address);
            } else {
                console.error('Failed to add code:', response.statusText);
            }
        } catch (error) {
            console.error('Error adding code:', error);
        }
    }
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
        allowedUsersManagement.style.display = selectedCommunity ? 'block' : 'none';
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

// Fetch initial CSRF token and data (already set up in DOMContentLoaded above)
fetchData();
