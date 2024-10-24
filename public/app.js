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
 * @event
 */
document.addEventListener('DOMContentLoaded', async () => {
    await fetchCsrfToken();
});

/**
 * Fetches the CSRF token from the server and stores it in the csrfToken variable.
 * If a hidden input field with the ID 'csrfToken' exists, sets its value to the fetched CSRF token.
 * @async
 * @function fetchCsrfToken
 * @returns {Promise<void>}
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
 * Updates the username displayed in the UI.
 * @param {string} username - The username to display.
 */
function updateUserName(username) {
    const userNameSpan = document.querySelector('#userName span');
    if (userNameSpan) {
        userNameSpan.textContent = username || 'Guest';
    }
}

/**
 * Checks the login status of the user and updates the UI accordingly.
 * @async
 * @function checkLoginStatus
 * @returns {Promise<void>}
 */
async function checkLoginStatus() {
    try {
        const response = await fetch('/api/check-auth');
        if (response.ok) {
            const data = await response.json();
            currentUserId = data.userId;
            currentUsername = data.username;
            updateUserName(data.username);

            isAdmin = data.role === 'admin' || data.role === 'superuser';

            if (isAdmin) {
                document.getElementById('allowedUsersManagement').style.display = 'block';
            } else {
                document.getElementById('allowedUsersManagement').remove();
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
 * Event listener for the logout button click event.
 * @event
 */
document.addEventListener('DOMContentLoaded', checkLoginStatus);

/**
 * Fetches users from the server and updates the UI.
 * @returns {Promise<void>}
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
 * Toggles a user's role between admin and user
 * @async
 * @param {string} userId - The ID of the user to toggle role
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

                // If user was made admin, remove them from all communities' allowed users lists
                if (data.newRole === 'admin') {
                    const username = users[userIndex].username;
                    communities.forEach(community => {
                        community.allowedUsers = community.allowedUsers.filter(
                            allowedUser => allowedUser !== username
                        );
                    });

                    // Update the UI for the currently selected community
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
 * Filters users with the role 'user' and creates a user item for each.
 * Each user item includes the username and a button to remove the user.
 * @function renderUsers
 * @returns {void}
 */
function renderUsers() {
    const usersList = document.getElementById('usersList');
    usersList.innerHTML = '';
    users.forEach(user => {
        if (user.id !== currentUserId && user.role !== 'superuser') {
            const userElement = document.createElement('div');
            userElement.className = 'user-item';
            userElement.innerHTML = `
                <span>${user.username}</span>
                <div class="user-controls">
                    <button onclick="toggleUserRole('${user.id}')" 
                            class="role-btn ${user.role === 'admin' ? 'admin' : 'user'}" 
                            title="${user.role === 'admin' ? 'Remove admin' : 'Make admin'}">
                        ${user.role === 'admin' ? '👑' : '👤'}
                    </button>
                    <button onclick="removeUser('${user.id}')" class="remove-btn">-</button>
                </div>
            `;
            usersList.appendChild(userElement);
        }
    });
}

/**
 * Adds a new user by sending a POST request to the server with the provided username and password.
 * If the user is successfully added, fetches the updated list of users and clears the input fields.
 * @async
 * @function addUser
 * @returns {Promise<void>}
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
 * Removes a user by sending a DELETE request to the server with the provided user ID.
 * Prompts the user for confirmation before proceeding with the deletion.
 * If the user is successfully removed, fetches the updated list of users.
 * @async
 * @function removeUser
 * @param {string} userId - The ID of the user to be removed.
 * @returns {Promise<void>}
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
 * @async
 * @function fetchData
 * @returns {Promise<void>}
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
        if (communities.length > 0) {
            selectCommunity(communities[0].id);
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
 * @async
 * @function logout
 * @returns {Promise<void>}
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
 * Prompts the user for the current password, new password, and confirmation of the new password.
 * Sends a POST request to the server to change the password.
 * @returns {Promise<void>}
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

// Add event listener for the "Change Password" button
document.getElementById('changePasswordBtn').addEventListener('click', changePassword);

// Add event listener for the "Show Logs" button
document.addEventListener('DOMContentLoaded', function() {
    const showLogsBtn = document.getElementById('showLogsBtn');
    if (showLogsBtn) {
        showLogsBtn.addEventListener('click', function() {
            showLogs(selectedCommunity.name);
        });
    }
});

// Add event listener for the "Show Users" button
document.addEventListener('DOMContentLoaded', function() {
    const showLogsBtn = document.getElementById('showUsersBtn');
    if (showLogsBtn) {
        showLogsBtn.addEventListener('click', function() {
            showUsersPopup()
        });
    }
});

// Add event listener for the "Add User" button
document.addEventListener('DOMContentLoaded', function() {
    const addAddressBtn = document.getElementById('addAddressBtn');
    if (addAddressBtn) {
        addAddressBtn.addEventListener('click', addAddress);
    }
});

/**
 * Displays logs for a specific community.
 * @param {string} communityName - The name of the community to show logs for.
 */
function showLogs(communityName) {
    document.getElementById('logPopupTitle').textContent = `Logs for ${communityName}`;
    document.getElementById('logPopup').style.display = 'block';
    updateLogs(communityName);

    if (window.logUpdateInterval) {
        clearInterval(window.logUpdateInterval);
    }

    window.logUpdateInterval = setInterval(() => updateLogs(communityName), 5000);
}

/**
 * Displays users in the system.
 */
function showUsersPopup() {
    document.getElementById('usersPopup').style.display = 'block';
    fetchUsers();
}

/**
 * Closes the log popup and clears the log update interval.
 */
function closeLogPopup() {
    document.getElementById('logPopup').style.display = 'none';
    if (window.logUpdateInterval) {
        clearInterval(window.logUpdateInterval);
    }
}

/**
 * Closes the user popup.
 */
function closeUsersPopup() {
    document.getElementById('usersPopup').style.display = 'none';
}

/**
 * Fetches and updates logs for a specific community.
 * @async
 * @function updateLogs
 * @param {string} communityName - The name of the community to update logs for.
 * @returns {Promise<void>}
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

    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    logs.forEach(log => {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        const timestamp = new Date(log.timestamp).toLocaleString();
        logEntry.innerHTML = `
            <span class="timestamp">${timestamp}</span><br>
            <span class="player">${log.player}</span>: 
            <span class="action">${log.action}</span>
        `;
        logContent.appendChild(logEntry);
    });
}

document.getElementById('logoutBtn').addEventListener('click', logout);

/**
 * Renders the list of communities in the UI.
 * @function renderCommunities
 * @returns {void}
 */
function renderCommunities() {
    const communityList = document.getElementById('communityList');
    communityList.innerHTML = '';
    communities.forEach(community => {
        const li = document.createElement('li');
        li.innerHTML = `
            ${isAdmin ? `<button class="remove-btn" onclick="removeCommunity('${community.id}')">-</button>` : ''}
            <span>${community.name}</span>
        `;
        li.onclick = (event) => {
            if (event.target !== li.querySelector('.remove-btn')) {
                selectCommunity(community.id);
            }
        };
        if (selectedCommunity && community.id === selectedCommunity.id) {
            li.classList.add('active');
        }
        communityList.appendChild(li);
    });
}

/**
 * Selects a community by its ID and updates the UI.
 * @function selectCommunity
 * @param {string} communityId - The ID of the community to select.
 * @returns {void}
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
 * Renders the list of addresses for the selected community in the UI.
 * @function renderAddresses
 * @returns {void}
 */
function renderAddresses() {
    const addressList = document.getElementById('addressList');
    addressList.innerHTML = '';
    if (selectedCommunity && selectedCommunity.addresses) {
        selectedCommunity.addresses.forEach(address => {
            const li = document.createElement('li');
            li.className = 'address-item';
            li.innerHTML = `
                <div class="address-main">
                    <button class="remove-btn" onclick="removeAddress('${address.id}')">-</button>
                    <span class="address-text" onclick="toggleAddressDetails('${address.id}')">${address.street}</span>
                </div>
                <div class="address-details" id="details-${address.id}">
                    <div class="user-ids">
                        <h4>User IDs:</h4>
                        <ul class="user-id-list"></ul>
                        <button class="add-btn" onclick="addUserId('${address.id}')">+</button>
                    </div>
                    <div class="codes">
                        <h4>Codes:</h4>
                        <ul class="code-list"></ul>
                        <button class="add-btn" onclick="addCode('${address.id}')">+</button>
                    </div>
                </div>
            `;
            addressList.appendChild(li);
            renderUserIds(address);
            renderCodes(address);
        });
    }
}

/**
 * Toggles the visibility of address details.
 * @function toggleAddressDetails
 * @param {string} addressId - The ID of the address to toggle details for.
 * @returns {void}
 */
function toggleAddressDetails(addressId) {
    const detailsElement = document.getElementById(`details-${addressId}`);
    detailsElement.classList.toggle('show');
}

/**
 * Renders the list of user IDs for a given address in the UI.
 * @function renderUserIds
 * @param {Object} address - The address object containing user IDs.
 * @returns {void}
 */
function renderUserIds(address) {
    const userIdList = document.querySelector(`#details-${address.id} .user-id-list`);
    userIdList.innerHTML = '';
    if (address.people) {
        address.people.forEach(person => {
            const li = document.createElement('li');
            li.innerHTML = `
                <button class="remove-btn" onclick="removeUserId('${address.id}', '${person.id}')">-</button>
                <span>${person.username} (Player ID: ${person.playerId})</span>
            `;
            userIdList.appendChild(li);
        });
    }
}

/**
 * Renders the list of codes for a given address in the UI.
 * @function renderCodes
 * @param {Object} address - The address object containing codes.
 * @returns {void}
 */
function renderCodes(address) {
    const codeList = document.querySelector(`#details-${address.id} .code-list`);
    codeList.innerHTML = '';
    if (address.codes) {
        address.codes.forEach(code => {
            const li = document.createElement('li');
            li.innerHTML = `
                <button class="remove-btn" onclick="removeCode('${address.id}', '${code.id}')">-</button>
                <span>${code.description} (Code: ${code.code}, Expires: ${new Date(code.expiresAt).toLocaleString()})</span>
            `;
            codeList.appendChild(li);
        });
    }
}

/**
 * Adds a new community by prompting the user for a name and sending a POST request to the server.
 * @async
 * @function addCommunity
 * @returns {Promise<void>}
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

            if (response.ok) {
                const newCommunity = await response.json();
                communities.push(newCommunity);
                renderCommunities();
                selectCommunity(newCommunity.id);
                updateAddCommunityButtonVisibility();
            } else {
                const errorData = await response.json();
                alert(errorData.error || 'Failed to add community');
            }
        } catch (error) {
            console.error('Error adding community:', error);
            alert('An error occurred while adding the community');
        }
    }
}

/**
 * Removes a community by its ID after user confirmation and sends a DELETE request to the server.
 * @async
 * @function removeCommunity
 * @param {string} communityId - The ID of the community to remove.
 * @returns {Promise<void>}
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
                if (communities.length > 0) {
                    selectCommunity(communities[0].id);
                } else {
                    selectedCommunity = null;
                    renderAddresses();
                }
                updateAddCommunityButtonVisibility();
            } else {
                console.error('Failed to remove community:', response.statusText);
                alert('Failed to remove community. Please try again.');
            }
        } catch (error) {
            console.error('Error removing community:', error);
            alert('An error occurred while removing the community. Please try again.');
        }
    }
}

/**
 * Updates the visibility of the "Add Community" button based on the number of communities.
 * If the number of communities is less than the maximum allowed, the button is displayed.
 * If the number of communities is equal to or greater than the maximum allowed, the button is removed.
 * @function updateAddCommunityButtonVisibility
 * @returns {void}
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
 * Adds a new address to the selected community by prompting the user for a street name and sending a POST request to the server.
 * @async
 * @function addAddress
 * @returns {Promise<void>}
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

            if (response.ok) {
                const newAddress = await response.json();
                if (!selectedCommunity.addresses) {
                    selectedCommunity.addresses = [];
                }
                selectedCommunity.addresses.push(newAddress);
                renderAddresses();
            } else {
                console.error('Failed to add address:', response.statusText);
            }
        } catch (error) {
            console.error('Error adding address:', error);
        }
    }
}

/**
 * Removes an address from the selected community by its ID after user confirmation and sends a DELETE request to the server.
 * @async
 * @function removeAddress
 * @param {string} addressId - The ID of the address to remove.
 * @returns {Promise<void>}
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

            if (response.ok) {
                selectedCommunity.addresses = selectedCommunity.addresses.filter(a => a.id !== addressId);
                renderAddresses();
            } else {
                console.error('Failed to remove address:', response.statusText);
            }
        } catch (error) {
            console.error('Error removing address:', error);
        }
    }
}

/**
 * Adds a new user ID to an address by prompting the user for a username and player ID and sending a POST request to the server.
 * @async
 * @function addUserId
 * @param {string} addressId - The ID of the address to add the user ID to.
 * @returns {Promise<void>}
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
 * Removes a user ID from an address by its ID after user confirmation and sends a DELETE request to the server.
 * @async
 * @function removeUserId
 * @param {string} addressId - The ID of the address to remove the user ID from.
 * @param {string} userIdId - The ID of the user ID to remove.
 * @returns {Promise<void>}
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
 * Adds a new code to an address by prompting the user for a description, code, and expiration date and sending a POST request to the server.
 * @async
 * @function addCode
 * @param {string} addressId - The ID of the address to add the code to.
 * @returns {Promise<void>}
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
 * Removes a code from an address by its ID after user confirmation and sends a DELETE request to the server.
 * @async
 * @function removeCode
 * @param {string} addressId - The ID of the address to remove the code from.
 * @param {string} codeId - The ID of the code to remove.
 * @returns {Promise<void>}
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
 * Checks if a user exists in the system.
 * @async
 * @function checkUserExists
 * @param {string} username - The username to check.
 * @returns {Promise<boolean>} - True if the user exists, false otherwise.
 */
async function checkUserExists(username) {
    try {
        const response = await fetch(`/api/users/exists/${encodeURIComponent(username)}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include'
        });

        if (response.ok) {
            const data = await response.json();
            return data.exists;
        } else {
            console.error('Failed to check user existence:', response.statusText);
            return false;
        }
    } catch (error) {
        console.error('Error checking user existence:', error);
        return false;
    }
}

/**
 * Updates the list of allowed users for the selected community by sending a PUT request to the server.
 * @async
 * @function updateAllowedUsers
 * @returns {Promise<void>}
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
            alert(data.message);
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
 * Renders the list of allowed users for the selected community in the UI.
 * @function renderAllowedUsers
 * @returns {void}
 */
function renderAllowedUsers() {
    const allowedUsersDropdown = document.getElementById('allowedUsersDropdown');
    allowedUsersDropdown.innerHTML = '';

    if (selectedCommunity && selectedCommunity.allowedUsers) {
        selectedCommunity.allowedUsers.forEach(user => {
            const option = document.createElement('option');
            option.value = user;
            option.textContent = user;
            allowedUsersDropdown.appendChild(option);
        });
    }
    document.getElementById('allowedUsersManagement').style.display = selectedCommunity ? 'block' : 'none';
}

/**
 * Removes the selected allowed user from the list and updates the server.
 * @function removeAllowedUser
 * @returns {void}
 */
function removeAllowedUser() {
    const allowedUsersDropdown = document.getElementById('allowedUsersDropdown');

    Array.from(allowedUsersDropdown.selectedOptions).forEach(option => {
        selectedCommunity.allowedUsers = selectedCommunity.allowedUsers.filter(u => u !== option.value);
    });
    updateAllowedUsers();
}

/**
 * Removes the selected users from the allowed users list and updates the server.
 * @function removeSelectedUsers
 * @returns {void}
 */
function removeSelectedUsers() {
    const allowedUsersDropdown = document.getElementById('allowedUsersDropdown');

    Array.from(allowedUsersDropdown.selectedOptions).forEach(option => {
        selectedCommunity.allowedUsers = selectedCommunity.allowedUsers.filter(u => u !== option.value);
    });
    updateAllowedUsers();
}

if (isAdmin) {
    const addCommunityBtn = document.querySelector('.sidebar .add-btn');
    if (addCommunityBtn) {
        addCommunityBtn.addEventListener('click', addCommunity);
    }
}

document.addEventListener('DOMContentLoaded', fetchCsrfToken);
document.querySelector('main .add-btn').addEventListener('click', addAddress);

fetchData();
