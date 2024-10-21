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
            updateUserName(data.username);

            console.log('User role:', data.role);

            isAdmin = data.role === 'admin';

            if (isAdmin) {
                document.getElementById('allowedUsersManagement').style.display = 'block';
            } else {
                document.getElementById('allowedUsersManagement').remove();
                const addCommunityBtn = document.getElementById('12');
                if (addCommunityBtn) addCommunityBtn.remove();
            }

            fetchData();
        } else {
            updateUserName('Guest');
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('Error checking login status:', error);
        updateUserName('Guest');
    }
}

document.addEventListener('DOMContentLoaded', checkLoginStatus);

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

        if (communities.length >= 9) {
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
        const response = await fetch('/api/logout', { method: 'POST' });
        if (response.ok) {
            window.location.href = '/login.html';
        } else {
            console.error('Logout failed');
        }
    } catch (error) {
        console.error('Error logging out:', error);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const showLogsBtn = document.getElementById('showLogsBtn');
    if (showLogsBtn) {
        showLogsBtn.addEventListener('click', function() {
            showLogs(selectedCommunity.name);
        });
    }
});

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
 * Closes the log popup and clears the log update interval.
 */
function closeLogPopup() {
    document.getElementById('logPopup').style.display = 'none';
    if (window.logUpdateInterval) {
        clearInterval(window.logUpdateInterval);
    }
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
console.log('User role:', data.role);

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
    if (communities.length >= 9) {
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
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
            await fetch(`/api/communities/${communityId}`, { method: 'DELETE' });
            communities = communities.filter(c => c.id !== communityId);
            renderCommunities();
            if (communities.length > 0) {
                selectCommunity(communities[0].id);
            } else {
                selectedCommunity = null;
                renderAddresses();
            }
            updateAddCommunityButtonVisibility();
        } catch (error) {
            console.error('Error removing community:', error);
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
    const MAX_COMMUNITIES = 9;
    const sidebarTop = document.querySelector('.sidebar-top');
    let addButton = document.getElementById('12');

    if (communities.length >= 9) {
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ street })
            });
            const newAddress = await response.json();
            if (!selectedCommunity.addresses) {
                selectedCommunity.addresses = [];
            }
            selectedCommunity.addresses.push(newAddress);
            renderAddresses();
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
            await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}`, { method: 'DELETE' });
            selectedCommunity.addresses = selectedCommunity.addresses.filter(a => a.id !== addressId);
            renderAddresses();
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, playerId })
            });
            const newUserId = await response.json();
            if (!address.people) {
                address.people = [];
            }
            address.people.push(newUserId);
            renderUserIds(address);
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
            await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/people/${userIdId}`, { method: 'DELETE' });
            address.people = address.people.filter(u => u.id !== userIdId);
            renderUserIds(address);
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
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description, code, expiresAt: new Date(expiresAt).toISOString() })
            });
            const newCode = await response.json();
            if (!address.codes) {
                address.codes = [];
            }
            address.codes.push(newCode);
            renderCodes(address);
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
            await fetch(`/api/communities/${selectedCommunity.id}/addresses/${addressId}/codes/${codeId}`, { method: 'DELETE' });
            address.codes = address.codes.filter(c => c.id !== codeId);
            renderCodes(address);
        } catch (error) {
            console.error('Error removing code:', error);
        }
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
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ allowedUsers: Array.from(allowedUsersSet) })
        });

        if (response.ok) {
            alert('Allowed users updated successfully');
            selectedCommunity.allowedUsers = Array.from(allowedUsersSet);
            renderAllowedUsers();
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.error}`);
        }
    } catch (error) {
        console.error('Error updating allowed users:', error);
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
document.querySelector('main .add-btn').addEventListener('click', addAddress);

fetchData();
