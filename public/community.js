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
 * Fetches community data from the server and updates the UI.
 * @async
 * @function fetchData
 * @returns {Promise<void>}
 */
async function fetchData() {
    try {
        const response = await fetch('/api/communities');
        communities = await response.json();
        renderCommunities();
        if (communities.length > 0) {
            selectCommunity(communities[0].id);
        }
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

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
            <button class="remove-btn" onclick="removeCommunity('${community.id}')">-</button>
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
    const name = prompt('Enter community name:');
    if (name) {
        try {
            const response = await fetch('/api/communities', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const newCommunity = await response.json();
            communities.push(newCommunity);
            renderCommunities();
            selectCommunity(newCommunity.id);
        } catch (error) {
            console.error('Error adding community:', error);
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
        } catch (error) {
            console.error('Error removing community:', error);
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

// Event listeners for adding community and address
document.querySelector('.sidebar .add-btn').addEventListener('click', addCommunity);
document.querySelector('main .add-btn').addEventListener('click', addAddress);

// Initial data fetch
fetchData();
