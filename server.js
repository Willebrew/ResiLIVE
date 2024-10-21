/**
 * @file server.js
 * @description This file contains the main server code for the application, including routes, middleware, and utility functions.
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs').promises;
const RateLimit = require('express-rate-limit');
const lusca = require('lusca');
const accessLogsFile = path.join(__dirname, 'access_logs.json');
const app = express();
const port = 3000;
const lastAccessTimes = {};

// Rate limiter setup: maximum of 100 requests per 15 minutes
const limiter = RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // max 100 requests per windowMs
});

// Middleware setup
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true, httpOnly: true }
}));
app.use(lusca.csrf());

// Route to serve the main API data file
app.get('/api', (req, res) => {
    res.sendFile(path.join(__dirname, 'data.json'));
});

const dataFile = path.join(__dirname, 'data.json');
const usersFile = path.join(__dirname, 'users.json');

/**
 * Reads data from a specified file.
 * @param {string} file - The path to the file.
 * @returns {Promise<Object>} The parsed JSON data from the file.
 */
async function readData(file) {
    try {
        const data = await fs.readFile(file, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return { communities: [] };
        }
        throw error;
    }
}

/**
 * Writes data to a specified file.
 * @param {string} file - The path to the file.
 * @param {Object} data - The data to write to the file.
 */
async function writeData(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

/**
 * Handles errors by logging them and sending a response with a 500 status code.
 * @param {Object} res - The response object.
 * @param {Error} error - The error object.
 * @param {string} message - The error message to send in the response.
 */
function errorHandler(res, error, message) {
    console.error(`${message}:`, error);
    res.status(500).json({ error: message });
}

/**
 * Middleware to require authentication.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 */
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

/**
 * Middleware to require admin access.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Function} next - The next middleware function.
 */
function requireAdmin(req, res, next) {
    if (req.session.userId && req.session.userRole === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }
}

// Route to register a new user
app.post('/api/register', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;
        let users = await readData(usersFile);

        if (!users.users) {
            users.users = [];
        }

        if (users.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: Date.now().toString(), username, password: hashedPassword, role: 'user' };
        users.users.push(newUser);
        await writeData(usersFile, users);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error registering user');
    }
});

/**
 * Adds a community to the access logs.
 * @param {string} communityName - The name of the community.
 */
async function addCommunityToAccessLogs(communityName) {
    try {
        let logs = await readData(accessLogsFile);
        if (!logs.communities) {
            logs.communities = [];
        }
        if (!logs.communities.some(c => c.name === communityName)) {
            logs.communities.push({ name: communityName, logs: [] });
            await writeData(accessLogsFile, logs);
        }
    } catch (error) {
        console.error('Error adding community to access logs:', error);
    }
}

/**
 * Removes a community from the access logs.
 * @param {string} communityName - The name of the community.
 */
async function removeCommunityFromAccessLogs(communityName) {
    try {
        let logs = await readData(accessLogsFile);
        if (logs.communities) {
            logs.communities = logs.communities.filter(c => c.name !== communityName);
            await writeData(accessLogsFile, logs);
        }
    } catch (error) {
        console.error('Error removing community from access logs:', error);
    }
}

// Route to log in a user
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = await readData(usersFile);
        const user = users.users.find(u => u.username === username);

        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.userRole = user.role;
            res.json({ message: 'Logged in successfully' });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error logging in');
    }
});

// Route to log out a user
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            errorHandler(res, err, 'Error logging out');
        } else {
            res.json({ message: 'Logged out successfully' });
        }
    });
});

// Route to add a new community
app.post('/api/communities', requireAuth, requireAdmin, async (req, res) => {
    try {
        const jsonData = await readData(dataFile);
        if (!jsonData.communities) jsonData.communities = [];

        if (jsonData.communities.length >= 9) {
            return res.status(400).json({ error: 'Maximum number of communities (9) reached' });
        }

        const newCommunity = {
            id: Date.now().toString(),
            name: req.body.name,
            addresses: [],
            allowedUsers: req.body.allowedUsers || []
        };

        jsonData.communities.push(newCommunity);
        await writeData(dataFile, jsonData);

        await addCommunityToAccessLogs(newCommunity.name);

        res.status(201).json(newCommunity);
    } catch (error) {
        errorHandler(res, error, 'Error adding community');
    }
});

// Route to delete a community
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const communityToRemove = jsonData.communities.find(community => community.id === req.params.id);
        if (communityToRemove) {
            jsonData.communities = jsonData.communities.filter(community => community.id !== req.params.id);
            await writeData(dataFile, jsonData);
            await removeCommunityFromAccessLogs(communityToRemove.name);
            res.sendStatus(204);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error removing community');
    }
});

// Route to get all communities visible to the authenticated user
app.get('/api/communities', requireAuth, async (req, res) => {
    try {
        const { communities } = await readData(dataFile);
        const visibleCommunities = communities.filter(community => {

            if (req.session.userRole === 'admin') return true;

            return community.allowedUsers.includes(req.session.username);
        });

        res.json(visibleCommunities || []);
    } catch (error) {
        errorHandler(res, error, 'Error reading communities');
    }
});

// Route to check if the user is authenticated
app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.json({ authenticated: true, username: req.session.username, role: req.session.userRole });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

// Route to add a new user by an admin
app.post('/api/admin/add-user', requireAuth, async (req, res) => {
    try {
        if (req.session.userRole !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
        }

        const { username, password } = req.body;
        let users = await readData(usersFile);

        if (!users.users) {
            users.users = [];
        }

        if (users.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: Date.now().toString(), username, password: hashedPassword };
        users.users.push(newUser);
        await writeData(usersFile, users);

        res.status(201).json({ message: 'User added successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error adding user');
    }
});

// Route to add a new community (duplicate, should be removed)
app.post('/api/communities', requireAuth, requireAdmin, async (req, res) => {
    try {
        const jsonData = await readData(dataFile);
        if (!jsonData.communities) jsonData.communities = [];
        const newCommunity = { id: Date.now().toString(), name: req.body.name, addresses: [], allowedUsers: [] };
        jsonData.communities.push(newCommunity);
        await writeData(dataFile, jsonData);
        res.status(201).json(newCommunity);
    } catch (error) {
        errorHandler(res, error, 'Error adding community');
    }
});

// Route to delete a community (duplicate, should be removed)
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        jsonData.communities = jsonData.communities.filter(community => community.id !== req.params.id);
        await writeData(dataFile, jsonData);
        res.sendStatus(204);
    } catch (error) {
        errorHandler(res, error, 'Error removing community');
    }
});

// Route to update allowed users for a community
app.put('/api/communities/:id/allowed-users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { allowedUsers } = req.body;
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.id);

        if (community) {
            community.allowedUsers = allowedUsers;
            await writeData(dataFile, jsonData);
            res.status(200).json({ message: 'Allowed users updated successfully' });
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error updating allowed users');
    }
});

// Route to get addresses for a community
app.get('/api/communities/:id/addresses', requireAuth, async (req, res) => {
    try {
        const jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.id);
        if (community) {
            res.json(community.addresses);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error reading addresses');
    }
});

// Route to add an address to a community
app.post('/api/communities/:id/addresses', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.id);
        if (community) {
            const newAddress = { id: Date.now().toString(), street: req.body.street, people: [] };
            community.addresses.push(newAddress);
            await writeData(dataFile, jsonData);
            res.status(201).json(newAddress);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error adding address');
    }
});

// Route to delete an address from a community
app.delete('/api/communities/:communityId/addresses/:addressId', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            community.addresses = community.addresses.filter(address => address.id !== req.params.addressId);
            await writeData(dataFile, jsonData);
            res.sendStatus(204);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error removing address');
    }
});

/**
 * Logs access to a community by a player.
 * @param {string} communityName - The name of the community.
 * @param {string} playerName - The name of the player.
 * @param {string} action - The action performed by the player.
 */
async function logAccess(communityName, playerName, action) {
    try {
        let logs = await readData(accessLogsFile);
        if (!logs[communityName]) {
            logs[communityName] = [];
        }
        logs[communityName].push({
            player: playerName,
            action: action,
            timestamp: new Date().toISOString()
        });
        await writeData(accessLogsFile, logs);
    } catch (error) {
        console.error('Error logging access:', error);
    }
}

// Route to log access to a community
app.post('/api/log-access', async (req, res) => {
    const { community, player, action } = req.body;

    console.log(`Received log access request for community: ${community}, player: ${player}, action: ${action}`);

    try {
        let logs = await readData(accessLogsFile);
        let jsonData = await readData(dataFile);
        let communityLog = logs.communities.find(c => c.name === community);

        const communityExists = jsonData.communities.some(c => c.name === community);

        if (!communityExists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        if (!logs.communities) {
            logs.communities = [];
        }

        if (!communityLog) {
            communityLog = { name: community, logs: [] };
            logs.communities.push(communityLog);
        }

        const currentTime = Date.now();
        const lastAccessKey = `${community}-${player}`;
        const lastAccessTime = lastAccessTimes[lastAccessKey] || 0;

        if (currentTime - lastAccessTime < 5000) {
            return res.status(429).json({ error: 'Access attempt too soon. Please wait 5 seconds between attempts.' });
        }

        lastAccessTimes[lastAccessKey] = currentTime;

        communityLog.logs.push({
            player: player,
            action: action,
            timestamp: new Date().toISOString()
        });

        await writeData(accessLogsFile, logs);
        res.status(200).json({ message: 'Access logged successfully' });
    } catch (error) {
        console.error('Error logging access:', error);
        res.status(500).json({ error: 'Error logging access' });
    }
});

// Route to add a person to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/people', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address) {
                const newPerson = { id: Date.now().toString(), username: req.body.username, playerId: req.body.playerId };
                address.people.push(newPerson);
                await writeData(dataFile, jsonData);
                res.status(201).json(newPerson);
            } else {
                res.status(404).json({ error: 'Address not found' });
            }
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error adding person');
    }
});

// Route to delete a person from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/people/:personId', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address) {
                address.people = address.people.filter(person => person.id !== req.params.personId);
                await writeData(dataFile, jsonData);
                res.sendStatus(204);
            } else {
                res.status(404).json({ error: 'Address not found' });
            }
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error removing person');
    }
});

// Route to add a code to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/codes', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address) {
                const newCode = {
                    id: Date.now().toString(),
                    description: req.body.description,
                    code: req.body.code,
                    expiresAt: req.body.expiresAt
                };
                if (!address.codes) {
                    address.codes = [];
                }
                address.codes.push(newCode);
                await writeData(dataFile, jsonData);
                res.status(201).json(newCode);
            } else {
                res.status(404).json({ error: 'Address not found' });
            }
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error adding code');
    }
});

// Route to delete a code from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/codes/:codeId', requireAuth, async (req, res) => {
    try {
        let jsonData = await readData(dataFile);
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address && address.codes) {
                address.codes = address.codes.filter(code => code.id !== req.params.codeId);
                await writeData(dataFile, jsonData);
                res.sendStatus(204);
            } else {
                res.status(404).json({ error: 'Address or codes not found' });
            }
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error removing code');
    }
});

// Route to get logs for a community
app.get('/api/communities/:name/logs', requireAuth, async (req, res) => {
    const communityName = req.params.name;
    try {
        const logs = await readData(accessLogsFile);
        const communityLog = logs.communities.find(c => c.name === communityName);

        if (communityLog) {
            res.json(communityLog.logs);
        } else {
            res.status(404).json({ error: 'Community logs not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error retrieving logs');
    }
});

/**
 * Removes expired codes from all addresses in all communities.
 *
 * This function reads the data from the specified data file, iterates through all communities and their addresses,
 * and filters out any codes that have expired. If any expired codes are found and removed, the updated data is written
 * back to the data file. The function logs a message to the console if expired codes are removed.
 *
 * @async
 * @function removeExpiredCodes
 * @returns {Promise<void>}
 */
async function removeExpiredCodes() {
    try {
        let jsonData = await readData(dataFile);
        const now = new Date();
        let codesRemoved = false;

        jsonData.communities.forEach(community => {
            community.addresses.forEach(address => {
                if (address.codes) {
                    const initialLength = address.codes.length;
                    address.codes = address.codes.filter(code => new Date(code.expiresAt) > now);
                    if (address.codes.length < initialLength) {
                        codesRemoved = true;
                    }
                }
            });
        });

        if (codesRemoved) {
            await writeData(dataFile, jsonData);
            console.log('Expired codes removed');
        }
    } catch (error) {
        console.error('Error removing expired codes:', error);
    }
}

// Set interval to remove expired codes every 60 seconds
setInterval(removeExpiredCodes, 60000);

// Route to serve the main API data file
app.get('/api', (req, res) => {
    res.sendFile(path.join(__dirname, 'data.json'));
});

// Route to serve the login page
app.get('/', limiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to serve the login page
app.get('/login.html', limiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to serve the index page
app.get('/index.html', requireAuth, limiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
