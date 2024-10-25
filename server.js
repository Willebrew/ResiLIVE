/**
 * @file server.js
 * @description This file contains the main server code for the application, including routes, middleware, and utility functions.
 */
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt');
const path = require('path');
const RateLimit = require('express-rate-limit');
const lusca = require('lusca');
const app = express();
const port = 3000;
const cors = require('cors');
const lastAccessTimes = {};

// Initialize Firebase
admin.initializeApp({
    credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL
    })
});

// Create the Firestore instance
const db = admin.firestore();

// Initialize collections after the database is created
const collections = {
    users: db.collection('users'),
    communities: db.collection('communities'),
    accessLogs: db.collection('access_logs')
};

// Rate limiter setup: maximum of 100 requests per 15 minutes
const limiter = RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // max 100 requests per windowMs
});

app.set('trust proxy', 1);

// Middleware setup
app.use(express.json());
app.use(express.static('public', {
    index: false
}));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true } // SET TO FALSE FOR DEBUGGING
}));

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

// Apply CSRF protection to all other routes
app.use((req, res, next) => {
    if (req.path !== '/api/log-access') {
        lusca.csrf()(req, res, next);
    } else {
        next();
    }
});

// Route to get CSRF token
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

/**
 * Reads data from a specified file.
 * @param {string} collection - The path to the file.
 * @returns {Promise<Object>} The parsed JSON data from the file.
 */
async function readData(collection) {
    try {
        const snapshot = await collections[collection].get();
        const data = {};
        data[collection] = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));
        return data;
    } catch (error) {
        console.error(`Error reading ${collection}:`, error);
        return { [collection]: [] };
    }
}

/**
 * Writes data to a specified file.
 * @param {string} collection - The path to the file.
 * @param {Object} data - The data to write to the file.
 */
async function writeData(collection, data) {
    try {
        const batch = db.batch();

        // Delete existing data
        const existingDocs = await collections[collection].get();
        existingDocs.docs.forEach(doc => {
            batch.delete(doc.ref);
        });

        // Add new data
        data[collection].forEach(item => {
            const docRef = collections[collection].doc(item.id);
            batch.set(docRef, item);
        });

        await batch.commit();
    } catch (error) {
        console.error(`Error writing to ${collection}:`, error);
        throw error;
    }
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
    if (req.session.userId && (req.session.userRole === 'admin' || req.session.userRole === 'superuser')) {
        next();
    } else {
        res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }
}

// Route to register a new user
app.post('/api/register', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;
        const usersRef = db.collection('users');

        const existingUser = await usersRef
            .where('username', '==', username.toLowerCase())
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: Date.now().toString(),
            username,
            password: hashedPassword,
            role: 'user'
        };

        await usersRef.doc(newUser.id).set(newUser);
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
        let logs = await readData('access_logs');
        if (!logs.communities) {
            logs.communities = [];
        }
        if (!logs.communities.some(c => c.name === communityName)) {
            logs.communities.push({ name: communityName, logs: [] });
            await writeData('access_logs', logs);
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
        let logs = await readData('access_logs');
        if (logs.communities) {
            logs.communities = logs.communities.filter(c => c.name !== communityName);
            await writeData('access_logs', logs);
        }
    } catch (error) {
        console.error('Error removing community from access logs:', error);
    }
}

// Route to log in a user
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Query Firestore for the user
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('username', '==', username.toLowerCase()).get();

        if (snapshot.empty) {
            console.log('User not found:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();

        // Compare password
        const isValidPassword = await bcrypt.compare(password, userData.password);

        if (!isValidPassword) {
            console.log('Invalid password for user:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Set session data
        req.session.userId = userDoc.id;
        req.session.username = userData.username;
        req.session.userRole = userData.role;

        // Save session
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'Error creating session' });
            }
            res.json({
                message: 'Logged in successfully',
                user: {
                    username: userData.username,
                    role: userData.role
                }
            });
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error during login' });
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
        // Get all communities to check count
        const snapshot = await db.collection('communities').get();
        if (snapshot.size >= 8) {
            return res.status(400).json({ error: 'Maximum number of communities (8) reached' });
        }

        // Create new community
        const newCommunity = {
            name: req.body.name,
            addresses: [],
            allowedUsers: req.body.allowedUsers || [],
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        // Add to Firestore and get the reference
        const docRef = await db.collection('communities').add(newCommunity);

        // Get the created document
        const createdDoc = await docRef.get();
        const communityData = {
            id: docRef.id,
            ...createdDoc.data()
        };

        // Return the complete community data
        res.status(201).json({
            message: 'Community added successfully',
            community: communityData
        });
    } catch (error) {
        console.error('Error adding community:', error);
        res.status(500).json({ error: 'Error adding community' });
    }
});

// Route to delete a community
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const communityName = communityData.name;

        // Start a batch write
        const batch = db.batch();

        // Delete the community
        batch.delete(communityRef);

        // Get all access logs for this community
        const logsSnapshot = await db.collection('access_logs')
            .where('community', '==', communityName)
            .get();

        // Add all log deletions to the batch
        logsSnapshot.docs.forEach(doc => {
            batch.delete(doc.ref);
        });

        // Commit the batch (deletes community and all its logs atomically)
        await batch.commit();

        res.status(200).json({ message: 'Community and associated logs deleted successfully' });
    } catch (error) {
        console.error('Error deleting community:', error);
        res.status(500).json({ error: 'Error deleting community' });
    }
});

// Route to get all communities visible to the authenticated user
app.get('/api/communities', requireAuth, async (req, res) => {
    try {
        const snapshot = await db.collection('communities').get();
        const communities = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // Filter communities based on user role
        const visibleCommunities = communities.filter(community => {
            if (req.session.userRole === 'admin' || req.session.userRole === 'superuser') {
                return true;
            }
            return community.allowedUsers.includes(req.session.username);
        });

        res.json(visibleCommunities);
    } catch (error) {
        console.error('Error fetching communities:', error);
        res.status(500).json({ error: 'Error fetching communities' });
    }
});

// Route to check if the user is authenticated
app.get('/api/check-auth', (req, res) => {
    if (req.session.userId) {
        res.json({
            authenticated: true,
            userId: req.session.userId,
            username: req.session.username,
            role: req.session.userRole
        });
    } else {
        res.status(401).json({ authenticated: false });
    }
});

// Get all users (admin only)
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('users').get();
        const users = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            password: undefined
        }));
        res.json(users);
    } catch (error) {
        errorHandler(res, error, 'Error fetching users');
    }
});

// Add a new user (admin only)
app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username, password } = req.body;

        const existingUser = await db.collection('users')
            .where('username', '==', username.toLowerCase())
            .get();

        if (!existingUser.empty) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            username: username.toLowerCase(),
            password: hashedPassword,
            role: 'user',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        const docRef = await db.collection('users').add(newUser);
        res.status(201).json({ message: 'User added successfully', id: docRef.id });
    } catch (error) {
        errorHandler(res, error, 'Error adding user');
    }
});

// Remove a user (admin only)
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const userRef = db.collection('users').doc(req.params.id);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userData = userDoc.data();

        // Prevent removal of superuser
        if (userData.role === 'superuser') {
            return res.status(403).json({ error: 'Cannot remove superuser account' });
        }

        // Remove user from all communities' allowedUsers arrays
        const communitiesSnapshot = await db.collection('communities').get();
        const batch = db.batch();

        communitiesSnapshot.docs.forEach(doc => {
            const community = doc.data();
            if (community.allowedUsers && community.allowedUsers.includes(userData.username)) {
                const updatedAllowedUsers = community.allowedUsers.filter(
                    username => username !== userData.username
                );
                batch.update(doc.ref, { allowedUsers: updatedAllowedUsers });
            }
        });

        // Delete the user
        batch.delete(userRef);

        // Commit all changes
        await batch.commit();

        res.json({
            message: 'User removed successfully',
            updatedCommunities: communitiesSnapshot.docs
                .map(doc => ({
                    id: doc.id,
                    ...doc.data()
                }))
                .filter(community => community.allowedUsers &&
                    community.allowedUsers.includes(userData.username))
        });

    } catch (error) {
        console.error('Error removing user:', error);
        res.status(500).json({ error: 'Error removing user' });
    }
});

// Route to add a new user by an admin
app.post('/api/admin/add-user', requireAuth, async (req, res) => {
    try {
        if (req.session.userRole !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
        }

        const { username, password } = req.body;
        let users = await readData('users');

        if (!users.users) {
            users.users = [];
        }

        if (users.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { id: Date.now().toString(), username, password: hashedPassword };
        users.users.push(newUser);
        await writeData('users', users);

        res.status(201).json({ message: 'User added successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error adding user');
    }
});

app.post('/api/change-password', requireAuth, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const users = await readData('users');
        const user = users.users.find(u => u.id === req.session.userId);

        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await writeData('users', users);
        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error changing password');
    }
});

// Route to delete a community (duplicate, should be removed)
app.delete('/api/communities/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await db.collection('communities').doc(req.params.id).delete();
        res.sendStatus(204);
    } catch (error) {
        errorHandler(res, error, 'Error removing community');
    }
});

// Route to update allowed users for a community
app.put('/api/communities/:id/allowed-users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { allowedUsers } = req.body;
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        // Get all users to validate against
        const usersSnapshot = await db.collection('users').get();
        const users = usersSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        const validUsers = [];
        const invalidUsers = [];

        // Convert allowedUsers to lowercase for comparison
        const normalizedAllowedUsers = allowedUsers.map(username => username.toLowerCase());

        // Validate each user
        for (const username of normalizedAllowedUsers) {
            // Find user case-insensitively but keep original case in database
            const user = users.find(u => u.username.toLowerCase() === username);
            if (user && user.role !== 'admin' && user.role !== 'superuser') {
                // Add the original username case from the database
                if (!validUsers.includes(user.username)) {
                    validUsers.push(user.username);
                }
            } else {
                invalidUsers.push(username);
            }
        }

        // Update the community with valid users
        await communityRef.update({
            allowedUsers: validUsers,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        if (invalidUsers.length > 0) {
            res.status(200).json({
                warning: `The following users were not added: ${invalidUsers.join(', ')}`,
                validUsers
            });
        } else {
            res.status(200).json({
                message: 'Allowed users updated successfully',
                validUsers
            });
        }
    } catch (error) {
        console.error('Error updating allowed users:', error);
        res.status(500).json({ error: 'Error updating allowed users' });
    }
});

// Route to toggle user role (admin only)
app.put('/api/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
    try {
        const targetUserId = req.params.id;

        // Prevent self-modification
        if (targetUserId === req.session.userId) {
            return res.status(403).json({ error: 'Cannot modify your own role' });
        }

        // Get user document reference
        const userRef = db.collection('users').doc(targetUserId);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(404).json({ error: 'User not found' });
        }

        const userData = userDoc.data();

        // Prevent modifying superuser
        if (userData.role === 'superuser') {
            return res.status(403).json({ error: 'Cannot modify superuser role' });
        }

        // Toggle role
        const newRole = userData.role === 'admin' ? 'user' : 'admin';

        // Update user role
        await userRef.update({ role: newRole });

        // If user is being made admin, remove them from all communities' allowed users
        if (newRole === 'admin') {
            const communitiesSnapshot = await db.collection('communities').get();
            const batch = db.batch();

            communitiesSnapshot.docs.forEach(doc => {
                const community = doc.data();
                if (community.allowedUsers && community.allowedUsers.includes(userData.username)) {
                    const updatedAllowedUsers = community.allowedUsers.filter(
                        username => username !== userData.username
                    );
                    batch.update(doc.ref, { allowedUsers: updatedAllowedUsers });
                }
            });

            await batch.commit();
        }

        res.json({
            message: 'User role updated successfully',
            newRole: newRole,
            username: userData.username
        });
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Error updating user role' });
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
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const addresses = communityData.addresses || [];

        // Create new address
        const newAddress = {
            id: Date.now().toString(),
            street: req.body.street,
            people: [],
            codes: [],
            createdAt: new Date().toISOString() // Use ISO string instead of serverTimestamp
        };

        // Add new address to the array
        addresses.push(newAddress);

        // Update the community document with the new addresses array
        await communityRef.update({
            addresses: addresses,
            updatedAt: admin.firestore.FieldValue.serverTimestamp() // Add timestamp to the root document
        });

        // Return the new address
        res.status(201).json(newAddress);
    } catch (error) {
        console.error('Error adding address:', error);
        res.status(500).json({ error: 'Error adding address' });
    }
});

// Route to delete an address from a community
app.delete('/api/communities/:id/addresses/:addressId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.id);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const addresses = communityData.addresses || [];

        // Filter out the address to delete
        const updatedAddresses = addresses.filter(addr => addr.id !== req.params.addressId);

        // Update the community document with the new addresses array
        await communityRef.update({
            addresses: updatedAddresses,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: 'Address deleted successfully' });
    } catch (error) {
        console.error('Error deleting address:', error);
        res.status(500).json({ error: 'Error deleting address' });
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
        await db.collection('access_logs').add({
            community: communityName,
            player: playerName,
            action: action,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
    } catch (error) {
        console.error('Error logging access:', error);
    }
}

// Route to log access to a community
app.post('/api/log-access', async (req, res) => {
    const { community, player, action } = req.body;

    try {
        const communityRef = await db.collection('communities')
            .where('name', '==', community)
            .get();

        if (communityRef.empty) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const currentTime = Date.now();
        const lastAccessKey = `${community}-${player}`;
        const lastAccessTime = lastAccessTimes[lastAccessKey] || 0;

        if (currentTime - lastAccessTime < 5000) {
            return res.status(429).json({ error: 'Access attempt too soon. Please wait 5 seconds between attempts.' });
        }

        lastAccessTimes[lastAccessKey] = currentTime;

        await db.collection('access_logs').add({
            community,
            player,
            action,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ message: 'Access logged successfully' });
    } catch (error) {
        errorHandler(res, error, 'Error logging access');
    }
});

// Route to add a person to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/people', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        const newPerson = {
            id: Date.now().toString(),
            username: req.body.username,
            playerId: req.body.playerId
        };

        // Add the new person to the address's people array
        if (!address.people) {
            address.people = [];
        }
        address.people.push(newPerson);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(201).json(newPerson);
    } catch (error) {
        console.error('Error adding person:', error);
        res.status(500).json({ error: 'Error adding person' });
    }
});

// Route to delete a person from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/people/:personId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        // Remove the person from the address's people array
        address.people = address.people.filter(person => person.id !== req.params.personId);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(200).json({ message: 'Person removed successfully' });
    } catch (error) {
        console.error('Error removing person:', error);
        res.status(500).json({ error: 'Error removing person' });
    }
});

// Route to add a code to an address in a community
app.post('/api/communities/:communityId/addresses/:addressId/codes', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address) {
            return res.status(404).json({ error: 'Address not found' });
        }

        const newCode = {
            id: Date.now().toString(),
            description: req.body.description,
            code: req.body.code,
            expiresAt: req.body.expiresAt
        };

        // Add the new code to the address's codes array
        if (!address.codes) {
            address.codes = [];
        }
        address.codes.push(newCode);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(201).json(newCode);
    } catch (error) {
        console.error('Error adding code:', error);
        res.status(500).json({ error: 'Error adding code' });
    }
});

// Route to delete a code from an address in a community
app.delete('/api/communities/:communityId/addresses/:addressId/codes/:codeId', requireAuth, async (req, res) => {
    try {
        const communityRef = db.collection('communities').doc(req.params.communityId);
        const communityDoc = await communityRef.get();

        if (!communityDoc.exists) {
            return res.status(404).json({ error: 'Community not found' });
        }

        const communityData = communityDoc.data();
        const address = communityData.addresses.find(a => a.id === req.params.addressId);

        if (!address || !address.codes) {
            return res.status(404).json({ error: 'Address or codes not found' });
        }

        // Remove the code from the address's codes array
        address.codes = address.codes.filter(code => code.id !== req.params.codeId);

        // Update the community document with the modified addresses array
        await communityRef.update({
            addresses: communityData.addresses
        });

        res.status(200).json({ message: 'Code removed successfully' });
    } catch (error) {
        console.error('Error removing code:', error);
        res.status(500).json({ error: 'Error removing code' });
    }
});

// Route to get logs for a community
app.get('/api/communities/:name/logs', requireAuth, async (req, res) => {
    const communityName = req.params.name;
    try {
        // Query Firestore for logs
        const logsSnapshot = await db.collection('access_logs')
            .where('community', '==', communityName)
            .orderBy('timestamp', 'desc')
            .limit(100) // Limit to last 100 logs
            .get();

        const logs = logsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            timestamp: doc.data().timestamp?.toDate() // Convert Firestore Timestamp to JS Date
        }));

        res.json(logs);
    } catch (error) {
        console.error('Error retrieving logs:', error);
        res.status(500).json({ error: 'Error retrieving logs' });
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
        let jsonData = await readData('communities');
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
            await writeData('communities', jsonData);
            console.log('Expired codes removed');
        }
    } catch (error) {
        console.error('Error removing expired codes:', error);
    }
}

// Set interval to remove expired codes every 60 seconds
setInterval(removeExpiredCodes, 60000);

// Route to serve the main API data file
app.get('/api', limiter, async (req, res) => {
    try {
        const snapshot = await db.collection('communities').get();
        const communities = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        res.json({ communities });
    } catch (error) {
        console.error('Error fetching communities:', error);
        res.status(500).json({ error: 'Error fetching data' });
    }
});

// Route to serve the login page
app.get('/', limiter, (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route to serve the login page
app.get('/login.html', limiter, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route to serve the index page
app.get('/index.html', limiter, (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
