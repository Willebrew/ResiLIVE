const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const app = express();
const port = 3000;
const dataFile = path.join(__dirname, 'data.json');

app.use(express.json());
app.use(express.static('public'));

/**
 * Reads data from the data file.
 * @async
 * @function readData
 * @returns {Promise<Object>} The parsed JSON data.
 */
async function readData() {
    const data = await fs.readFile(dataFile, 'utf8');
    return JSON.parse(data);
}

/**
 * Writes data to the data file.
 * @async
 * @function writeData
 * @param {Object} data - The data to write to the file.
 * @returns {Promise<void>}
 */
async function writeData(data) {
    await fs.writeFile(dataFile, JSON.stringify(data, null, 2));
}

/**
 * Handles errors by logging them and sending a response.
 * @function errorHandler
 * @param {Object} res - The response object.
 * @param {Error} error - The error object.
 * @param {string} message - The error message to send in the response.
 */
function errorHandler(res, error, message) {
    console.error(`${message}:`, error);
    res.status(500).json({ error: message });
}

/**
 * Endpoint to get all communities.
 * @name GET/api/communities
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.get('/api/communities', async (req, res) => {
    try {
        const { communities } = await readData();
        res.json(communities);
    } catch (error) {
        errorHandler(res, error, 'Error reading communities');
    }
});

/**
 * Endpoint to add a new community.
 * @name POST/api/communities
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.post('/api/communities', async (req, res) => {
    try {
        const jsonData = await readData();
        const newCommunity = { id: Date.now().toString(), name: req.body.name, addresses: [] };
        jsonData.communities.push(newCommunity);
        await writeData(jsonData);
        res.status(201).json(newCommunity);
    } catch (error) {
        errorHandler(res, error, 'Error adding community');
    }
});

/**
 * Endpoint to delete a community by ID.
 * @name DELETE/api/communities/:id
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.delete('/api/communities/:id', async (req, res) => {
    try {
        let jsonData = await readData();
        jsonData.communities = jsonData.communities.filter(community => community.id !== req.params.id);
        await writeData(jsonData);
        res.sendStatus(204);
    } catch (error) {
        errorHandler(res, error, 'Error removing community');
    }
});

/**
 * Endpoint to get addresses for a specific community.
 * @name GET/api/communities/:id/addresses
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.get('/api/communities/:id/addresses', async (req, res) => {
    try {
        const jsonData = await readData();
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

/**
 * Endpoint to add a new address to a specific community.
 * @name POST/api/communities/:id/addresses
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.post('/api/communities/:id/addresses', async (req, res) => {
    try {
        let jsonData = await readData();
        const community = jsonData.communities.find(c => c.id === req.params.id);
        if (community) {
            const newAddress = { id: Date.now().toString(), street: req.body.street, people: [] };
            community.addresses.push(newAddress);
            await writeData(jsonData);
            res.status(201).json(newAddress);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error adding address');
    }
});

/**
 * Endpoint to delete an address from a specific community.
 * @name DELETE/api/communities/:communityId/addresses/:addressId
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.delete('/api/communities/:communityId/addresses/:addressId', async (req, res) => {
    try {
        let jsonData = await readData();
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            community.addresses = community.addresses.filter(address => address.id !== req.params.addressId);
            await writeData(jsonData);
            res.sendStatus(204);
        } else {
            res.status(404).json({ error: 'Community not found' });
        }
    } catch (error) {
        errorHandler(res, error, 'Error removing address');
    }
});

/**
 * Endpoint to add a new person to an address.
 * @name POST/api/communities/:communityId/addresses/:addressId/people
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.post('/api/communities/:communityId/addresses/:addressId/people', async (req, res) => {
    try {
        let jsonData = await readData();
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address) {
                const newPerson = { id: Date.now().toString(), username: req.body.username, playerId: req.body.playerId };
                address.people.push(newPerson);
                await writeData(jsonData);
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

/**
 * Endpoint to delete a person from an address.
 * @name DELETE/api/communities/:communityId/addresses/:addressId/people/:personId
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.delete('/api/communities/:communityId/addresses/:addressId/people/:personId', async (req, res) => {
    try {
        let jsonData = await readData();
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address) {
                address.people = address.people.filter(person => person.id !== req.params.personId);
                await writeData(jsonData);
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

/**
 * Endpoint to add a new code to an address.
 * @name POST/api/communities/:communityId/addresses/:addressId/codes
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.post('/api/communities/:communityId/addresses/:addressId/codes', async (req, res) => {
    try {
        let jsonData = await readData();
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
                await writeData(jsonData);
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

/**
 * Endpoint to delete a code from an address.
 * @name DELETE/api/communities/:communityId/addresses/:addressId/codes/:codeId
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 */
app.delete('/api/communities/:communityId/addresses/:addressId/codes/:codeId', async (req, res) => {
    try {
        let jsonData = await readData();
        const community = jsonData.communities.find(c => c.id === req.params.communityId);
        if (community) {
            const address = community.addresses.find(a => a.id === req.params.addressId);
            if (address && address.codes) {
                address.codes = address.codes.filter(code => code.id !== req.params.codeId);
                await writeData(jsonData);
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

/**
 * Removes expired codes from all addresses.
 * @async
 * @function removeExpiredCodes
 * @returns {Promise<void>}
 */
async function removeExpiredCodes() {
    try {
        let jsonData = await readData();
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
            await writeData(jsonData);
            console.log('Expired codes removed');
        }
    } catch (error) {
        console.error('Error removing expired codes:', error);
    }
}

// Set an interval to remove expired codes every minute
setInterval(removeExpiredCodes, 60000);

/**
 * Endpoint to get the data file.
 * @name GET/api
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('/api', (req, res) => {
    res.sendFile(path.join(__dirname, 'data.json'));
});

/**
 * Endpoint to serve the main HTML file.
 * @name GET/*
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 */
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
