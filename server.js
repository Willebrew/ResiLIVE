const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static('public'));

const dataFile = path.join(__dirname, 'people.json');

// Get all players
app.get('/api/people', async (req, res) => {
    try {
        const data = await fs.readFile(dataFile, 'utf8');
        const people = JSON.parse(data);
        res.json(people);
    } catch (error) {
        console.error('Error reading data:', error);
        res.status(500).json({ error: 'Error reading data' });
    }
});

// Add a player
app.post('/api/people', async (req, res) => {
    try {
        const data = await fs.readFile(dataFile, 'utf8');
        const people = JSON.parse(data);
        const newPerson = { id: Date.now().toString(), ...req.body };
        people.push(newPerson);
        await fs.writeFile(dataFile, JSON.stringify(people, null, 2));
        res.status(201).json(newPerson);
    } catch (error) {
        console.error('Error adding person:', error);
        res.status(500).json({ error: 'Error adding person' });
    }
});

// Remove a player
app.delete('/api/people/:id', async (req, res) => {
    try {
        const data = await fs.readFile(dataFile, 'utf8');
        let people = JSON.parse(data);
        people = people.filter(person => person.id !== req.params.id);
        await fs.writeFile(dataFile, JSON.stringify(people, null, 2));
        res.sendStatus(204);
    } catch (error) {
        console.error('Error removing person:', error);
        res.status(500).json({ error: 'Error removing person' });
    }
});

app.get('/api', async (req, res) => {
    try {
        const data = await fs.readFile(dataFile, 'utf8');
        res.json(JSON.parse(data));
    } catch (error) {
        console.error('Error reading data:', error);
        res.status(500).json({ error: 'Error reading data' });
    }
});

// Send the main HTML file for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
