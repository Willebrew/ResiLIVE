const form = document.getElementById('addPlayerForm');
const playerList = document.getElementById('playerList');

async function fetchPlayers() {
    try {
        const response = await fetch('/api/people');
        const players = await response.json();
        playerList.innerHTML = '';
        players.forEach(player => {
            const li = document.createElement('li');
            li.textContent = `${player.username} (Player ID: ${player.playerId})`;
            const deleteButton = document.createElement('button');
            deleteButton.textContent = 'Delete';
            deleteButton.classList.add('delete-btn');
            deleteButton.onclick = () => deletePlayer(player.id);
            li.appendChild(deleteButton);
            playerList.appendChild(li);
        });
    } catch (error) {
        console.error('Error fetching players:', error);
    }
}

async function addPlayer(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const playerId = document.getElementById('playerId').value;
    try {
        await fetch('/api/people', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, playerId })
        });
        form.reset();
        fetchPlayers();
    } catch (error) {
        console.error('Error adding player:', error);
    }
}

async function deletePlayer(id) {
    try {
        await fetch(`/api/people/${id}`, { method: 'DELETE' });
        fetchPlayers();
    } catch (error) {
        console.error('Error deleting player:', error);
    }
}

form.addEventListener('submit', addPlayer);
fetchPlayers();
