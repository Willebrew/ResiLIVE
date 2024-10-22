/**
 * Variable to store the CSRF token.
 * @type {string}
 */
let csrfToken;

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
    const response = await fetch('/csrf-token');
    if (!response.ok) {
        throw new Error('Failed to fetch CSRF token');
    }
    const data = await response.json();
    csrfToken = data.csrfToken; // Store the CSRF token
    // Optionally, set the token in a hidden input field
    document.getElementById('csrfToken').value = csrfToken;
}

/**
 * Handles the login form submission.
 * Prevents the default form submission, retrieves the username and password,
 * sends a POST request to the /api/login endpoint, and handles the response.
 */
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, // Use the stored token
            body: JSON.stringify({ username, password })
        });
        if (response.ok) {
            window.location.href = '/index.html';
        } else {
            alert('Invalid username or password');
        }
    } catch (error) {
        console.error('Error logging in:', error);
    }
});

/**
 * Displays the login form and hides the registration form.
 */
function showLoginForm() {
    document.querySelector('.login-container').style.display = 'block';
    document.querySelector('.register-container').style.display = 'none';
}
