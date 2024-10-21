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
            headers: { 'Content-Type': 'application/json' },
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
 * Handles the registration form submission.
 * Prevents the default form submission, retrieves the username and password,
 * sends a POST request to the /api/register endpoint, and handles the response.
 */
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (response.ok) {
            alert('Registration successful. Please log in.');
            showLoginForm();
        } else {
            const data = await response.json();
            alert(data.error || 'Error registering user');
        }
    } catch (error) {
        console.error('Error registering:', error);
    }
});

/**
 * Shows the registration form and hides the login form.
 * Prevents the default link behavior.
 */
document.getElementById('showRegister').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelector('.login-container').style.display = 'none';
    document.querySelector('.register-container').style.display = 'block';
});

/**
 * Shows the login form and hides the registration form.
 * Prevents the default link behavior.
 */
document.getElementById('showLogin').addEventListener('click', (e) => {
    e.preventDefault();
    showLoginForm();
});

/**
 * Displays the login form and hides the registration form.
 */
function showLoginForm() {
    document.querySelector('.login-container').style.display = 'block';
    document.querySelector('.register-container').style.display = 'none';
}
