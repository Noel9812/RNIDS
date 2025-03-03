document.getElementById('signupForm').addEventListener('submit', function (e) {
    e.preventDefault();

    // Show loading spinner
    document.getElementById('submitText').classList.add('d-none');
    document.getElementById('loadingSpinner').classList.remove('d-none');

    // Get form values
    const fullname = document.getElementById('fullname').value;
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Clear previous error messages
    document.getElementById('emailError').textContent = '';
    document.getElementById('passwordError').textContent = '';

    // Validate email format
    if (!validateEmail(email)) {
        document.getElementById('emailError').textContent = 'Invalid email format';
        hideLoadingSpinner();
        return;
    }

    // Validate password strength
    if (!validatePassword(password)) {
        document.getElementById('passwordError').textContent = 'Password must be at least 8 characters long';
        hideLoadingSpinner();
        return;
    }

    // Send signup request to the backend
    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `fullname=${encodeURIComponent(fullname)}&email=${encodeURIComponent(email)}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    })
    .then(response => {
        if (response.ok) {
            // Show success message
            showMessage('Signup successful! Redirecting to login page...', 'success');
            setTimeout(() => {
                window.location.href = "/";
            }, 2000);
        } else {
            // Show error message
            showMessage('Signup failed. Please try again.', 'error');
        }
    })
    .catch(error => {
        console.error('Error during signup:', error);
        showMessage('An error occurred. Please try again.', 'error');
    })
    .finally(() => {
        hideLoadingSpinner();
    });
});

// Helper Functions
function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function validatePassword(password) {
    return password.length >= 8;
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `mt-3 text-center text-${type}`;
}

function hideLoadingSpinner() {
    document.getElementById('submitText').classList.remove('d-none');
    document.getElementById('loadingSpinner').classList.add('d-none');
}