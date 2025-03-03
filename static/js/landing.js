document.getElementById('authForm').addEventListener('submit', function (e) {
    e.preventDefault();

    // Get form values
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Send login request to the backend
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    })
    .then(response => {
        if (response.ok) {
            // Redirect to the capture page after successful login
            window.location.href = "/capture";
        } else {
            // Display error message if login fails
            alert("Invalid credentials. Please try again.");
        }
    })
    .catch(error => {
        console.error('Error during login:', error);
        alert("An error occurred. Please try again.");
    });
});

// Redirect to the signup page when the "Signup" link is clicked
document.getElementById('toggleSignup').addEventListener('click', function (e) {
    e.preventDefault();
    window.location.href = "/signup"; // Redirect to the signup page
});