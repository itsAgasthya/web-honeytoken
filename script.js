document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault();
    alert('You are accessing the honeypot web!!!');
});

document.getElementById('forgotPassword').addEventListener('click', function(event) {
    event.preventDefault();
    // Hide the login container (which includes the form and the link)
    document.getElementById('loginContainer').style.display = 'none';
    // Show the forgot password container
    document.getElementById('forgotPasswordContainer').style.display = 'block';
});

document.getElementById('forgotPasswordForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    alert(`A code has been sent to ${email}`);
    // Hide the forgot password container
    document.getElementById('forgotPasswordContainer').style.display = 'none';
    // Show the reset password container
    document.getElementById('resetPasswordContainer').style.display = 'block';
});

document.getElementById('resetPasswordForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    alert(`Your password has been reset to: ${newPassword}`);
    // Hide the reset password container
    document.getElementById('resetPasswordContainer').style.display = 'none';
    // Show the login container again
    document.getElementById('loginContainer').style.display = 'block';
});