import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

document.getElementById('register-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = document.getElementById('register-email').value;

    // Fetch registration options from the server
    const response = await fetch('/webauthn/register/generate-options', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
    });
    const options = await response.json();

    // Start the registration process
    const registrationResponse = await startRegistration(options);

    // Send the registration response to the server for verification
    await fetch('/webauthn/register/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, response: registrationResponse })
    });
});

document.getElementById('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = document.getElementById('login-email').value;

    // Fetch authentication options from the server
    const response = await fetch('/webauthn/authenticate/generate-options', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
    });
    const options = await response.json();

    // Start the authentication process
    const authenticationResponse = await startAuthentication(options);

    // Send the authentication response to the server for verification
    await fetch('/webauthn/authenticate/verify', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, response: authenticationResponse })
    });
});