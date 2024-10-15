import React from 'react';
import { GoogleLogin } from '@react-oauth/google';
import { useNavigate } from 'react-router-dom';
import config from '../../config';

const Login = () => {
    const navigate = useNavigate();

    const handleLoginSuccess = (response) => {
        const { credential } = response;
    
        if (!credential) {
            console.error("Response does not contain a credential:", response);
            return;
        }
    
        fetch(`${config.apiEndpoint}/api/google-login`, {  // Use HTTPS
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                token: credential
            })
        })
        .then(response => response.json())
        .then(data => {
            // Store token and user data into local storage
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify({
                email: data.email,
                name: data.name
            }));
    

            navigate("/targets");
        })
        .catch(error => {
            console.error("Login failed:", error);
        });
    };

    const handleLoginFailure = (error) => {
        console.error("Login failed:", error);
        alert("Google login failed. Please try again.");
    };

    return (
        <div>
            <h2>Login with Google</h2>
            <GoogleLogin
                onSuccess={handleLoginSuccess}
                onError={handleLoginFailure}
            />
        </div>
    );
};

export default Login;
