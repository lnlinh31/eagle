import axios from 'axios';
import config from '../config';

// Ceate default config for axios with baseURL
const axiosInstance = axios.create({
    baseURL: process.env.REACT_APP_API_ENDPOINT || config.apiEndpoint,
});

// Add interceptor for adding automatically JWT token into each request
axiosInstance.interceptors.request.use(config => {
    const token = localStorage.getItem('token'); // Get token from localStorage
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}, error => {
    return Promise.reject(error);
});

export default axiosInstance;