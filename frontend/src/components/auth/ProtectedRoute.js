import React from 'react';
import { Route, Navigate } from 'react-router-dom';

const ProtectedRoute = ({ component: Component, ...rest }) => {
    const token = localStorage.getItem('token');
    if (!token) {
        return <Navigate to="/login" />;
    }
    return <Component {...rest} />;
};

export default ProtectedRoute;