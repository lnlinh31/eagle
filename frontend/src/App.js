import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import ManageTargets from './pages/ManageTargets';
import ManageVulnerabilities from './pages/ManageVulnerabilities';
import ManageJobs from './pages/ManageJobs';
import ManageSettings from './pages/ManageSettings';
import ManageCustomNuclei from './pages/ManageCustomNuclei'; 
import { GoogleOAuthProvider } from '@react-oauth/google';
import ProtectedRoute from './components/auth/ProtectedRoute';
import VisualizeTargets from './pages/visualizes/VisualizeTargets';
import Login from './components/auth/Login';
import './css/App.css';

const App = () => {
  return (
    <GoogleOAuthProvider clientId="593191606839-984jtb0e3rfbv1ufadfvs4c7e9tlv7p1.apps.googleusercontent.com">
      <Router>
        <div className="app-container">
          <Navbar className="sidebar" />
          <div className="page-content">
            <Routes>
              <Route path="/targets" element={<ProtectedRoute component={ManageTargets} />} />
              <Route path="/targets/visualize" element={<ProtectedRoute component={VisualizeTargets} />} /> 
              <Route path="/vulnerabilities" element={<ProtectedRoute component={ManageVulnerabilities} />} />
              <Route path="/jobs" element={<ProtectedRoute component={ManageJobs} />} />
              <Route path="/settings" element={<ProtectedRoute component={ManageSettings} />} />
              <Route path="/custom-nuclei" element={<ProtectedRoute component={ManageCustomNuclei} />} /> 
              <Route path="/login" element={<Login />} />
              <Route path="*" element={<Navigate to="/login" />} />
            </Routes>
          </div>
        </div>
      </Router>
    </GoogleOAuthProvider>
  );
};

export default App;
