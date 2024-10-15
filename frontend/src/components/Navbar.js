import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { MdPerson, MdHome, MdSecurity, MdVpnLock, MdWork, MdMenu, MdOutlineSettings, MdBuild } from 'react-icons/md';
import '../css/Navbar.css';

const Navbar = () => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isDropdownVisible, setDropdownVisible] = useState(false);
  const navigate = useNavigate();

  
  const user = JSON.parse(localStorage.getItem('user'));

  const handleLogout = () => {
    
    localStorage.removeItem('token');
    localStorage.removeItem('user');

    navigate('/login');
  };

  const toggleDropdown = () => {
    setDropdownVisible(!isDropdownVisible);
  };

  return (
    <div className={`navbar ${isExpanded ? 'expanded' : ''}`}>
      <MdMenu className="menu-icon" onClick={() => setIsExpanded(!isExpanded)} />
      <div className={`nav-items ${isExpanded ? 'expanded' : ''}`}>
        <NavLink to="/" className="nav-link">
          <MdHome className="icon" />
          {isExpanded && <span>Home</span>}
        </NavLink>
        <NavLink to="/targets" className="nav-link">
          <MdVpnLock className="icon" />
          {isExpanded && <span>Targets</span>}
        </NavLink>
        <NavLink to="/vulnerabilities" className="nav-link">
          <MdSecurity className="icon" />
          {isExpanded && <span>Vulnerabilities</span>}
        </NavLink>
        <NavLink to="/jobs" className="nav-link">
          <MdWork className="icon" />
          {isExpanded && <span>Job</span>}
        </NavLink>
        <NavLink to="/settings" className="nav-link">
          <MdOutlineSettings className="icon" />
          {isExpanded && <span>Settings</span>}
        </NavLink>
        <NavLink to="/custom-nuclei" className="nav-link">
          <MdBuild className="icon" />
          {isExpanded && <span>Custom Nuclei</span>}
        </NavLink>

        {user && (
          <div className="user-section">
            <MdPerson className="user-icon" />
            <button onClick={toggleDropdown} className={`user-button ${isDropdownVisible ? 'active' : ''}`}>
              {user.name}
            </button>
            {isDropdownVisible && (
              <div className="dropdown">
                <button onClick={handleLogout}>Logout</button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Navbar;
