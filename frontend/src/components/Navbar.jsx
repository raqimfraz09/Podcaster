import React, { useState, useRef, useEffect } from 'react';
import { 
  Radio, Search, Plus, PenSquare, LogIn, User, 
  LogOut, LayoutDashboard, BookOpen, Menu, X, Compass, ChevronDown
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar = ({ currentRoute, setCurrentRoute, searchGlobal, setSearchGlobal }) => {
  const { user, logout, openAuthModal } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleNav = (route) => {
    setCurrentRoute(route);
    setMobileMenuOpen(false);
    setDropdownOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <nav className="navbar">
      <div className="container navbar-container">
        {/* Left: Brand & Links */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
          <button 
            onClick={() => handleNav({ page: 'home' })} 
            className="nav-brand"
            style={{ background: 'none', border: 'none', padding: 0 }}
          >
            <div className="brand-icon">
              <Radio size={18} strokeWidth={2.4} />
            </div>
            <span>Podcaster</span>
          </button>

          <ul className="nav-links">
            <li>
              <button
                onClick={() => handleNav({ page: 'home' })}
                className={`nav-link ${currentRoute.page === 'home' ? 'active' : ''}`}
              >
                Home
              </button>
            </li>
            <li>
              <button
                onClick={() => handleNav({ page: 'explore' })}
                className={`nav-link ${currentRoute.page === 'explore' ? 'active' : ''}`}
              >
                Explore
              </button>
            </li>
            <li>
              <button
                onClick={() => handleNav({ page: 'blogs' })}
                className={`nav-link ${currentRoute.page === 'blogs' ? 'active' : ''}`}
              >
                Articles
              </button>
            </li>
          </ul>
        </div>

        {/* Center: Search */}
        <div style={{
          position: 'relative',
          width: '260px',
          display: 'none',
          alignItems: 'center'
        }} className="desktop-search">
          <Search size={15} color="var(--text-muted)" style={{ position: 'absolute', left: '10px' }} />
          <input
            type="text"
            placeholder="Search episodes, creators..."
            value={searchGlobal}
            onChange={(e) => setSearchGlobal(e.target.value)}
            style={{
              width: '100%',
              padding: '0.45rem 0.75rem 0.45rem 2rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-light)',
              background: 'var(--bg-app)',
              fontSize: '0.8125rem',
              outline: 'none'
            }}
          />
        </div>

        {/* Right: Actions */}
        <div className="nav-actions">
          {user ? (
            <>
              <button
                onClick={() => handleNav({ page: 'upload-podcast' })}
                className="btn btn-secondary btn-sm"
                title="Upload podcast"
              >
                <Plus size={15} />
                <span className="hide-mobile">Upload Episode</span>
              </button>

              <button
                onClick={() => handleNav({ page: 'create-blog' })}
                className="btn btn-ghost btn-sm"
                title="Write article"
              >
                <PenSquare size={15} />
                <span className="hide-mobile">Write Article</span>
              </button>

              {/* User Dropdown */}
              <div className="user-menu-wrapper" ref={dropdownRef}>
                <button
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className="user-avatar-btn"
                  aria-label="User menu"
                >
                  <div className="avatar-circle">
                    {user.username ? user.username.charAt(0).toUpperCase() : 'U'}
                  </div>
                  <span style={{ fontWeight: 600, fontSize: '0.8125rem' }} className="hide-mobile">
                    {user.username}
                  </span>
                  <ChevronDown size={14} color="var(--text-muted)" className="hide-mobile" />
                </button>

                {dropdownOpen && (
                  <div className="user-dropdown">
                    <div className="dropdown-header">
                      <div className="dropdown-name">{user.username}</div>
                      <div className="dropdown-email">{user.email}</div>
                    </div>
                    <button
                      onClick={() => handleNav({ page: 'dashboard' })}
                      className="dropdown-item"
                    >
                      <LayoutDashboard size={15} />
                      Creator Dashboard
                    </button>
                    <button
                      onClick={() => handleNav({ page: 'upload-podcast' })}
                      className="dropdown-item"
                    >
                      <Plus size={15} />
                      Upload Podcast
                    </button>
                    <button
                      onClick={() => handleNav({ page: 'create-blog' })}
                      className="dropdown-item"
                    >
                      <PenSquare size={15} />
                      Write Article
                    </button>
                    <div style={{ height: '1px', background: 'var(--border-light)', margin: '0.25rem 0' }} />
                    <button
                      onClick={() => {
                        logout();
                        setDropdownOpen(false);
                      }}
                      className="dropdown-item danger"
                    >
                      <LogOut size={15} />
                      Sign Out
                    </button>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', gap: '0.45rem' }}>
              <button
                onClick={() => openAuthModal('login')}
                className="btn btn-ghost btn-sm"
              >
                <LogIn size={15} />
                Sign In
              </button>
              <button
                onClick={() => openAuthModal('signup')}
                className="btn btn-primary btn-sm"
              >
                Get Started
              </button>
            </div>
          )}

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="btn btn-icon btn-ghost"
            style={{ display: 'none' }}
            className="mobile-menu-btn"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div style={{
          position: 'fixed',
          top: 'var(--header-height)',
          left: 0,
          right: 0,
          background: 'var(--bg-surface)',
          borderBottom: '1px solid var(--border-light)',
          padding: '1rem',
          boxShadow: 'var(--shadow-lg)',
          zIndex: 49,
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem'
        }}>
          <button
            onClick={() => handleNav({ page: 'home' })}
            className={`dropdown-item ${currentRoute.page === 'home' ? 'active' : ''}`}
          >
            <Radio size={16} /> Home
          </button>
          <button
            onClick={() => handleNav({ page: 'explore' })}
            className={`dropdown-item ${currentRoute.page === 'explore' ? 'active' : ''}`}
          >
            <Compass size={16} /> Explore
          </button>
          <button
            onClick={() => handleNav({ page: 'blogs' })}
            className={`dropdown-item ${currentRoute.page === 'blogs' ? 'active' : ''}`}
          >
            <BookOpen size={16} /> Articles
          </button>
          {user && (
            <button
              onClick={() => handleNav({ page: 'dashboard' })}
              className={`dropdown-item ${currentRoute.page === 'dashboard' ? 'active' : ''}`}
            >
              <LayoutDashboard size={16} /> Dashboard
            </button>
          )}
        </div>
      )}
    </nav>
  );
};
