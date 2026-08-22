import React, { createContext, useContext, useState, useEffect } from 'react';
import { getUserDetails, loginUser, logoutUser, registerUser } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalTab, setAuthModalTab] = useState('login'); // 'login' | 'signup'

  // Fetch current user on initial mount
  const fetchUser = async () => {
    try {
      setLoading(true);
      const res = await getUserDetails();
      if (res && res.user) {
        setUser(res.user);
      } else {
        setUser(null);
      }
    } catch (err) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUser();
  }, []);

  const login = async (email, password) => {
    const res = await loginUser({ email, password });
    if (res && res.id) {
      await fetchUser();
      setAuthModalOpen(false);
    }
    return res;
  };

  const signup = async (username, email, password) => {
    const res = await registerUser({ username, email, password });
    // After signup, automatically log in
    if (res) {
      await login(email, password);
    }
    return res;
  };

  const logout = async () => {
    try {
      await logoutUser();
    } catch (e) {
      console.error(e);
    } finally {
      setUser(null);
    }
  };

  const openAuthModal = (tab = 'login') => {
    setAuthModalTab(tab);
    setAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setAuthModalOpen(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        signup,
        logout,
        fetchUser,
        authModalOpen,
        authModalTab,
        setAuthModalTab,
        openAuthModal,
        closeAuthModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
