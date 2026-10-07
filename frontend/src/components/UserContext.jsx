import { createContext, useState, useEffect, useContext } from 'react';
import * as api from '../services/api';

const UserContext = createContext(null);

export function UserProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Check if session exists on load
  useEffect(() => {
    async function checkSession() {
      try {
        const user = await api.getCurrentUser();
        if (user) {
          setCurrentUser(user);
          // Sync local history to backend upon initial load if authenticated
          await api.syncLocalHistoryToBackend().catch(err => console.warn('Guest history sync failed:', err.message));
        }
      } catch (err) {
        console.error('Session check failed:', err);
      } finally {
        setLoading(false);
      }
    }
    checkSession();
  }, []);

  const login = async (username, password) => {
    setError(null);
    try {
      const user = await api.login(username, password);
      setCurrentUser(user);
      // Sync local history to backend after successful login
      await api.syncLocalHistoryToBackend().catch(err => console.warn('Guest history sync failed:', err.message));
      return user;
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.');
      throw err;
    }
  };

  const signup = async (username, email, password) => {
    setError(null);
    try {
      const user = await api.signup(username, email, password);
      setCurrentUser(user);
      // Sync local history to backend after successful registration
      await api.syncLocalHistoryToBackend().catch(err => console.warn('Guest history sync failed:', err.message));
      return user;
    } catch (err) {
      setError(err.message || 'Signup failed. Please try again.');
      throw err;
    }
  };

  const logout = async () => {
    setError(null);
    try {
      await api.logout();
      setCurrentUser(null);
    } catch (err) {
      console.error('Logout error:', err);
      setError('Failed to log out cleanly.');
      throw err;
    }
  };

  const value = {
    currentUser,
    loading,
    error,
    login,
    signup,
    logout,
    isAuthenticated: !!currentUser
  };

  return (
    <UserContext.Provider value={value}>
      {children}
    </UserContext.Provider>
  );
}

// Context and its hook intentionally share one module.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useAuth must be used within a UserProvider');
  }
  return context;
}
