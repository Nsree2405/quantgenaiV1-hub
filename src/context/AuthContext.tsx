import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';

// Define the structure of your user object (adjust as needed)
interface User {
  id: string;
  email: string;
  name?: string;
  // Add other fields like tokens if using JWT later
}

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>; // Make async
  logout: () => void;
  signup: (email: string, password: string, name?: string) => Promise<void>; // Make async
  loading: boolean; // Add loading state
  error: string | null; // Add error state
  isAuthenticated: boolean ;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Define the backend API base URL
const API_URL = '/api/auth'; // Adjust port if needed

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true); // Start true for initial check
  const [error, setError] = useState<string | null>(null);

  // Check local storage on initial load (optional, for persistence)
  useEffect(() => {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        console.error("Failed to parse stored user:", e);
        localStorage.removeItem('user');
      }
    }
    setLoading(false); // Done checking storage
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }

      // Assuming the backend sends back user info on successful login
      const loggedInUser: User = data.user;
      setUser(loggedInUser);
      localStorage.setItem('user', JSON.stringify(loggedInUser)); // Persist user

    } catch (err: any) {
      console.error("Login failed:", err);
      setError(err.message || 'Login failed. Please check your credentials.');
      // Ensure user state is null on failure
      setUser(null);
      localStorage.removeItem('user');
    } finally {
      setLoading(false);
    }
  };

  const signup = async (email: string, password: string, name?: string) => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name }), // Include name if provided
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }

      // Optionally log the user in automatically after signup
      // const signedUpUser: User = data.user;
      // setUser(signedUpUser);
      // localStorage.setItem('user', JSON.stringify(signedUpUser));
      // Or just show a success message and let them log in manually
      console.log("Signup successful:", data.message);
      // You might want to redirect to login page or show a success message

    } catch (err: any) {
      console.error("Signup failed:", err);
      setError(err.message || 'Signup failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('user'); // Clear persisted user
    // Optionally redirect to login page
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, signup, loading, error ,isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};