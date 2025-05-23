
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Menu, X, Search, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { Button } from "@/components/ui/button";
import SearchBar from './SearchBar';

const Navbar = () => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const { isAuthenticated, logout } = useAuth();
  const location = useLocation();

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 10) {
        setIsScrolled(true);
      } else {
        setIsScrolled(false);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    // Close mobile menu when route changes
    setIsMenuOpen(false);
  }, [location]);

  const toggleMenu = () => setIsMenuOpen(!isMenuOpen);
  const toggleSearch = () => setIsSearchOpen(!isSearchOpen);

  return (
    <header className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
      isScrolled ? 'bg-gray-100/95 backdrop-blur-sm shadow-lg' : 'bg-gray-100/90 backdrop-blur-sm'
    }`}>
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <div className="w-10 h-10 rounded-lg bg-quantum-500 flex items-center justify-center">
              <span className="text-white font-bold text-xl">Q</span>
            </div>
            <span className="font-bold text-xl hidden md:inline">QuantGenAILabs</span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center space-x-8">
            <Link to="/" className="text-gray-700 hover:text-gray-900 transition-colors font-medium">Home</Link>
            <Link to="/about" className="text-gray-700 hover:text-gray-900 transition-colors font-medium">About</Link>
            <div className="relative group">
              <Link to="#services" className="text-gray-700 hover:text-gray-900 transition-colors font-medium">Services</Link>
              <div className="absolute left-0 mt-2 w-48 rounded-md shadow-lg bg-white/95 backdrop-blur-sm opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-300 transform group-hover:translate-y-0 translate-y-2 z-10">
                <div className="rounded-md ring-1 ring-gray-200 p-2 space-y-1">
                  {['Machine Learning', 'Deep Learning', 'NLP', 'Robotics', 'Drones', 'Quantum Computing', 'GenAI', 'LLMs'].map((service) => (
                    <Link 
                      key={service}
                      to={`/topic/${service.toLowerCase().replace(' ', '-')}`}
                      className="block px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
                    >
                      {service}
                    </Link>
                  ))}
                </div>
              </div>
            </div>
            <Link to="/contact" className="text-gray-700 hover:text-gray-900 transition-colors font-medium">Contact</Link>
          </nav>

          {/* Right side buttons */}
          <div className="flex items-center space-x-4">
            <button 
              onClick={toggleSearch}
              className="p-2 rounded-full hover:bg-gray-200 transition-colors"
              aria-label="Search"
            >
              <Search className="w-5 h-5 text-gray-700" />
            </button>

            {isAuthenticated ? (
              <div className="hidden md:flex items-center space-x-4">
                <Link to="/dashboard">
                  <Button variant="outline" size="sm" className="flex items-center bg-white hover:bg-blue-500 hover:text-white text-gray-900 transition-colors">
                    <User className="w-4 h-4 mr-2" />
                    Dashboard
                  </Button>
                </Link>
                <Button 
                  variant="ghost" 
                  size="sm"
                  onClick={() => logout()}
                  className="text-gray-700 hover:text-gray-900"
                >
                  Logout
                </Button>
              </div>
            ) : (
              <div className="hidden md:flex items-center space-x-4">
                <Link to="/login">
                  <Button variant="outline" size="sm" className="bg-gray-100 text-gray-700 hover:bg-blue-500 hover:text-white hover:border-blue-500 font-semibold transition-colors backdrop-blur-sm">Login</Button>
                </Link>
                <Link to="/signup">
                  <Button variant="outline" size="sm" className="bg-gray-100 text-gray-700 hover:bg-blue-500 hover:text-white hover:border-blue-500 font-semibold transition-colors backdrop-blur-sm">Sign Up</Button>
                </Link>
              </div>
            )}

            {/* Mobile menu button */}
            <button
              onClick={toggleMenu}
              className="p-2 rounded-full md:hidden hover:bg-quantum-800 transition-colors"
              aria-label="Menu"
            >
              {isMenuOpen ? <X className="w-6 h-6 text-white" /> : <Menu className="w-6 h-6 text-white" />}
            </button>
          </div>
        </div>

        {/* Mobile menu */}
        <div className={`md:hidden transition-all duration-300 ease-in-out overflow-hidden ${isMenuOpen ? 'max-h-screen opacity-100 mt-4' : 'max-h-0 opacity-0'}`}>
          <nav className="flex flex-col space-y-4 py-4 bg-black/90 backdrop-blur-sm rounded-lg px-4">
            <Link to="/" className="text-gray-100 hover:text-white transition-colors font-medium">Home</Link>
            <Link to="/about" className="text-gray-100 hover:text-white transition-colors font-medium">About</Link>
            <Link to="#services" className="text-gray-100 hover:text-white transition-colors font-medium">Services</Link>
            <div className="pl-8 space-y-2">
              {['Machine Learning', 'Deep Learning', 'NLP', 'Robotics', 'Drones', 'Quantum Computing', 'GenAI', 'LLMs'].map((service) => (
                <Link 
                  key={service}
                  to={`/topic/${service.toLowerCase().replace(' ', '-')}`}
                  className="block py-1 text-sm text-gray-600 dark:text-gray-300 hover:text-primary transition-colors"
                >
                  {service}
                </Link>
              ))}
            </div>
            <Link to="/contact" className="text-gray-100 hover:text-white transition-colors font-medium">Contact</Link>
            
            {isAuthenticated ? (
              <>
                <Link to="/dashboard" className="nav-link px-4 py-2">Dashboard</Link>
                <button 
                  onClick={() => logout()}
                  className="text-left nav-link px-4 py-2"
                >
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link to="/login" className="nav-link px-4 py-2 text-gray-100 hover:text-white transition-colors font-medium">Login</Link>
                <Link to="/signup" className="nav-link px-4 py-2 text-gray-100 hover:text-white transition-colors font-medium">Sign Up</Link>
              </>
            )}
          </nav>
        </div>
      </div>

      {/* Search Overlay */}
      <div className={`fixed inset-0 bg-black/50 z-50 transition-opacity duration-300 ${
        isSearchOpen ? 'opacity-100 visible' : 'opacity-0 invisible'
      }`} onClick={toggleSearch}>
        <div className="container mx-auto px-4 pt-24" onClick={e => e.stopPropagation()}>
          <SearchBar onClose={toggleSearch} />
        </div>
      </div>
    </header>
  );
};

export default Navbar;
