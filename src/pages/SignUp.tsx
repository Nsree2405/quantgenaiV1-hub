
import React, { useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import Navbar from '../components/Navbar';
import { SignUpForm } from '../components/AuthForms';
import { useAuth } from '../context/AuthContext';

const SignUp = () => {
  const { isAuthenticated } = useAuth();
  
  useEffect(() => {
    window.scrollTo(0, 0);
  }, []);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      <Navbar />
      
      <div className="pt-20 px-4">
        <div className="container mx-auto py-16 md:py-24">
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div>
              <SignUpForm />
            </div>
            
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5 }}
              className="hidden md:block"
            >
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-quantum-600 to-quantum-500 opacity-20 rounded-2xl transform rotate-2"></div>
                <div className="absolute inset-0 bg-gradient-to-r from-quantum-500 to-quantum-400 opacity-20 rounded-2xl transform -rotate-2"></div>
                <div className="relative bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-lg">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Join QuantGenAILabs Today</h2>
                  <p className="text-gray-600 dark:text-gray-400 mb-6">
                    Create your account to unlock the full potential of our platform and explore cutting-edge AI technologies.
                  </p>
                  
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-3">What you'll get:</h3>
                  <ul className="space-y-4">
                    <li className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-6 w-6 text-quantum-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <p className="ml-3 text-gray-600 dark:text-gray-400">
                        <strong className="text-gray-900 dark:text-white">Personalized Dashboard</strong> - Access your custom learning journey
                      </p>
                    </li>
                    <li className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-6 w-6 text-quantum-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <p className="ml-3 text-gray-600 dark:text-gray-400">
                        <strong className="text-gray-900 dark:text-white">Research Papers</strong> - Full access to our library of cutting-edge research
                      </p>
                    </li>
                    <li className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-6 w-6 text-quantum-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <p className="ml-3 text-gray-600 dark:text-gray-400">
                        <strong className="text-gray-900 dark:text-white">AI Assistant</strong> - Get help with your queries through our intelligent chatbot
                      </p>
                    </li>
                    <li className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-6 w-6 text-quantum-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                        </svg>
                      </div>
                      <p className="ml-3 text-gray-600 dark:text-gray-400">
                        <strong className="text-gray-900 dark:text-white">Educational Resources</strong> - Premium courses, tutorials, and learning materials
                      </p>
                    </li>
                    {/* <li className="flex"> 
                      <div className="flex-shrink-0"> 
                        <svg className="h-6 w-6 text-quantum-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"> 
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" /> 
                        </svg> 
                      </div> 
                      <p className="ml-3 text-gray-600 dark:text-gray-400"> 
                        <strong className="text-gray-900 dark:text-white">Community Access</strong> - Connect with like-minded technology enthusiasts 
                      </p> 
                    </li> */}
                  </ul>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
      
      <div className="bg-gray-900 text-white py-6 text-center text-sm">
        <div className="container mx-auto">
          <p>&copy; {new Date().getFullYear()} QuantGenAILabs. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
};

export default SignUp;
