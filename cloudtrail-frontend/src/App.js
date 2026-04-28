/**
 * CloudTrail Anomaly Detection – Frontend
 * ========================================
 * CORS REMINDER: Ensure api/main.py includes:
 *   from fastapi.middleware.cors import CORSMiddleware
 *   app.add_middleware(CORSMiddleware,
 *       allow_origins=["http://localhost:3000"],
 *       allow_methods=["*"], allow_headers=["*"])
 */

import React, { useState } from 'react';
import './App.css';
import Sidebar from './Sidebar';
import { ToastProvider } from './Toast';
import Dashboard from './pages/Dashboard';
import Register from './pages/Register';
import Tenants from './pages/Tenants';
import HowItWorks from './pages/HowItWorks';

function App() {
  const [page, setPage] = useState('dashboard');

  const renderPage = () => {
    switch (page) {
      case 'dashboard':  return <Dashboard />;
      case 'register':   return <Register />;
      case 'tenants':    return <Tenants />;
      case 'howitworks': return <HowItWorks />;
      default:           return <Dashboard />;
    }
  };

  return (
    <ToastProvider>
      <div className="app-layout">
        <Sidebar active={page} onNavigate={setPage} />
        <main className="main-content">
          {renderPage()}
        </main>
      </div>
    </ToastProvider>
  );
}

export default App;
