import { useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import IngestLogs from './components/IngestLogs' // Make sure this path is correct!
import './App.css'

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar activePage={activePage} setActivePage={setActivePage} />
      <main style={{ flex: 1, overflow: 'auto', padding: '24px' }}>
        
        {/* NEW: Conditionally render Ingest Logs vs Dashboard */}
        {activePage === 'ingest' ? (
          <IngestLogs />
        ) : (
          <Dashboard activePage={activePage} />
        )}
        
      </main>
    </div>
  )
}