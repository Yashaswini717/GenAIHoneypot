export default function Sidebar({ activePage, setActivePage }) {
  const nav = [
    { id: 'dashboard', label: 'Overview' },
    { id: 'livefeed',  label: 'Live Feed' },
    { id: 'sessions',  label: 'Sessions' },
    { id: 'iocs',      label: 'IOC Intel' },
    { id: 'alerts',    label: 'Alerts' },
    { id: 'map',       label: 'Attack Map' },
  ]

  return (
    <aside style={{
      width: '200px', background: '#13151f', borderRight: '1px solid #2d3148',
      display: 'flex', flexDirection: 'column', padding: '20px 0', flexShrink: 0
    }}>
      <div style={{ padding: '0 20px 24px', borderBottom: '1px solid #2d3148' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#60a5fa', letterSpacing: '0.05em' }}>
          HONEYPOT
        </div>
        <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
          Intelligence Hub
        </div>
      </div>

      <nav style={{ marginTop: 16, flex: 1 }}>
        {nav.map(item => (
          <button key={item.id} onClick={() => setActivePage(item.id)}
            style={{
              width: '100%', textAlign: 'left', padding: '10px 20px',
              background: activePage === item.id ? '#1e2235' : 'transparent',
              color: activePage === item.id ? '#60a5fa' : '#94a3b8',
              border: 'none', cursor: 'pointer', fontSize: 13,
              borderLeft: activePage === item.id ? '3px solid #60a5fa' : '3px solid transparent',
            }}>
            {item.label}
          </button>
        ))}
      </nav>

      <div style={{ padding: '16px 20px', borderTop: '1px solid #2d3148' }}>
        <div style={{ fontSize: 11, color: '#64748b' }}>backend</div>
        <div style={{ fontSize: 11, color: '#4ade80', marginTop: 2 }}>● connected</div>
      </div>
    </aside>
  )
}