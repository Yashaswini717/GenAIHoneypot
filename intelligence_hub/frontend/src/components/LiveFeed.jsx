import useWebSocket from '../hooks/useWebSocket.js'

function scoreBadge(score) {
  if (score >= 90) return <span className="badge badge-critical">{score}</span>
  if (score >= 70) return <span className="badge badge-high">{score}</span>
  if (score >= 50) return <span className="badge badge-medium">{score}</span>
  return <span className="badge badge-low">{score}</span>
}

// Through Vite's /ws proxy on whichever host served this page. A hardcoded
// localhost:8000 only worked when the browser ran on the hub's own machine --
// opened from another PC on the LAN, localhost is that PC, and the feed
// silently never connected.
const FEED_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/feed`

export default function LiveFeed() {
  const { messages, connected } = useWebSocket(FEED_URL)

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:20 }}>
        <h2 style={{ fontSize:18, fontWeight:600 }}>Live Threat Feed</h2>
        <span style={{ fontSize:11, color: connected ? '#4ade80' : '#f87171' }}>
          {connected ? '● live' : '○ connecting...'}
        </span>
      </div>

      {messages.length === 0 && (
        <div className="card" style={{ color:'#64748b', textAlign:'center', padding:40 }}>
          Waiting for events... Send a log to /ingest/ to see it here live.
        </div>
      )}

      <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
        {messages.map((e, i) => (
          <div key={i} className="card" style={{ display:'flex', alignItems:'center', gap:12, padding:'10px 14px' }}>
            <div style={{ fontSize:11, color:'#64748b', minWidth:160 }}>
              {new Date(e.timestamp).toLocaleTimeString()}
            </div>
            <div style={{ minWidth:130, color:'#f1f5f9', fontFamily:'monospace', fontSize:12 }}>
              {e.src_ip}
            </div>
            <div style={{ minWidth:100 }}>
              <span className="badge badge-info">{e.event_type}</span>
            </div>
            <div style={{ minWidth:80 }}>
              {scoreBadge(e.threat_score)}
            </div>
            <div style={{ color:'#94a3b8', fontSize:12, flex:1 }}>
              {e.mitre_technique && <span style={{ color:'#a78bfa', marginRight:8 }}>{e.mitre_technique}</span>}
              {e.username && `user: ${e.username}`}
              {e.password && ` / pass: ${e.password}`}
              {e.country && ` · ${e.country}`}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}