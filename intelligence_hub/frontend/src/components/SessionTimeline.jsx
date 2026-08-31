import { useEffect, useState } from 'react'
import axios from 'axios'

export default function SessionTimeline() {
  const [sessions, setSessions] = useState([])
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)

  useEffect(() => {
    axios.get('/api/sessions/').then(r => setSessions(r.data.sessions))
  }, [])

  const loadDetail = async (id) => {
    setSelected(id)
    const r = await axios.get(`/api/sessions/${id}`)
    setDetail(r.data)
  }

  return (
    <div style={{ display:'grid', gridTemplateColumns:'320px 1fr', gap:16, height:'calc(100vh - 96px)' }}>
      <div style={{ overflowY:'auto' }}>
        <h2 style={{ fontSize:18, fontWeight:600, marginBottom:16 }}>Sessions</h2>
        {sessions.map(s => (
          <div key={s.session_id} onClick={() => loadDetail(s.session_id)}
            className="card" style={{
              marginBottom:8, cursor:'pointer',
              borderColor: selected === s.session_id ? '#60a5fa' : '#2d3148'
            }}>
            <div style={{ fontFamily:'monospace', fontSize:12, color:'#60a5fa' }}>{s.src_ip}</div>
            <div style={{ fontSize:11, color:'#64748b', marginTop:2 }}>
              {s.session_id?.slice(0,12)} · {s.country || 'Unknown'}
            </div>
            <div style={{ display:'flex', gap:6, marginTop:6 }}>
              <span className={`badge ${s.threat_score >= 70 ? 'badge-high' : 'badge-medium'}`}>
                score: {s.threat_score}
              </span>
              {s.login_attempts > 0 && (
                <span className="badge badge-critical">{s.login_attempts} attempts</span>
              )}
            </div>
          </div>
        ))}
      </div>

      <div style={{ overflowY:'auto' }}>
        {!detail && (
          <div style={{ color:'#64748b', textAlign:'center', paddingTop:80 }}>
            Select a session to see timeline
          </div>
        )}
        {detail && (
          <div>
            <h3 style={{ fontSize:15, fontWeight:600, marginBottom:4 }}>
              Session {detail.session_id}
            </h3>
            <div style={{ fontSize:12, color:'#64748b', marginBottom:16 }}>
              {detail.src_ip}
              {detail.correlated_ips?.length > 1 && (
                <span style={{ color:'#f87171', marginLeft:10 }}>
                  ⚠ Same tool seen from {detail.correlated_ips.length} IPs
                </span>
              )}
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
              {detail.events.map((e, i) => (
                <div key={i} className="card" style={{ padding:'8px 12px', display:'flex', gap:12 }}>
                  <div style={{ fontSize:11, color:'#64748b', minWidth:80 }}>
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </div>
                  <span className="badge badge-info" style={{ minWidth:100, textAlign:'center' }}>
                    {e.event_type}
                  </span>
                  <div style={{ fontSize:12, color:'#94a3b8' }}>
                    {e.username && `${e.username} / ${e.password}`}
                    {e.command && `$ ${e.command}`}
                    {e.mitre_technique && <span style={{ color:'#a78bfa', marginLeft:8 }}>{e.mitre_technique}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}