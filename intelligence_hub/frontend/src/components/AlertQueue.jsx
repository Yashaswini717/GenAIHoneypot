import { useEffect, useState } from 'react'
import axios from 'axios'

export default function AlertQueue() {
  const [alerts, setAlerts] = useState([])

  const load = () => axios.get('/api/alerts/').then(r => setAlerts(r.data.alerts))

  useEffect(() => { load() }, [])

  const update = async (id, status) => {
    await axios.patch(`/api/alerts/${id}?status=${status}`)
    load()
  }

  return (
    <div>
      <h2 style={{ fontSize:18, fontWeight:600, marginBottom:20 }}>Alert Queue</h2>
      {alerts.length === 0 && (
        <div className="card" style={{ color:'#64748b', textAlign:'center', padding:40 }}>
          No alerts yet. Events with threat score ≥ 70 auto-generate alerts.
        </div>
      )}
      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
        {alerts.map(a => (
          <div key={a.id} className="card" style={{ display:'flex', alignItems:'center', gap:12 }}>
            <div style={{ flex:1 }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                <span className={`badge ${a.threat_score >= 90 ? 'badge-critical' : a.threat_score >= 70 ? 'badge-high' : 'badge-medium'}`}>
                  {a.threat_score}
                </span>
                <span style={{ fontWeight:600, fontSize:13 }}>{a.alert_type}</span>
                <span style={{ color:'#64748b', fontSize:12 }}>{a.src_ip}</span>
                {a.country && <span style={{ color:'#64748b', fontSize:12 }}>· {a.country}</span>}
              </div>
              <div style={{ fontSize:12, color:'#94a3b8' }}>
                {a.mitre_technique && <span style={{ color:'#a78bfa', marginRight:8 }}>{a.mitre_technique}</span>}
                {a.description?.slice(0, 80)}
              </div>
            </div>
            <div style={{ display:'flex', gap:6 }}>
              {a.status === 'open' && <>
                <button onClick={() => update(a.id, 'acked')}
                  style={{ padding:'4px 10px', background:'#1e3a2a', color:'#4ade80',
                    border:'1px solid #2d5a3d', borderRadius:4, cursor:'pointer', fontSize:12 }}>
                  Ack
                </button>
                <button onClick={() => update(a.id, 'escalated')}
                  style={{ padding:'4px 10px', background:'#3d1515', color:'#f87171',
                    border:'1px solid #5a2d2d', borderRadius:4, cursor:'pointer', fontSize:12 }}>
                  Escalate
                </button>
                <button onClick={() => update(a.id, 'suppressed')}
                  style={{ padding:'4px 10px', background:'#1a1d27', color:'#64748b',
                    border:'1px solid #2d3148', borderRadius:4, cursor:'pointer', fontSize:12 }}>
                  Suppress
                </button>
              </>}
              {a.status !== 'open' && (
                <span className={`badge ${a.status === 'escalated' ? 'badge-critical' : a.status === 'acked' ? 'badge-low' : 'badge-info'}`}>
                  {a.status}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}