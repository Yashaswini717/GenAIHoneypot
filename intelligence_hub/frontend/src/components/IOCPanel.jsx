import { useEffect, useState } from 'react'
import axios from 'axios'

export default function IOCPanel() {
  const [iocs, setIocs] = useState([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    axios.get('/api/iocs/').then(r => setIocs(r.data.iocs))
  }, [])

  const filtered = iocs.filter(i => i.value?.includes(search))

  return (
    <div>
      <h2 style={{ fontSize:18, fontWeight:600, marginBottom:20 }}>IOC Intelligence</h2>
      <input placeholder="Search IOCs..." value={search}
        onChange={e => setSearch(e.target.value)}
        style={{ background:'#1a1d27', border:'1px solid #2d3148', color:'#e2e8f0',
          padding:'8px 12px', borderRadius:6, marginBottom:16, width:300 }} />
      <div className="card" style={{ padding:0 }}>
        <table style={{ width:'100%', borderCollapse:'collapse' }}>
          <thead>
            <tr style={{ borderBottom:'1px solid #2d3148' }}>
              {['Type','Value','Hit Count','Threat Score','First Seen','Last Seen'].map(h => (
                <th key={h} style={{ padding:'10px 14px', textAlign:'left', fontSize:12, color:'#64748b' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc, i) => (
              <tr key={i} style={{ borderBottom:'1px solid #1e2235' }}>
                <td style={{ padding:'10px 14px' }}><span className="badge badge-info">{ioc.ioc_type}</span></td>
                <td style={{ padding:'10px 14px', fontFamily:'monospace', fontSize:12 }}>{ioc.value}</td>
                <td style={{ padding:'10px 14px', color:'#94a3b8' }}>{ioc.hit_count}</td>
                <td style={{ padding:'10px 14px' }}>
                  <span className={`badge ${ioc.threat_score >= 70 ? 'badge-high' : 'badge-medium'}`}>
                    {ioc.threat_score}
                  </span>
                </td>
                <td style={{ padding:'10px 14px', color:'#64748b', fontSize:12 }}>
                  {new Date(ioc.first_seen).toLocaleDateString()}
                </td>
                <td style={{ padding:'10px 14px', color:'#64748b', fontSize:12 }}>
                  {new Date(ioc.last_seen).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}