import { useEffect, useState } from 'react'
import axios from 'axios'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area,
  RadialBarChart, RadialBar, Legend
} from 'recharts'

const SEVERITY_COLORS = {
  brute_force:  '#f87171',
  connection:   '#60a5fa',
  recon:        '#fbbf24',
  command_exec: '#f472b6',
  compromise:   '#ef4444',
  exfil:        '#a78bfa',
  lateral_move: '#fb923c',
  session_end:  '#94a3b8',
  unknown:      '#64748b',
}

const PIE_COLORS = ['#f87171','#60a5fa','#fbbf24','#4ade80','#a78bfa','#34d399','#fb923c','#f472b6']

function MetricCard({ label, value, sub, color = '#60a5fa', accent }) {
  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1d27 0%, #1e2235 100%)',
      border: `1px solid ${accent || '#2d3148'}`,
      borderTop: `3px solid ${color}`,
      borderRadius: 8, padding: '16px 20px',
      display: 'flex', flexDirection: 'column', gap: 4
    }}>
      <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color, lineHeight: 1.1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: '#94a3b8' }}>{sub}</div>}
    </div>
  )
}

function SectionTitle({ children }) {
  return (
    <div style={{ fontSize: 12, fontWeight: 600, color: '#64748b', textTransform: 'uppercase',
      letterSpacing: '0.1em', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 3, height: 14, background: '#60a5fa', borderRadius: 2 }} />
      {children}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 6, padding: '8px 12px' }}>
      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ fontSize: 12, color: p.color || '#e2e8f0' }}>
          {p.name}: <b>{p.value}</b>
        </div>
      ))}
    </div>
  )
}

export default function Overview() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [iocs, setIocs] = useState([])
  const [lastUpdate, setLastUpdate] = useState(new Date())

  useEffect(() => {
    const load = async () => {
      const [s, e, i] = await Promise.all([
        axios.get('/api/events/stats'),
        axios.get('/api/events/?limit=100'),
        axios.get('/api/iocs/'),
      ])
      setStats(s.data)
      setEvents(e.data.events)
      setIocs(i.data.iocs)
      setLastUpdate(new Date())
    }
    load()
    const interval = setInterval(load, 30000)
    return () => clearInterval(interval)
  }, [])

  if (!stats) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60vh', flexDirection: 'column', gap: 16 }}>
      <div style={{ width: 40, height: 40, border: '3px solid #2d3148', borderTop: '3px solid #60a5fa', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
      <div style={{ color: '#64748b', fontSize: 13 }}>Loading intelligence data...</div>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
    </div>
  )

  const totalEvents   = stats.by_type.reduce((a, b) => a + b.doc_count, 0)
  const topIP         = stats.top_ips[0]?.key || '—'
  const topIPCount    = stats.top_ips[0]?.doc_count || 0
  const avgScore      = stats.avg_threat_score
  const bruteForce    = stats.by_type.find(t => t.key === 'brute_force')?.doc_count || 0
  const compromised   = stats.by_type.find(t => t.key === 'compromise')?.doc_count || 0
  const uniqueIPs     = stats.top_ips.length
  const highRisk      = events.filter(e => e.threat_score >= 70).length
  const criticalPct   = totalEvents > 0 ? Math.round((highRisk / totalEvents) * 100) : 0

  // credential attempts from events
  const credAttempts  = events.filter(e => e.username).length
  const uniqueUsers   = [...new Set(events.filter(e => e.username).map(e => e.username))].length

  // threat score distribution
  const scoreDistrib = [
    { name: 'Critical (90+)', value: events.filter(e => e.threat_score >= 90).length, fill: '#ef4444' },
    { name: 'High (70-89)',   value: events.filter(e => e.threat_score >= 70 && e.threat_score < 90).length, fill: '#f87171' },
    { name: 'Medium (40-69)', value: events.filter(e => e.threat_score >= 40 && e.threat_score < 70).length, fill: '#fbbf24' },
    { name: 'Low (<40)',      value: events.filter(e => e.threat_score < 40).length, fill: '#4ade80' },
  ].filter(d => d.value > 0)

  // MITRE breakdown
  const mitreMap = {}
  events.forEach(e => {
    if (e.mitre_technique) mitreMap[e.mitre_technique] = (mitreMap[e.mitre_technique] || 0) + 1
  })
  const mitreData = Object.entries(mitreMap).map(([k, v]) => ({ technique: k, count: v }))
    .sort((a, b) => b.count - a.count).slice(0, 6)

  // top passwords tried
  const passMap = {}
  events.forEach(e => { if (e.password) passMap[e.password] = (passMap[e.password] || 0) + 1 })
  const topPasswords = Object.entries(passMap).map(([k, v]) => ({ password: k, count: v }))
    .sort((a, b) => b.count - a.count).slice(0, 5)

  // radial threat gauge data
  const gaugeData = [{ name: 'Threat', value: Math.round(avgScore), fill: avgScore >= 70 ? '#ef4444' : avgScore >= 40 ? '#fbbf24' : '#4ade80' }]

  return (
    <div style={{ paddingBottom: 40 }}>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} } @keyframes spin { to{transform:rotate(360deg)} }`}</style>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Security Operations Center</h1>
          <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
            GenAI Honeypot Intelligence Hub · Updated {lastUpdate.toLocaleTimeString()}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {compromised > 0 && (
            <div style={{ background: '#3d1515', border: '1px solid #7f1d1d', borderRadius: 6,
              padding: '6px 12px', fontSize: 12, color: '#f87171', animation: 'pulse 2s infinite' }}>
              ⚠ {compromised} COMPROMISE DETECTED
            </div>
          )}
          <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 6,
            padding: '6px 12px', fontSize: 12, color: '#4ade80' }}>
            ● LIVE
          </div>
        </div>
      </div>

      {/* Top metric cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12, marginBottom: 24 }}>
        <MetricCard label="Total Events"      value={totalEvents}    color="#60a5fa" sub="all time" />
        <MetricCard label="Unique Attackers"  value={uniqueIPs}      color="#a78bfa" sub="source IPs" />
        <MetricCard label="Brute Force"       value={bruteForce}     color="#f87171" sub="login attempts" accent="#7f1d1d" />
        <MetricCard label="Avg Threat Score"  value={avgScore}       color={avgScore >= 70 ? '#ef4444' : '#fbbf24'} sub="out of 100" />
        <MetricCard label="High Risk Events"  value={`${criticalPct}%`} color="#fb923c" sub={`${highRisk} events ≥70`} />
        <MetricCard label="Credentials Tried" value={credAttempts}   color="#34d399" sub={`${uniqueUsers} unique users`} />
      </div>

      {/* Row 2: Pie + Radial gauge + Area chart */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px 1fr', gap: 16, marginBottom: 16 }}>

        {/* Attack type pie */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>Attack type distribution</SectionTitle>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <ResponsiveContainer width="55%" height={200}>
              <PieChart>
                <Pie data={stats.by_type} dataKey="doc_count" nameKey="key"
                  cx="50%" cy="50%" outerRadius={80} innerRadius={40}>
                  {stats.by_type.map((entry, i) => (
                    <Cell key={i} fill={SEVERITY_COLORS[entry.key] || PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2d3148', fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {stats.by_type.map((t, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                    background: SEVERITY_COLORS[t.key] || PIE_COLORS[i % PIE_COLORS.length] }} />
                  <span style={{ color: '#94a3b8', flex: 1 }}>{t.key}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{t.doc_count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Threat gauge */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <SectionTitle>Threat level</SectionTitle>
          <ResponsiveContainer width="100%" height={160}>
            <RadialBarChart cx="50%" cy="50%" innerRadius="60%" outerRadius="90%"
              startAngle={180} endAngle={0} data={gaugeData}>
              <RadialBar dataKey="value" cornerRadius={6} background={{ fill: '#2d3148' }} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div style={{ textAlign: 'center', marginTop: -20 }}>
            <div style={{ fontSize: 36, fontWeight: 700,
              color: avgScore >= 70 ? '#ef4444' : avgScore >= 40 ? '#fbbf24' : '#4ade80' }}>
              {Math.round(avgScore)}
            </div>
            <div style={{ fontSize: 11, color: '#64748b' }}>avg threat score</div>
            <div style={{ marginTop: 8, fontSize: 12, fontWeight: 600,
              color: avgScore >= 70 ? '#ef4444' : avgScore >= 40 ? '#fbbf24' : '#4ade80' }}>
              {avgScore >= 70 ? '🔴 HIGH RISK' : avgScore >= 40 ? '🟡 MODERATE' : '🟢 LOW RISK'}
            </div>
          </div>
        </div>

        {/* Threat score distribution */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>Threat score distribution</SectionTitle>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={scoreDistrib} layout="vertical">
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={100} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {scoreDistrib.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 3: Timeline area chart */}
      <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16, marginBottom: 16 }}>
        <SectionTitle>Attack timeline</SectionTitle>
        <ResponsiveContainer width="100%" height={160}>
          <AreaChart data={stats.by_hour}>
            <defs>
              <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#60a5fa" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#60a5fa" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="key_as_string"
              tickFormatter={v => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip content={<CustomTooltip />} labelFormatter={v => new Date(v).toLocaleString()} />
            <Area type="monotone" dataKey="doc_count" name="Events"
              stroke="#60a5fa" strokeWidth={2} fill="url(#areaGrad)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Row 4: Top IPs bar + MITRE + Top passwords */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Top IPs */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>Top attacker IPs</SectionTitle>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.top_ips.slice(0, 6)} layout="vertical">
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis dataKey="key" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={110} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="doc_count" name="Events" fill="#f87171" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* MITRE techniques */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>MITRE ATT&CK techniques</SectionTitle>
          {mitreData.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: 12, textAlign: 'center', paddingTop: 40 }}>No technique data</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {mitreData.map((m, i) => (
                <div key={i}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, color: '#a78bfa', fontFamily: 'monospace' }}>{m.technique}</span>
                    <span style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 600 }}>{m.count}</span>
                  </div>
                  <div style={{ height: 4, background: '#2d3148', borderRadius: 2 }}>
                    <div style={{ height: '100%', borderRadius: 2, background: PIE_COLORS[i % PIE_COLORS.length],
                      width: `${(m.count / mitreData[0].count) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top passwords */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>Top passwords tried</SectionTitle>
          {topPasswords.length === 0 ? (
            <div style={{ color: '#64748b', fontSize: 12, textAlign: 'center', paddingTop: 40 }}>No credential data</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {topPasswords.map((p, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10,
                  background: '#13151f', borderRadius: 6, padding: '8px 12px' }}>
                  <div style={{ width: 20, height: 20, borderRadius: 4, background: '#2d3148',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 10, color: '#64748b', fontWeight: 700 }}>{i + 1}</div>
                  <span style={{ flex: 1, fontSize: 12, fontFamily: 'monospace', color: '#fbbf24' }}>{p.password}</span>
                  <span style={{ fontSize: 11, color: '#94a3b8' }}>{p.count}x</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Row 5: IOC summary + recent high risk events */}
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>

        {/* IOC summary */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>IOC summary</SectionTitle>
          {['ip', 'username', 'hassh'].map(type => {
            const count = iocs.filter(i => i.ioc_type === type).length
            const icons = { ip: '🌐', username: '👤', hassh: '🔑' }
            return (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 0', borderBottom: '1px solid #2d3148' }}>
                <span style={{ fontSize: 16 }}>{icons[type]}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 500, textTransform: 'capitalize' }}>{type}</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>indicators</div>
                </div>
                <div style={{ fontSize: 22, fontWeight: 700, color: '#60a5fa' }}>{count}</div>
              </div>
            )
          })}
          <div style={{ marginTop: 12, fontSize: 11, color: '#64748b', textAlign: 'center' }}>
            {iocs.length} total IOCs tracked
          </div>
        </div>

        {/* Recent high risk events */}
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>
          <SectionTitle>Recent high-risk events</SectionTitle>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {events.filter(e => e.threat_score >= 50).slice(0, 6).map((e, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10,
                background: '#13151f', borderRadius: 6, padding: '8px 12px' }}>
                <div style={{ width: 36, height: 36, borderRadius: 6, flexShrink: 0,
                  background: e.threat_score >= 70 ? '#3d1515' : '#3d3415',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 13, fontWeight: 700,
                  color: e.threat_score >= 70 ? '#f87171' : '#fbbf24' }}>
                  {e.threat_score}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace' }}>{e.src_ip}</div>
                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 1 }}>
                    {e.event_type} · {e.mitre_technique || 'no technique'} · {e.country || 'unknown location'}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: '#64748b', flexShrink: 0 }}>
                  {new Date(e.timestamp).toLocaleTimeString()}
                </div>
              </div>
            ))}
            {events.filter(e => e.threat_score >= 50).length === 0 && (
              <div style={{ color: '#64748b', fontSize: 12, textAlign: 'center', padding: 20 }}>
                No high-risk events yet
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}