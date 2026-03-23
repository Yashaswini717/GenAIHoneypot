import { useEffect, useState } from 'react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

const COLORS = ['#60a5fa', '#f87171', '#fbbf24', '#4ade80', '#a78bfa', '#34d399']

function MetricCard({ label, value, color = '#60a5fa' }) {
  return (
    <div className="card" style={{ textAlign: 'center' }}>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>{label}</div>
    </div>
  )
}

export default function Overview() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    axios.get('/api/events/stats').then(r => setStats(r.data))
  }, [])

  if (!stats) return <div style={{ color: '#64748b' }}>Loading...</div>

  const totalEvents = stats.by_type.reduce((a, b) => a + b.doc_count, 0)
  const topIP = stats.top_ips[0]?.key || '—'
  const avgScore = stats.avg_threat_score

  return (
    <div>
      <h2 style={{ marginBottom: 20, fontSize: 18, fontWeight: 600 }}>Overview</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
        <MetricCard label="Total Events"      value={totalEvents} />
        <MetricCard label="Avg Threat Score"  value={avgScore} color="#fbbf24" />
        <MetricCard label="Top Attacker IP"   value={topIP} color="#f87171" />
        <MetricCard label="Attack Types"      value={stats.by_type.length} color="#4ade80" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Events by type</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.by_type}>
              <XAxis dataKey="key" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2d3148' }} />
              <Bar dataKey="doc_count" fill="#60a5fa" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Top source IPs</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats.top_ips} layout="vertical">
              <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis dataKey="key" type="category" tick={{ fill: '#94a3b8', fontSize: 11 }} width={120} />
              <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2d3148' }} />
              <Bar dataKey="doc_count" fill="#f87171" radius={[0,4,4,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Events over time</div>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={stats.by_hour}>
            <XAxis dataKey="key_as_string"
              tickFormatter={v => new Date(v).getHours() + ':00'}
              tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#1a1d27', border: '1px solid #2d3148' }}
              labelFormatter={v => new Date(v).toLocaleString()} />
            <Bar dataKey="doc_count" fill="#4ade80" radius={[4,4,0,0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}