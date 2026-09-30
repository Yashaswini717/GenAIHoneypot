import { useEffect, useState } from 'react'
import axios from 'axios'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

// The page the research claim rests on. Everything else in this dashboard
// describes what attackers did; this measures whether the deception held them.
//
// Two things it deliberately refuses to do:
//   - show an uplift figure when only one arm has data, because a ratio
//     against an empty control arm is a claim with nothing behind it
//   - hide the scanner traffic, because a honeypot mostly hit by scanners is
//     a true fact about the deployment

const ADAPTIVE = '#4ade80'
const CONTROL = '#60a5fa'
const MUTED = '#64748b'
const DEPTH_COLORS = ['#60a5fa', '#fbbf24', '#f87171']

function fmtDuration(seconds) {
  if (!seconds || seconds < 1) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`
  const h = Math.floor(seconds / 3600)
  const m = Math.round((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function MetricCard({ label, value, sub, color = '#60a5fa' }) {
  return (
    <div style={{
      background: 'linear-gradient(135deg, #1a1d27 0%, #1e2235 100%)',
      border: '1px solid #2d3148', borderTop: `3px solid ${color}`,
      borderRadius: 8, padding: '16px 20px',
      display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0,
    }}>
      <div style={{ fontSize: 11, color: MUTED, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</div>
      <div style={{ fontSize: 30, fontWeight: 700, color, lineHeight: 1.1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: '#94a3b8' }}>{sub}</div>}
    </div>
  )
}

function ArmColumn({ title, data, color, empty }) {
  const rows = [
    ['Visits', data.visits],
    ['Engaged visits', data.engaged_visits],
    ['Median visit', fmtDuration(data.median_visit_seconds)],
    ['Mean visit', fmtDuration(data.mean_visit_seconds)],
    ['Longest visit', fmtDuration(data.longest_visit_seconds)],
    ['Commands / visit', data.mean_commands],
    ['Pivot rate', `${Math.round(data.pivot_rate * 100)}%`],
    ['Return rate', `${Math.round(data.return_rate * 100)}%`],
  ]
  return (
    <div style={{
      background: '#141824', border: `1px solid ${empty ? '#2d3148' : color}`,
      borderRadius: 8, padding: '16px 20px', flex: '1 1 260px', minWidth: 0,
      opacity: empty ? 0.55 : 1,
    }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: empty ? MUTED : color, marginBottom: 12 }}>
        {title}{empty && <span style={{ fontWeight: 400, fontSize: 11 }}> — no data yet</span>}
      </div>
      {rows.map(([k, v]) => (
        <div key={k} style={{
          display: 'flex', justifyContent: 'space-between', gap: 12,
          padding: '6px 0', borderBottom: '1px solid #1e2235', fontSize: 13,
        }}>
          <span style={{ color: '#94a3b8' }}>{k}</span>
          <span style={{ color: '#e2e8f0', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{v}</span>
        </div>
      ))}
    </div>
  )
}

export default function Retention() {
  const [data, setData] = useState(null)
  const [visits, setVisits] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const [summary, detail] = await Promise.all([
          axios.get('/api/retention/'),
          axios.get('/api/retention/visits?limit=12'),
        ])
        if (!alive) return
        setData(summary.data)
        setVisits(detail.data.visits || [])
        setError(null)
      } catch (e) {
        if (alive) setError(e.message)
      }
    }
    load()
    const timer = setInterval(load, 15000)
    return () => { alive = false; clearInterval(timer) }
  }, [])

  if (error) {
    return <div style={{ padding: 24, color: '#f87171' }}>
      Could not load retention data: {error}
    </div>
  }
  if (!data) {
    return <div style={{ padding: 24, color: MUTED }}>Loading retention data…</div>
  }

  const o = data.overall
  const cmp = data.comparison
  const chart = visits.slice(0, 10).map((v, i) => ({
    // Never truncate an address. slice(-9) turned 172.23.0.1 into
    // 72.23.0.1, which reads as a different host entirely.
    name: `${v.attacker} #${i + 1}`,
    seconds: Math.round(v.dwell_seconds),
    depth: v.depth,
  }))

  return (
    <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h2 style={{ margin: 0, fontSize: 20, color: '#e2e8f0' }}>Attacker Retention</h2>
        <p style={{ margin: '6px 0 0', fontSize: 13, color: MUTED, maxWidth: '70ch' }}>
          A visit ends after {Math.round(data.method.visit_gap_seconds / 60)} minutes of inactivity;
          coming back later starts a new one. Measured per attacker across every hop, so a pivot
          counts toward the same visit as the jump-host session that launched it.
        </p>
      </div>

      <div style={{
        display: 'grid', gap: 12,
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
      }}>
        <MetricCard label="Median visit" value={fmtDuration(o.median_visit_seconds)}
          sub={`${o.engaged_visits} engaged of ${o.visits} visits`} color={ADAPTIVE} />
        <MetricCard label="Longest visit" value={fmtDuration(o.longest_visit_seconds)}
          sub="single unbroken engagement" color="#fbbf24" />
        <MetricCard label="Commands / visit" value={o.mean_commands}
          sub="mean, engaged visits only" color="#f472b6" />
        <MetricCard label="Pivot rate" value={`${Math.round(o.pivot_rate * 100)}%`}
          sub={`${o.reached_erp} reached ERP · ${o.reached_db} reached DB`} color="#fb923c" />
        <MetricCard label="Return rate" value={`${Math.round(o.return_rate * 100)}%`}
          sub={`${o.attackers} distinct attackers`} color="#a78bfa" />
        <MetricCard label="Mean depth" value={o.mean_depth}
          sub="1 = jump only, 3 = database" color="#60a5fa" />
      </div>

      <div style={{
        background: cmp.comparable ? '#141824' : '#1a1508',
        border: `1px solid ${cmp.comparable ? '#2d3148' : '#78500f'}`,
        borderRadius: 8, padding: '14px 18px',
      }}>
        <div style={{ fontSize: 12, color: cmp.comparable ? '#94a3b8' : '#fbbf24', lineHeight: 1.5 }}>
          {cmp.comparable
            ? <><strong style={{ color: ADAPTIVE }}>{cmp.median_visit_uplift}×</strong> median visit length with adaptation on. {cmp.note}</>
            : <><strong>Not yet comparable.</strong> {cmp.note}</>}
          {!cmp.comparable && cmp.engaged_control > 0 && (
            <span style={{ color: MUTED }}>
              {' '}Engaged visits so far: {cmp.engaged_adaptive} adaptive,
              {' '}{cmp.engaged_control} control, {cmp.min_arm_visits} needed in each.
            </span>
          )}
        </div>
        {/* Shown whenever it is non-zero, next to the number it qualifies.
            Excluded visits mean the assignment moved while attackers were
            being measured, which the reader needs before quoting the uplift. */}
        {cmp.excluded_mixed_arm > 0 && (
          <div style={{ fontSize: 11, color: '#fbbf24', marginTop: 8 }}>
            {cmp.excluded_mixed_arm} visit{cmp.excluded_mixed_arm === 1 ? '' : 's'} excluded
            for spanning both arms.
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <ArmColumn title="Adaptive" data={data.by_arm.adaptive} color={ADAPTIVE}
          empty={data.by_arm.adaptive.visits === 0} />
        <ArmColumn title="Control (adaptation off)" data={data.by_arm.control} color={CONTROL}
          empty={data.by_arm.control.visits === 0} />
      </div>

      <div style={{ background: '#141824', border: '1px solid #2d3148', borderRadius: 8, padding: '16px 20px' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>Longest visits</div>
        <div style={{ fontSize: 11, color: MUTED, marginBottom: 14 }}>
          Bar colour is how deep they got: blue jump host, amber ERP, red database.
        </div>
        {chart.length === 0
          ? <div style={{ color: MUTED, fontSize: 13 }}>No visits recorded yet.</div>
          : <ResponsiveContainer width="100%" height={260}>
              <BarChart data={chart} margin={{ top: 4, right: 8, bottom: 4, left: 8 }}>
                <XAxis dataKey="name" tick={{ fill: MUTED, fontSize: 10 }} interval={0} angle={-25} textAnchor="end" height={58} />
                <YAxis tick={{ fill: MUTED, fontSize: 11 }} tickFormatter={fmtDuration} width={62} />
                <Tooltip
                  contentStyle={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 6, fontSize: 12 }}
                  formatter={(v, _n, p) => [fmtDuration(v), `depth ${p.payload.depth}`]}
                />
                <Bar dataKey="seconds" radius={[3, 3, 0, 0]}>
                  {chart.map((entry, i) => (
                    <Cell key={i} fill={DEPTH_COLORS[Math.min(entry.depth, 3) - 1]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>}
      </div>
    </div>
  )
}
