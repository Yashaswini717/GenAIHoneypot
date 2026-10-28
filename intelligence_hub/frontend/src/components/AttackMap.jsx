import { useEffect, useState } from 'react'
import axios from 'axios'
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'

// The map plots attackers that can be located. Most of the time, during
// development, none of them can be: lab traffic comes from RFC1918 addresses
// and will never geolocate. The old version showed an empty world and blamed a
// missing database, which was the wrong diagnosis in every local run and sent
// you looking for a file that was not the problem.
//
// So internal traffic is counted and named rather than dropped, and the empty
// state says which of the two reasons applies.

const RED = '#f87171'
const AMBER = '#fbbf24'
const MUTED = '#64748b'

function scoreColour(score) {
  if (score >= 90) return '#ef4444'
  if (score >= 70) return RED
  if (score >= 40) return AMBER
  return '#60a5fa'
}

// Several events usually share one address; one marker per attacker reads far
// better than five hundred stacked circles on the same pixel.
function groupByAddress(events) {
  const byIp = new Map()
  for (const e of events) {
    const current = byIp.get(e.src_ip)
    if (current) {
      current.hits += 1
      current.score = Math.max(current.score, e.threat_score || 0)
      if (e.timestamp > current.last) current.last = e.timestamp
    } else {
      byIp.set(e.src_ip, {
        ip: e.src_ip,
        lat: e.latitude,
        lon: e.longitude,
        country: e.country,
        city: e.city,
        score: e.threat_score || 0,
        hits: 1,
        last: e.timestamp,
      })
    }
  }
  return [...byIp.values()].sort((a, b) => b.hits - a.hits)
}

export default function AttackMap() {
  const [located, setLocated] = useState([])
  const [internal, setInternal] = useState([])
  const [total, setTotal] = useState(0)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await axios.get('/api/events/?limit=500')
        if (!alive) return
        const events = r.data.events || []
        setTotal(events.length)
        setLocated(groupByAddress(events.filter(e => e.latitude && e.longitude)))
        setInternal(groupByAddress(
          events.filter(e => !e.latitude && e.ip_scope && e.ip_scope !== 'public')
        ))
        setError(null)
      } catch (e) {
        if (alive) setError(e.message)
      }
    }
    load()
    const timer = setInterval(load, 20000)
    return () => { alive = false; clearInterval(timer) }
  }, [])

  const card = {
    background: '#141824', border: '1px solid #2d3148',
    borderRadius: 8, padding: '12px 16px',
  }

  return (
    <div>
      <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 6 }}>Attack Map</h2>
      <div style={{ fontSize: 12, color: MUTED, marginBottom: 14 }}>
        {located.length} located {located.length === 1 ? 'attacker' : 'attackers'}
        {internal.length > 0 && <> · {internal.length} internal (no location)</>}
        {' '}· {total} recent events
      </div>

      {error && (
        <div style={{ ...card, color: RED, marginBottom: 14 }}>
          Could not load events: {error}
        </div>
      )}

      {!error && located.length === 0 && (
        <div style={{ ...card, color: MUTED, marginBottom: 14, lineHeight: 1.6 }}>
          {internal.length > 0 ? (
            <>
              <strong style={{ color: AMBER }}>No external attackers yet.</strong> Every
              source so far is on a private network, which has no geographic location —
              expected while the honeypot runs locally. Markers appear once it is exposed
              publicly.
            </>
          ) : (
            <>
              <strong>No located events.</strong> Either nothing has been captured yet, or
              no city database is present in <code>intelligence_hub/geoip/</code>.
            </>
          )}
        </div>
      )}

      <div style={{ ...card, padding: 0, overflow: 'hidden', height: 'calc(100vh - 230px)' }}>
        <MapContainer
          center={[20, 0]}
          zoom={2}
          worldCopyJump
          style={{ height: '100%', width: '100%', background: '#0f1117' }}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; CartoDB · IP data &copy; <a href="https://db-ip.com">DB-IP</a>'
          />
          {located.map((a) => (
            <CircleMarker
              key={a.ip}
              center={[a.lat, a.lon]}
              radius={Math.min(18, 5 + Math.log2(a.hits + 1) * 3)}
              pathOptions={{
                color: scoreColour(a.score),
                fillColor: scoreColour(a.score),
                fillOpacity: 0.55,
                weight: 2,
              }}
            >
              <Popup>
                <div style={{ fontSize: 12, lineHeight: 1.5 }}>
                  <b>{a.ip}</b><br />
                  {[a.city, a.country].filter(Boolean).join(' · ') || 'location unknown'}<br />
                  {a.hits} {a.hits === 1 ? 'event' : 'events'} · max score {a.score}
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>

      {internal.length > 0 && (
        <div style={{ ...card, marginTop: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 8 }}>
            Internal sources — not plottable
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {internal.map(a => (
              <div key={a.ip} style={{
                background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 6,
                padding: '6px 10px', fontSize: 12,
              }}>
                <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{a.ip}</span>
                <span style={{ color: MUTED }}> · {a.hits} events · score {a.score}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
