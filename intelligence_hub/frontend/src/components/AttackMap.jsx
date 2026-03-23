import { useEffect, useState } from 'react'
import axios from 'axios'
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'

export default function AttackMap() {
  const [events, setEvents] = useState([])

  useEffect(() => {
    axios.get('/api/events/?limit=500').then(r => {
      const withGeo = r.data.events.filter(e => e.latitude && e.longitude)
      setEvents(withGeo)
    })
  }, [])

  return (
    <div>
      <h2 style={{ fontSize:18, fontWeight:600, marginBottom:16 }}>Attack Map</h2>
      {events.length === 0 && (
        <div className="card" style={{ color:'#64748b', marginBottom:16, padding:12 }}>
          No geo data yet — add GeoLite2-City.mmdb to /geoip/ folder and reingest logs
        </div>
      )}
      <div className="card" style={{ padding:0, overflow:'hidden', height:'calc(100vh - 160px)' }}>
        <MapContainer center={[20, 0]} zoom={2} style={{ height:'100%', width:'100%', background:'#0f1117' }}>
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; CartoDB'
          />
          {events.map((e, i) => (
            <CircleMarker key={i}
              center={[e.latitude, e.longitude]}
              radius={6}
              pathOptions={{ color:'#f87171', fillColor:'#f87171', fillOpacity:0.7 }}>
              <Popup>
                <div style={{ fontSize:12 }}>
                  <b>{e.src_ip}</b><br/>
                  {e.country} · {e.city}<br/>
                  {e.event_type} · score: {e.threat_score}
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>
    </div>
  )
}