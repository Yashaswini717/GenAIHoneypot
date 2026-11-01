import { useState, useRef } from 'react'

export default function IngestLogs() {
  const [lines, setLines]       = useState([])
  const [fileName, setFileName] = useState('')
  const [log, setLog]           = useState([])
  const [running, setRunning]   = useState(false)
  const [counts, setCounts]     = useState({ ok: 0, err: 0 })
  const [progress, setProgress] = useState(0)
  const [done, setDone]         = useState(false)
  const [dragOver, setDragOver] = useState(false)
  // The hub's OPERATOR_TOKEN. Held in memory only: it is the one credential
  // that lets events in without a signature, so it is not written to storage.
  const [token, setToken]       = useState('')
  const fileRef = useRef()

  const handleFile = (file) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      const parsed = e.target.result.split('\n').filter(l => l.trim())
      setLines(parsed)
      setFileName(file.name)
      setDone(false)
      setLog([])
      setCounts({ ok: 0, err: 0 })
      setProgress(0)
    }
    reader.readAsText(file)
  }

  const clearFile = () => {
    setLines([])
    setFileName('')
    setLog([])
    setCounts({ ok: 0, err: 0 })
    setProgress(0)
    setDone(false)
    fileRef.current.value = ''
  }

  const addLog = (msg, type) => {
    setLog(prev => [...prev, { msg, type, time: new Date().toLocaleTimeString() }])
  }

  const startIngest = async () => {
    if (!lines.length || running) return
    const BATCH = 50
    setRunning(true)
    setDone(false)
    setLog([])
    setCounts({ ok: 0, err: 0 })
    setProgress(0)

    let ok = 0, err = 0

    for (let i = 0; i < lines.length; i += BATCH) {
      const chunk = lines.slice(i, i + BATCH)
      const body  = chunk.join('\n')
      const pct   = Math.min(Math.round(((i + BATCH) / lines.length) * 100), 100)
      setProgress(pct)

      try {
        // Through the Vite proxy like every other call, not straight at
        // :8000 -- which only worked when the browser and the backend
        // happened to share a host.
        const headers = { 'Content-Type': 'application/x-ndjson' }
        if (token.trim()) headers.Authorization = `Bearer ${token.trim()}`
        const res = await fetch('/api/ingest/batch', { method: 'POST', headers, body })

        let data
        try { data = await res.json() }
        catch { data = {} }

        if (res.status === 401 || res.status === 403) {
          // Every remaining batch would be refused the same way.
          err += lines.length - i
          addLog(`HTTP ${res.status} — ${data.detail || res.statusText}`, 'err')
          setCounts({ ok, err })
          break
        } else if (!res.ok) {
          err += chunk.length
          addLog(
            `Batch ${i + 1}–${Math.min(i + BATCH, lines.length)}: HTTP ${res.status} — ${data.detail || res.statusText}`,
            'err'
          )
        } else {
          const results = data.results || []
          const bOk  = results.filter(r => !r.error).length
          const bErr = results.filter(r =>  r.error).length
          ok  += bOk
          err += bErr
          if (bErr > 0) {
            const sample = results.find(r => r.error)
            addLog(
              `Batch ${i + 1}–${Math.min(i + BATCH, lines.length)}: ${bOk} ok · ${bErr} errors · e.g. "${sample.error}"`,
              'err'
            )
          } else {
            addLog(
              `Batch ${i + 1}–${Math.min(i + BATCH, lines.length)}: ${bOk} events ingested`,
              'ok'
            )
          }
        }
      } catch (e) {
        err += chunk.length
        addLog(`Network error on batch ${i + 1}: ${e.message} — is the backend running?`, 'err')
      }

      setCounts({ ok, err })
    }

    setRunning(false)
    setDone(true)
    setProgress(100)
  }

  return (
    <div style={{ maxWidth: 720, paddingBottom: 40 }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f1f5f9' }}>Ingest Logs</h1>
        <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
          Upload a Cowrie JSONL file · each line is one JSON event · sent to /ingest/batch
          as an operator upload, tagged <code>operator_upload</code> and left out of the
          retention figures
        </div>
      </div>

      {/* Operator token */}
      <div style={{ marginBottom: 16 }}>
        <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>
          Operator token <span style={{ color: '#64748b' }}>(OPERATOR_TOKEN in the hub's .env)</span>
        </label>
        <input
          type="password"
          autoComplete="off"
          value={token}
          onChange={e => setToken(e.target.value)}
          disabled={running}
          placeholder="Required to upload"
          style={{
            width: '100%', boxSizing: 'border-box', padding: '8px 12px', fontSize: 13,
            borderRadius: 6, border: '1px solid #2d3148', background: '#13151f', color: '#e2e8f0',
          }}
        />
      </div>

      {/* Drop zone */}
      <div
        onClick={() => fileRef.current.click()}
        onDragOver={e  => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={e => {
          e.preventDefault()
          setDragOver(false)
          if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0])
        }}
        style={{
          border:       `2px dashed ${dragOver ? '#60a5fa' : '#2d3148'}`,
          borderRadius: 8,
          padding:      '40px 24px',
          textAlign:    'center',
          cursor:       'pointer',
          background:   dragOver ? '#1e2235' : '#13151f',
          transition:   'all 0.15s',
          marginBottom: 16,
        }}
      >
        <div style={{ fontSize: 32, marginBottom: 8 }}>📂</div>
        <div style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>
          {fileName ? `✓  ${fileName}` : 'Drop your .jsonl file here, or click to browse'}
        </div>
        <div style={{ fontSize: 12, color: '#64748b', marginTop: 6 }}>
          {lines.length > 0
            ? `${lines.length} events loaded and ready`
            : 'One JSON object per line · Cowrie format'}
        </div>
        <input
          ref={fileRef}
          type="file"
          accept=".jsonl,.json,.log,.txt"
          style={{ display: 'none' }}
          onChange={e => { if (e.target.files[0]) handleFile(e.target.files[0]) }}
        />
      </div>

      {/* File info bar + progress */}
      {lines.length > 0 && (
        <div style={{
          background: '#1a1d27', border: '1px solid #2d3148',
          borderRadius: 8, padding: '12px 16px', marginBottom: 16,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 13, color: '#94a3b8' }}>
              {fileName}&nbsp;·&nbsp;{lines.length} events
            </span>
            {!running && (
              <button onClick={clearFile} style={{
                background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 12,
              }}>
                ✕ clear
              </button>
            )}
          </div>

          {/* Progress bar — only shown once ingest starts */}
          {(running || done) && (
            <div style={{ height: 6, background: '#2d3148', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                height:     '100%',
                borderRadius: 3,
                background: done ? '#4ade80' : '#60a5fa',
                width:      `${progress}%`,
                transition: 'width 0.3s',
              }} />
            </div>
          )}
        </div>
      )}

      {/* Start button */}
      <button
        onClick={startIngest}
        disabled={!lines.length || running}
        style={{
          padding:      '10px 28px',
          fontSize:     14,
          fontWeight:   600,
          borderRadius: 8,
          border:       'none',
          cursor:       lines.length && !running ? 'pointer' : 'not-allowed',
          background:   lines.length && !running ? '#60a5fa' : '#2d3148',
          color:        lines.length && !running ? '#0f172a' : '#64748b',
          transition:   'background 0.15s',
          marginBottom: 24,
        }}
      >
        {running ? `Processing… ${progress}%` : 'Start Ingest'}
      </button>

      {/* Log panel */}
      {log.length > 0 && (
        <div style={{ background: '#1a1d27', border: '1px solid #2d3148', borderRadius: 8, padding: 16 }}>

          {/* Summary counts */}
          <div style={{ display: 'flex', gap: 20, marginBottom: 12, fontSize: 12 }}>
            <span style={{ color: '#4ade80' }}>✓ {counts.ok} ok</span>
            <span style={{ color: '#f87171' }}>✗ {counts.err} errors</span>
            <span style={{ color: '#64748b' }}>{counts.ok + counts.err} / {lines.length} processed</span>
          </div>

          {/* Log rows */}
          <div style={{
            maxHeight: 300, overflowY: 'auto',
            display: 'flex', flexDirection: 'column', gap: 4,
          }}>
            {log.map((entry, i) => (
              <div key={i} style={{
                display:      'flex',
                alignItems:   'baseline',
                gap:          10,
                padding:      '5px 10px',
                borderRadius: 5,
                background:   entry.type === 'ok'
                  ? 'rgba(74,222,128,0.07)'
                  : 'rgba(248,113,113,0.07)',
              }}>
                <span style={{
                  fontSize:     10,
                  fontWeight:   600,
                  padding:      '2px 7px',
                  borderRadius: 20,
                  flexShrink:   0,
                  background:   entry.type === 'ok'
                    ? 'rgba(74,222,128,0.15)'
                    : 'rgba(248,113,113,0.15)',
                  color: entry.type === 'ok' ? '#4ade80' : '#f87171',
                }}>
                  {entry.type === 'ok' ? 'OK' : 'ERR'}
                </span>
                <span style={{ fontSize: 12, fontFamily: 'monospace', color: '#e2e8f0', flex: 1 }}>
                  {entry.msg}
                </span>
                <span style={{ fontSize: 11, color: '#64748b', flexShrink: 0 }}>
                  {entry.time}
                </span>
              </div>
            ))}
          </div>

          {/* Done banner */}
          {done && (
            <div style={{
              marginTop:  14,
              padding:    '10px 16px',
              borderRadius: 6,
              background: counts.err === 0 ? '#0f2318' : '#2d1a0e',
              border:     `1px solid ${counts.err === 0 ? '#166534' : '#92400e'}`,
              fontSize:   13,
              fontWeight: 600,
              color:      counts.err === 0 ? '#4ade80' : '#fbbf24',
            }}>
              {counts.err === 0
                ? '✓ All events ingested — click Overview in the sidebar to see your data.'
                : `⚠ Done with ${counts.err} errors — check the log above. Successful events are already in the dashboard.`}
            </div>
          )}
        </div>
      )}
    </div>
  )
}