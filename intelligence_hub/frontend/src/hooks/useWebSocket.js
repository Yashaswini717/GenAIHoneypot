import { useEffect, useRef, useState } from 'react'

export default function useWebSocket(url) {
  const [messages, setMessages] = useState([])
  const [connected, setConnected] = useState(false)
  const ws = useRef(null)

  useEffect(() => {
    function connect() {
      ws.current = new WebSocket(url)

      ws.current.onopen = () => setConnected(true)
      ws.current.onclose = () => {
        setConnected(false)
        setTimeout(connect, 3000)
      }
      ws.current.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.type === 'ping') return
          setMessages(prev => [data, ...prev].slice(0, 200))
        } catch {}
      }
    }
    connect()
    return () => ws.current?.close()
  }, [url])

  return { messages, connected }
}