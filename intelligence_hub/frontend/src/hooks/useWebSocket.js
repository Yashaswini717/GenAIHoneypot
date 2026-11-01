import { useEffect, useRef, useState } from 'react'

export default function useWebSocket(url) {
  const [messages, setMessages] = useState([])
  const [connected, setConnected] = useState(false)
  const ws = useRef(null)

  useEffect(() => {
    // Set on cleanup. Closing the socket there used to fire onclose, whose
    // reconnect opened a new socket after the component had gone: React's
    // StrictMode mounts twice in development, so two sockets stayed live and
    // every event was shown twice, and each return to the page leaked another.
    let disposed = false
    let retry = null

    function connect() {
      const socket = new WebSocket(url)
      ws.current = socket

      socket.onopen = () => {
        if (!disposed) setConnected(true)
      }
      socket.onclose = () => {
        if (disposed) return
        setConnected(false)
        retry = setTimeout(connect, 3000)
      }
      socket.onmessage = (e) => {
        if (disposed) return
        try {
          const data = JSON.parse(e.data)
          if (data.type === 'ping') return
          setMessages(prev => [data, ...prev].slice(0, 200))
        } catch {}
      }
    }
    connect()
    return () => {
      disposed = true
      clearTimeout(retry)
      ws.current?.close()
    }
  }, [url])

  return { messages, connected }
}