import LiveFeed from '../components/LiveFeed.jsx'
import Charts from '../components/Charts.jsx'
import IOCPanel from '../components/IOCPanel.jsx'
import AlertQueue from '../components/AlertQueue.jsx'
import SessionTimeline from '../components/SessionTimeline.jsx'
import AttackMap from '../components/AttackMap.jsx'
import Overview from '../components/Overview.jsx'

export default function Dashboard({ activePage }) {
  const pages = {
    dashboard: <Overview />,
    livefeed:  <LiveFeed />,
    sessions:  <SessionTimeline />,
    iocs:      <IOCPanel />,
    alerts:    <AlertQueue />,
    map:       <AttackMap />,
  }
  return pages[activePage] || <Overview />
}