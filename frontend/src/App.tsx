import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import AttackList from './pages/AttackList'
import AttackDetail from './pages/AttackDetail'
import AnalyzeURL from './pages/AnalyzeURL'
import UploadPCAP from './pages/UploadPCAP'

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/attacks" element={<AttackList />} />
          <Route path="/attacks/:id" element={<AttackDetail />} />
          <Route path="/analyze" element={<AnalyzeURL />} />
          <Route path="/upload" element={<UploadPCAP />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
