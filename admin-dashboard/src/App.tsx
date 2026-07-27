import { Navigate, Route, Routes } from 'react-router-dom'
import Login from './pages/Login'
import Tokens from './pages/Tokens'
import AuditLog from './pages/AuditLog'
import { getToken } from './api-client'

function RequireToken({ children }: { children: React.ReactNode }) {
  return getToken() ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/tokens"
        element={
          <RequireToken>
            <Tokens />
          </RequireToken>
        }
      />
      <Route
        path="/audit"
        element={
          <RequireToken>
            <AuditLog />
          </RequireToken>
        }
      />
      <Route path="*" element={<Navigate to={getToken() ? '/tokens' : '/login'} replace />} />
    </Routes>
  )
}
