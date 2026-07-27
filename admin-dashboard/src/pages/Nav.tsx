import { NavLink, useNavigate } from 'react-router-dom'
import { clearToken } from '../api-client'

export default function Nav() {
  const navigate = useNavigate()
  const link = ({ isActive }: { isActive: boolean }) =>
    `px-3 py-2 rounded ${isActive ? 'bg-blue-600 text-white' : 'hover:bg-gray-200 dark:hover:bg-gray-800'}`

  return (
    <nav className="mb-6 flex items-center justify-between border-b border-gray-300 pb-3 dark:border-gray-700">
      <div className="flex gap-2">
        <NavLink to="/tokens" className={link}>
          Tokens
        </NavLink>
        <NavLink to="/audit" className={link}>
          Audit log
        </NavLink>
      </div>
      <button
        onClick={() => {
          clearToken()
          navigate('/login')
        }}
        className="text-sm text-gray-500 hover:underline"
      >
        Sign out
      </button>
    </nav>
  )
}
