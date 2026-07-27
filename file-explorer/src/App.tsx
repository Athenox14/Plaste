import { useState } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { getToken, clearToken } from './lib/api-client'
import Login from './components/Login'
import Explorer from './pages/Explorer'
import Favorites from './pages/Favorites'

function App() {
  const [loggedIn, setLoggedIn] = useState(!!getToken())

  if (!loggedIn) {
    return <Login onLoggedIn={() => setLoggedIn(true)} />
  }

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-white dark:bg-gray-900">
        <div className="flex justify-end p-2">
          <button
            onClick={() => {
              clearToken()
              setLoggedIn(false)
            }}
            className="text-xs text-gray-400 hover:text-red-500"
          >
            Log out
          </button>
        </div>
        <Routes>
          <Route path="/" element={<Explorer />} />
          <Route path="/favorites" element={<Favorites />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}

export default App
