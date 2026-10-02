import express from 'express'
import router from './src/route.js'

const PORT = Number(process.env.PORT) || 3000

const app = express()
app.disable('x-powered-by')

app.use(express.json({ limit: '200kb' }))
app.use(router)

// Malformed or oversized JSON bodies get a short JSON error instead of
// Express's default HTML page (which can include a stack trace).
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500
  console.error(JSON.stringify({ event: 'request_error', status, reason: err.type || err.message }))
  res.status(status).json({ error: status < 500 ? 'invalid request' : 'internal server error' })
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
