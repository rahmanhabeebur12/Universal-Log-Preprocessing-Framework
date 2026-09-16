const base = '/api/v1'

async function request(path, options = {}) {
  let response
  try {
    response = await fetch(base + path, options)
  } catch {
    throw new Error('Processing API is unavailable. Check the local FastAPI service.')
  }
  const contentType = response.headers.get('content-type') || ''
  const body = contentType.includes('application/json') ? await response.json() : await response.text()
  if (!response.ok) {
    const detail = typeof body === 'object' ? body.detail : body
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail || `HTTP ${response.status}`))
  }
  return body
}

export const api = {
  process: raw_event => request('/process', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ raw_event }),
  }),
  upload: file => {
    const body = new FormData()
    body.append('file', file)
    return request('/upload', { method: 'POST', body })
  },
  events: params => request('/events?' + new URLSearchParams(params)),
  event: id => request(`/events/${encodeURIComponent(id)}`),
  integrity: id => request(`/events/${encodeURIComponent(id)}/integrity`),
  stats: () => request('/stats'),
  parsers: () => request('/parsers'),
  exportUrl: format => `${base}/export/${format}`,
}
