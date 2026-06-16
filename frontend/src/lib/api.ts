import type { Alert } from './types'
import type { NewsItem } from './types'

const BASE_URL = import.meta.env.DEV ? 'http://localhost:8080/api' : '/api'

const fetchOptions: RequestInit = {
  credentials: 'include'
}

export async function getNews(): Promise<NewsItem[]> {
  const response = await fetch(`${BASE_URL}/news`, fetchOptions)
  if (!response.ok) {
    return []
  }
  return response.json()
}

export async function login(username: string, password: string): Promise<boolean> {
  const response = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username, password })
  })
  return response.ok
}

export async function logout(): Promise<void> {
  await fetch(`${BASE_URL}/auth/logout`, {
    method: 'POST',
    credentials: 'include'
  })
}

export async function checkAuth(): Promise<{ authenticated: boolean; role: string }> {
  try {
    const response = await fetch(`${BASE_URL}/auth/status`, fetchOptions)
    if (!response.ok) {
      return { authenticated: false, role: '' }
    }
    const data = await response.json()
    return { authenticated: true, role: data.role ?? '' }
  } catch {
    return { authenticated: false, role: '' }
  }
}

export async function getAlerts(): Promise<Alert[]> {
  const response = await fetch(`${BASE_URL}/alerts`, fetchOptions)
  return response.json()
}

export async function getAlertById(id: number): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts/${id}`, fetchOptions)
  return response.json()
}

export async function createAlert(alert: Omit<Alert, 'id'>): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(alert)
  })
  return response.json()
}

export async function updateAlert(id: number, alert: Alert): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(alert)
  })
  return response.json()
}

export async function deleteAlert(id: number): Promise<void> {
  await fetch(`${BASE_URL}/alerts/${id}`, {
    method: 'DELETE',
    credentials: 'include'
  })
}