import type { Alert } from './types'

const BASE_URL = 'http://localhost:8080/api'

export async function getAlerts(): Promise<Alert[]> {
  const response = await fetch(`${BASE_URL}/alerts`)
  return response.json()
}

export async function getAlertById(id: number): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts/${id}`)
  return response.json()
}

export async function createAlert(alert: Omit<Alert, 'id'>): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert)
  })
  return response.json()
}

export async function updateAlert(id: number, alert: Alert): Promise<Alert> {
  const response = await fetch(`${BASE_URL}/alerts/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alert)
  })
  return response.json()
}

export async function deleteAlert(id: number): Promise<void> {
  await fetch(`${BASE_URL}/alerts/${id}`, {
    method: 'DELETE'
  })
}