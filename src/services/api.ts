/**
 * API service for IDS backend integration.
 * Replace the base URL with your actual ML/TL API endpoint.
 */

const API_BASE = "http://localhost:5000/api"

export interface DetectionRequest {
  packetData: string
  modelType: 'ml' | 'tl'
  features?: Record<string, number>
}

export interface DetectionResponse {
  prediction: 'malicious' | 'safe'
  confidence: number
  attackType?: string
}

export async function runDetection(
  request: DetectionRequest
): Promise<DetectionResponse> {
  const res = await fetch(`${API_BASE}/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })

  if (!res.ok) {
    throw new Error(`Detection failed: ${res.statusText}`)
  }

  return res.json()
}
