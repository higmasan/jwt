import { decodeBase64Url, encodeBase64Url } from 'https://deno.land/std@0.224.0/encoding/base64url.ts'

interface Payload {
  iss: string
  exp: number
}

export async function encode(payload: Payload, secretKey: string): Promise<string> {
  const header = generateHeader('HS512')
  const payloadStr = generatePayload(payload)
  const signature = await generateSignature(header, payloadStr, secretKey)

  return `${header}.${payloadStr}.${signature}`
}

export async function verify(token: string, secretKey: string): Promise<boolean> {
  const parts = token.split('.')
  if (parts.length !== 3) return false

  const [header, payload, signature] = parts

  try {
    const decodePayload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)))
    if (decodePayload.exp && decodePayload.exp < Math.floor(Date.now() / 1000)) {
      return false // Token expired
    }
  } catch {
    return false // Invalid payload
  }
  const expectedSignature = await generateSignature(header, payload, secretKey)

  return signature === expectedSignature
}

function generateHeader(algorithm: string): string {
  const header = {
    alg: algorithm,
    typ: 'JWT',
  }
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(header)))
}

function generatePayload(payload: Payload): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
}

async function generateSignature(header: string, payload: string, secretKey: string): Promise<string> {
  const message = `${header}.${payload}`
  const signature = await crypto.subtle.sign(
    {
      name: 'HMAC',
      hash: 'SHA-512',
    },
    await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secretKey),
      {
        name: 'HMAC',
        hash: 'SHA-512'
      },
      false,
      ['sign']
    ),
    new TextEncoder().encode(message)
  )
  return encodeBase64Url(new Uint8Array(signature))
}
