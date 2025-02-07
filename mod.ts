import { decodeBase64Url, encodeBase64Url } from 'https://deno.land/std@0.224.0/encoding/base64url.ts'

interface Payload {
  iss?: string,             // Issuer
  sub?: string,             // Subject
  aud?: string | string[],  // Audienct
  exp:  number,             // Expiration Time
  nbf?: number,
  iat?: number,
  jti?: string,
  [key: string]: string | string[] | number | boolean | undefined
}

type Algorithm = 'HS256' | 'HS384' | 'HS512'

/**
 * generate JWT
 * @param payload   - JWT payload
 * @param secretKey - Secret key
 * @param algorithm - Algorithm to use (defaults to 'HS256')
 * @returns generated JWT string
 * @example
 * ```typescript
 * const payload = {
 *   userId: '123',
 *   exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1時間後
 * };
 * const secretKey = 'your-secret-key';
 * const token = await encode(payload, secretKey);
 * console.log(token); // eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
 * ```
 */
export async function encode(
  payload: Payload,
  secretKey: string,
  algorithm: Algorithm = 'HS256'
): Promise<string> {
  const header = generateHeader(algorithm)
  const payloadStr = generatePayload(payload)
  const signature = await generateSignature(header, payloadStr, secretKey, algorithm)

  return `${header}.${payloadStr}.${signature}`
}

/**
 * validate JWT tokens.
 * @param token     - JWT token
 * @param secretKey - Secret key
 * @param algorithm - Algorithm to use (default is 'HS256')
 * @param leeway    - Time allowed for expiration (in seconds)
 * @returns - 'valid': token is valid, 'invalid': token is invalid, 'expired': token has expired
 * @example
 * ```typescript
 * const token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...';
 * const secretKey = 'your-secret-key';
 * const result = await verify(token, secretKey);
 * console.log(result); // 'valid' | 'invalid' | 'expired'
 * ```
 */
export async function verify(
  token: string,
  secretKey: string,
  algorithm: Algorithm = 'HS256',
  leeway: number = 0
): Promise<'valid' | 'invalid' | 'expired'> {
  const parts = token.split('.')
  if (parts.length !== 3) return 'invalid'

  const [header, payload, signature] = parts

  try {
    const decodePayload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)))
    const currentTime = Math.floor(Date.now() / 1000)
    if (decodePayload.exp && decodePayload.exp + leeway < currentTime) {
      return 'expired' // Token expired
    }
  } catch (error) {
    console.error("JWT Payload parsing error:", error)
    return 'invalid' // Invalid payload
  }
  const expectedSignature = await generateSignature(header, payload, secretKey, algorithm)

  return signature === expectedSignature ? 'valid' : 'invalid'
}

function generateHeader(algorithm: Algorithm): string {
  const header = {
    alg: algorithm,
    typ: 'JWT',
  }
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(header)))
}

function generatePayload(payload: Payload): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)))
}

async function generateSignature(
  header: string,
  payload: string,
  secretKey: string,
  algorithm: Algorithm
): Promise<string> {
  const message = `${header}.${payload}`
  const hashAlgorithm: "SHA-256" | "SHA-384" | "SHA-512" = algorithm === 'HS256' ? 'SHA-256' :
                                                          algorithm === 'HS384' ? 'SHA-384' : 
                                                          'SHA-512';
  const signature = await crypto.subtle.sign(
    {
      name: 'HMAC',
      hash: hashAlgorithm,
    },
    await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secretKey),
      {
        name: 'HMAC',
        hash: hashAlgorithm
      },
      false,
      ['sign']
    ),
    new TextEncoder().encode(message)
  )
  return encodeBase64Url(new Uint8Array(signature))
}
