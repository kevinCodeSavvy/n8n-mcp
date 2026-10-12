import crypto from 'crypto';

export interface JWTPayload {
  sub: string;
  iss: string;
  aud: string;
  jti?: string;
  iat: number;
  exp?: number;
}

/**
 * Simple JWT validation without external dependencies
 * Validates HS256 signed JWTs from n8n
 */
export function validateJWT(token: string, secret: string): JWTPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Verify signature
    const data = headerB64 + '.' + payloadB64;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('base64url');

    if (signatureB64 !== expectedSignature) {
      return null;
    }

    // Decode payload
    const payloadJson = Buffer.from(payloadB64, 'base64url').toString('utf-8');
    const payload: JWTPayload = JSON.parse(payloadJson);

    // Check expiration
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    // Validate audience
    if (payload.aud !== 'mcp-server-api' && payload.aud !== 'public-api') {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}
