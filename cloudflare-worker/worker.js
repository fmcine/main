/**
 * Gemini Assistant - Cloudflare Worker Backend
 *
 * Required Cloudflare Worker Secret (Settings > Variables and Secrets):
 *   - GEMINI_API_KEY : Google Gemini API Key (Secret)
 *
 * Optional Secrets / Variables:
 *   - SESSION_SECRET  : Custom HMAC secret for signing session tokens
 *   - ALLOWED_ORIGINS : Comma-separated extra CORS origins (https://*.github.io is allowed automatically)
 */

const MODEL_NAME = 'gemini-4-hydrogen';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

// PBKDF2-SHA256 salted hashes (synced with /auth/credentials.json, no plaintext credentials)
const DEFAULT_CREDENTIALS = {
  iterations: 100000,
  keylen: 32,
  user: {
    idSalt: '445f983038b33e9c7b5a96ca3f36b583',
    idHash: 'ef14f3b1b36a14c531b6a815532de75e8947c6290fabf511698b84376cc2e7a5',
    passwordSalt: '2418a20ba73048d7f4188f61e732ad83',
    passwordHash: '2f9a49b5e7f0efae1be94104660d60e426d5f3c9def1852dda9dcac216f53fe6',
  },
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function verifyPbkdf2(input, saltHex, expectedHashHex, iterations, keylen) {
  if (typeof input !== 'string' || !saltHex || !expectedHashHex) return false;
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(input),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: hexToBytes(saltHex),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    keylen * 8
  );
  const derived = new Uint8Array(derivedBits);
  const expected = hexToBytes(expectedHashHex);
  return timingSafeEqual(derived, expected);
}

function getCredentialsConfig(env) {
  if (env.CREDENTIALS_JSON) {
    try {
      const parsed = JSON.parse(env.CREDENTIALS_JSON);
      if (parsed?.pbkdf2?.user) return parsed.pbkdf2;
      if (parsed?.user) return parsed;
    } catch {
      // Fallback to default hashed credentials
    }
  }
  return DEFAULT_CREDENTIALS;
}

async function verifyCredentials(id, password, env) {
  const cfg = getCredentialsConfig(env);
  const idValid = await verifyPbkdf2(
    id,
    cfg.user.idSalt,
    cfg.user.idHash,
    cfg.iterations,
    cfg.keylen
  );
  const pwValid = await verifyPbkdf2(
    password,
    cfg.user.passwordSalt,
    cfg.user.passwordHash,
    cfg.iterations,
    cfg.keylen
  );
  return idValid && pwValid;
}

async function getHmacKey(env) {
  const cfg = getCredentialsConfig(env);
  const secretStr =
    (env.SESSION_SECRET || '').trim() ||
    `gemini-worker-session::${cfg.user.idHash}::${cfg.user.passwordHash}`;
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(secretStr),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signSessionToken(payloadObj, env) {
  const payloadBytes = encoder.encode(JSON.stringify(payloadObj));
  const payloadB64 = bytesToBase64Url(payloadBytes);
  const key = await getHmacKey(env);
  const sigBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
  const sigB64 = bytesToBase64Url(new Uint8Array(sigBuf));
  return `${payloadB64}.${sigB64}`;
}

async function verifySessionToken(token, env) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [payloadB64, sigB64] = token.split('.');
  if (!payloadB64 || !sigB64) return null;

  try {
    const key = await getHmacKey(env);
    const expectedBuf = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadB64));
    const expected = new Uint8Array(expectedBuf);
    const actual = base64UrlToBytes(sigB64);
    if (!timingSafeEqual(actual, expected)) return null;

    const payload = JSON.parse(decoder.decode(base64UrlToBytes(payloadB64)));
    if (!payload?.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function isAllowedOrigin(origin, env) {
  if (!origin) return false;
  const extra = (env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (extra.includes('*') || extra.includes(origin)) return true;

  try {
    const parsed = new URL(origin);
    if (parsed.protocol === 'https:' && parsed.hostname.endsWith('.github.io')) return true;
    if (parsed.protocol === 'https:' && parsed.hostname.endsWith('.run.app')) return true;
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') return true;
  } catch {
    return false;
  }
  return false;
}

function corsHeaders(request, env, extra = {}) {
  const origin = request.headers.get('Origin');
  const headers = { ...extra };
  if (origin && isAllowedOrigin(origin, env)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
  }
  return headers;
}

function jsonResponse(request, env, body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders(request, env, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    }),
  });
}

function extractBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function formatUpstreamError(status, rawText) {
  let detail = rawText;
  let reason = '';
  try {
    const parsed = JSON.parse(rawText);
    detail = parsed?.error?.message || rawText;
    reason = parsed?.error?.details?.[0]?.reason || '';
  } catch {
    // Plain text
  }

  if (reason === 'CONSUMER_SUSPENDED' || detail.includes('has been suspended')) {
    return `연결된 Google Cloud 프로젝트가 정지 상태입니다. 새 프로젝트의 GEMINI_API_KEY를 Cloudflare Worker Secret에 등록해 주세요.\n(상세: ${detail})`;
  }
  if (status === 403 || status === 400) {
    return `API 키가 유효하지 않거나 요청이 거부되었습니다. Cloudflare Worker의 GEMINI_API_KEY 시크릿을 확인해 주세요.\n(상세: ${detail})`;
  }
  if (status === 429) {
    return `요청 한도를 초과했습니다. 잠시 후 다시 시도해 주세요.\n(상세: ${detail})`;
  }
  return detail || `Gemini API 오류 (HTTP ${status})`;
}

async function handleGeminiGenerate(request, env) {
  const token = extractBearerToken(request);
  const session = await verifySessionToken(token, env);
  if (!session) {
    return jsonResponse(request, env, { error: { message: '로그인이 필요합니다.' } }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(request, env, { error: { message: '잘못된 요청 형식입니다.' } }, 400);
  }

  const prompt = typeof body?.prompt === 'string' ? body.prompt.trim() : '';
  if (!prompt) {
    return jsonResponse(request, env, { error: { message: '프롬프트를 입력해 주세요.' } }, 400);
  }

  const apiKey = (env.GEMINI_API_KEY || '').trim();
  if (!apiKey) {
    return jsonResponse(
      request,
      env,
      {
        error: {
          message: 'Cloudflare Worker에 GEMINI_API_KEY 시크릿이 설정되어 있지 않습니다.',
        },
      },
      500
    );
  }

  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:streamGenerateContent?alt=sse`;
  const upstreamRes = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey,
      'User-Agent': 'aistudio-build',
    },
    body: JSON.stringify({
      systemInstruction: {
        parts: [
          {
            text: '당신은 친절하고 정확한 AI 어시스턴트 Gemini입니다. 사용자의 질문에 명확하고 자연스럽게 답변해 주세요.',
          },
        ],
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }],
        },
      ],
    }),
  });

  if (!upstreamRes.ok || !upstreamRes.body) {
    const errText = await upstreamRes.text().catch(() => '');
    const message = formatUpstreamError(upstreamRes.status, errText);
    return jsonResponse(request, env, { error: { message } }, upstreamRes.status || 500);
  }

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();

  (async () => {
    const reader = upstreamRes.body.getReader();
    let buffer = '';
    let hasText = false;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data:')) continue;
          const payloadStr = line.slice(5).trim();
          if (!payloadStr || payloadStr === '[DONE]') continue;

          try {
            const parsed = JSON.parse(payloadStr);
            const parts = parsed?.candidates?.[0]?.content?.parts || [];
            for (const part of parts) {
              if (part?.thought) continue;
              if (typeof part?.text === 'string' && part.text.length > 0) {
                hasText = true;
                await writer.write(encoder.encode(`data: ${JSON.stringify({ text: part.text })}\n\n`));
              }
            }
          } catch {
            // Ignore partial JSON frames
          }
        }
      }

      if (!hasText) {
        await writer.write(
          encoder.encode(
            `data: ${JSON.stringify({ error: '답변을 생성하지 못했습니다. 잠시 후 다시 시도해 주세요.' })}\n\n`
          )
        );
      } else {
        await writer.write(encoder.encode(`data: ${JSON.stringify({ done: true })}\n\n`));
      }
    } catch (err) {
      await writer.write(
        encoder.encode(
          `data: ${JSON.stringify({ error: err?.message || '스트리밍 중 오류가 발생했습니다.' })}\n\n`
        )
      );
    } finally {
      await writer.close();
    }
  })();

  return new Response(readable, {
    status: 200,
    headers: corsHeaders(request, env, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
    }),
  });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request, env),
      });
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'GET' && (pathname === '/api/health' || pathname === '/')) {
      return jsonResponse(request, env, { ok: true, service: 'gemini-assistant-worker' });
    }

    if (request.method === 'POST' && pathname === '/api/auth/login') {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, env, { error: { message: '잘못된 요청 형식입니다.' } }, 400);
      }

      const id = typeof body?.id === 'string' ? body.id.trim().toLowerCase() : '';
      const password = typeof body?.password === 'string' ? body.password.trim() : '';

      if (!id || !password) {
        return jsonResponse(
          request,
          env,
          { error: { message: '아이디와 비밀번호를 모두 입력해 주세요.' } },
          400
        );
      }

      const ok = await verifyCredentials(id, password, env);
      if (!ok) {
        return jsonResponse(
          request,
          env,
          { error: { message: '아이디 또는 비밀번호가 올바르지 않습니다.' } },
          401
        );
      }

      const token = await signSessionToken(
        {
          sub: 'owner',
          iat: Date.now(),
          exp: Date.now() + SESSION_TTL_MS,
        },
        env
      );

      return jsonResponse(request, env, { ok: true, token });
    }

    if (request.method === 'GET' && pathname === '/api/auth/me') {
      const token = extractBearerToken(request);
      const session = await verifySessionToken(token, env);
      return jsonResponse(request, env, { authenticated: Boolean(session) });
    }

    if (request.method === 'POST' && pathname === '/api/auth/logout') {
      return jsonResponse(request, env, { ok: true });
    }

    if (request.method === 'POST' && pathname === '/api/gemini/generate') {
      return handleGeminiGenerate(request, env);
    }

    return jsonResponse(request, env, { error: { message: 'Not Found' } }, 404);
  },
};
