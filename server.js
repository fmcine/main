import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

const PORT = Number(process.env.PORT) || 3000;
const HOST = '0.0.0.0';
const MODEL_NAME = 'gemini-4-hydrogen';

const CREDENTIALS_PATH = path.join(__dirname, 'auth', 'credentials.json');
const SESSION_COOKIE_NAME = 'gemini_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

const credentialsRaw = fs.readFileSync(CREDENTIALS_PATH, 'utf8');
const credentialsConfig = JSON.parse(credentialsRaw);

const SESSION_SECRET =
  (process.env.SESSION_SECRET || '').trim() ||
  crypto
    .createHash('sha256')
    .update(`gemini-assistant-session::${credentialsRaw}`)
    .digest('hex');

const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 20;
const LOGIN_WINDOW_MS = 5 * 60 * 1000;

app.use(express.json({ limit: '1mb' }));

function verifyScrypt(input, salt, expectedHex, keylen, params) {
  if (typeof input !== 'string' || !salt || !expectedHex) return false;
  const derived = crypto.scryptSync(input, salt, keylen, params);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function verifyCredentials(id, password) {
  const { keylen, params, user } = credentialsConfig;
  const idValid = verifyScrypt(id, user.idSalt, user.idHash, keylen, params);
  const pwValid = verifyScrypt(password, user.passwordSalt, user.passwordHash, keylen, params);
  return { ok: idValid && pwValid, idValid, pwValid };
}

function signSessionToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${signature}`;
}

function verifySessionToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');

  const sigBuf = Buffer.from(signature, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!parsed?.exp || Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;
    const key = part.slice(0, eqIndex).trim();
    const val = part.slice(eqIndex + 1).trim();
    if (key) {
      try {
        cookies[key] = decodeURIComponent(val);
      } catch {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}

function isHttpsRequest(req) {
  const proto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  const origin = String(req.headers.origin || '').toLowerCase();
  const referer = String(req.headers.referer || '').toLowerCase();
  return (
    req.secure ||
    proto.includes('https') ||
    origin.startsWith('https://') ||
    referer.startsWith('https://')
  );
}

function buildSessionCookie(token, maxAgeSeconds, secure) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) {
    parts.push('SameSite=None', 'Secure', 'Partitioned');
  } else {
    parts.push('SameSite=Lax');
  }
  return parts.join('; ');
}

function extractBearerToken(req) {
  const authHeader = req.headers.authorization;
  if (typeof authHeader !== 'string') return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function getAuthenticatedSession(req) {
  const bearerToken = extractBearerToken(req);
  if (bearerToken) {
    const session = verifySessionToken(bearerToken);
    if (session) return session;
  }
  const cookies = parseCookies(req.headers.cookie);
  const cookieToken = cookies[SESSION_COOKIE_NAME];
  return verifySessionToken(cookieToken);
}

function requireAuthApi(req, res, next) {
  const session = getAuthenticatedSession(req);
  if (!session) {
    return res.status(401).json({
      error: { message: '로그인이 필요합니다.' },
    });
  }
  req.session = session;
  next();
}

function getClientKey(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(clientKey) {
  const now = Date.now();
  const record = loginAttempts.get(clientKey);
  if (!record || now - record.windowStart > LOGIN_WINDOW_MS) {
    return { allowed: true };
  }
  if (record.count >= MAX_LOGIN_ATTEMPTS) {
    return { allowed: false };
  }
  return { allowed: true };
}

function recordFailedLogin(clientKey) {
  const now = Date.now();
  const record = loginAttempts.get(clientKey);
  if (!record || now - record.windowStart > LOGIN_WINDOW_MS) {
    loginAttempts.set(clientKey, { count: 1, windowStart: now });
  } else {
    record.count += 1;
  }
}

function clearFailedLogins(clientKey) {
  loginAttempts.delete(clientKey);
}

let aiClient = null;
let cachedApiKey = null;

function getAiClient() {
  const apiKey = (
    process.env.CUSTOM_GEMINI_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.GEMINI_API_KEY ||
    ''
  ).trim();
  if (!apiKey) {
    return null;
  }
  if (!aiClient || cachedApiKey !== apiKey) {
    cachedApiKey = apiKey;
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

function extractApiErrorDetail(rawMessage) {
  let current = rawMessage;
  let reason = '';

  for (let i = 0; i < 3; i++) {
    if (typeof current !== 'string') break;
    const trimmed = current.trim();
    if (!trimmed.startsWith('{')) break;
    try {
      const parsed = JSON.parse(trimmed);
      const nextMsg = parsed?.error?.message;
      const nextReason = parsed?.error?.details?.[0]?.reason;
      if (nextReason) reason = nextReason;
      if (typeof nextMsg === 'string' && nextMsg !== current) {
        current = nextMsg;
      } else {
        break;
      }
    } catch {
      break;
    }
  }

  return { detail: current, reason };
}

function formatGeminiError(err) {
  const status = Number(err?.status || err?.code) || 500;
  const rawMessage = err?.message || 'Gemini API 요청 중 오류가 발생했습니다.';
  const { detail, reason } = extractApiErrorDetail(rawMessage);

  if (reason === 'CONSUMER_SUSPENDED' || detail.includes('has been suspended')) {
    return {
      status: 403,
      message: `연결된 Google Cloud 프로젝트가 정지 상태입니다. 정지되지 않은 새 Google Cloud 프로젝트의 API 키를 Settings > Secrets의 GEMINI_API_KEY(또는 기본 키 변경이 안 될 경우 CUSTOM_GEMINI_API_KEY)에 등록해 주세요.\n(상세: ${detail})`,
    };
  }
  if (status === 403 || rawMessage.includes('PERMISSION_DENIED') || rawMessage.includes('API_KEY_INVALID')) {
    return {
      status: status === 403 ? 403 : 400,
      message: `API 키가 유효하지 않거나 권한이 없습니다. Settings > Secrets 패널에서 GEMINI_API_KEY를 확인해 주세요.\n(상세: ${detail})`,
    };
  }
  if (status === 429 || rawMessage.includes('RESOURCE_EXHAUSTED')) {
    return {
      status: 429,
      message: `요청 한도를 초과했습니다. 잠시 후 다시 시도해 주세요.\n(상세: ${detail})`,
    };
  }
  if (status === 404 || rawMessage.includes('NOT_FOUND')) {
    return {
      status: 404,
      message: `요청한 모델(${MODEL_NAME})을 찾을 수 없습니다.\n(상세: ${detail})`,
    };
  }
  return {
    status: status >= 400 && status < 600 ? status : 500,
    message: detail,
  };
}

async function generateStreamWithRetry(ai, params, maxRetries = 2) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await ai.models.generateContentStream(params);
    } catch (err) {
      lastError = err;
      const status = Number(err?.status || err?.code);
      const isRetryable = status === 429 || status === 503 || status === 500;
      if (!isRetryable || attempt === maxRetries) {
        throw err;
      }
      const delayMs = 500 * Math.pow(2, attempt);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

// Auth API endpoints
app.post('/api/auth/login', (req, res) => {
  const clientKey = getClientKey(req);
  if (!checkRateLimit(clientKey).allowed) {
    return res.status(429).json({
      error: { message: '로그인 시도가 너무 많습니다. 5분 후 다시 시도해 주세요.' },
    });
  }

  const id = typeof req.body?.id === 'string' ? req.body.id.trim().toLowerCase() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password.trim() : '';

  if (!id || !password) {
    return res.status(400).json({
      error: { message: '아이디와 비밀번호를 모두 입력해 주세요.' },
    });
  }

  const check = verifyCredentials(id, password);
  if (!check.ok) {
    console.warn(`Login failed (idValid=${check.idValid}, pwValid=${check.pwValid})`);
    recordFailedLogin(clientKey);
    return res.status(401).json({
      error: { message: '아이디 또는 비밀번호가 올바르지 않습니다.' },
    });
  }

  clearFailedLogins(clientKey);
  const token = signSessionToken({
    sub: 'owner',
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
  });

  res.setHeader(
    'Set-Cookie',
    buildSessionCookie(token, SESSION_TTL_SECONDS, isHttpsRequest(req))
  );
  return res.json({ ok: true, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', buildSessionCookie('', 0, isHttpsRequest(req)));
  return res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = getAuthenticatedSession(req);
  return res.json({ authenticated: Boolean(session) });
});

// Protected Gemini API endpoint
app.post('/api/gemini/generate', requireAuthApi, async (req, res) => {
  const prompt = typeof req.body?.prompt === 'string' ? req.body.prompt.trim() : '';
  if (!prompt) {
    return res.status(400).json({ error: { message: '프롬프트를 입력해 주세요.' } });
  }

  const ai = getAiClient();
  if (!ai) {
    return res.status(500).json({
      error: {
        message: 'GEMINI_API_KEY가 설정되어 있지 않습니다. Settings > Secrets 패널에서 API 키를 확인해 주세요.',
      },
    });
  }

  try {
    const responseStream = await generateStreamWithRetry(ai, {
      model: MODEL_NAME,
      contents: prompt,
      config: {
        systemInstruction:
          '당신은 친절하고 정확한 AI 어시스턴트 Gemini입니다. 사용자의 질문에 명확하고 자연스럽게 답변해 주세요.',
      },
    });

    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    let hasText = false;
    for await (const chunk of responseStream) {
      const text = chunk.text;
      if (text) {
        hasText = true;
        res.write(`data: ${JSON.stringify({ text })}\n\n`);
      }
    }

    if (!hasText) {
      res.write(`data: ${JSON.stringify({ error: '답변을 생성하지 못했습니다. 잠시 후 다시 시도해 주세요.' })}\n\n`);
    } else {
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    }
    res.end();
  } catch (err) {
    const { status, message } = formatGeminiError(err);
    console.warn(`Gemini API error (${status}): ${message}`);
    if (!res.headersSent) {
      return res.status(status).json({ error: { message } });
    }
    res.write(`data: ${JSON.stringify({ error: message })}\n\n`);
    res.end();
  }
});

// Public PWA assets
const publicAssets = new Set(['/manifest.json', '/icon.png', '/sw.js']);

app.get(Array.from(publicAssets), (req, res) => {
  return res.sendFile(path.join(__dirname, req.path));
});

// Explicitly block sensitive files/directories
app.use((req, res, next) => {
  if (
    req.path.startsWith('/auth') ||
    req.path.startsWith('/node_modules') ||
    req.path.startsWith('/.env') ||
    req.path === '/server.js' ||
    req.path === '/package.json' ||
    req.path === '/package-lock.json' ||
    req.path === '/metadata.json'
  ) {
    return res.status(404).end();
  }
  next();
});

// Serve unified app entry (shows login gate before auth, Gemini Assistant after auth)
app.get(['/', '/login', '/index.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.sendFile(path.join(__dirname, 'index.html'));
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: { message: 'Not Found' } });
  }
  return res.redirect('/');
});

app.listen(PORT, HOST, () => {
  console.log(`Server listening on http://${HOST}:${PORT}`);
});
