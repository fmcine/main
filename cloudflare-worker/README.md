# Cloudflare Worker 설정 가이드 (GitHub Pages 연동용)

GitHub Pages는 정적 파일만 호스팅하므로, 로그인 검증과 Gemini API 호출을 Cloudflare Worker에서 처리합니다.

## 1. Worker 코드 붙여넣기
1. [Cloudflare Dashboard](https://dash.cloudflare.com) → **Workers & Pages** 이동
2. 기존 Worker(`perplexity-proxy`)를 선택하거나 새 Worker 생성
3. **Edit code**를 열고 `cloudflare-worker/worker.js` 전체 내용을 복사해 붙여넣은 뒤 **Deploy** 클릭

## 2. Gemini API 키 시크릿 등록
1. 해당 Worker의 **Settings → Variables and Secrets** 이동
2. **Add** 클릭 후 아래 항목 추가:
   - Type: **Secret**
   - Variable name: `GEMINI_API_KEY`
   - Value: 새로 발급한 Google Gemini API 키
3. **Save / Deploy** 클릭

## 3. GitHub Pages에서 사용
- 기존 `perplexity-proxy.fmcine.workers.dev`를 사용했다면, 변경 사항을 GitHub에 푸시한 뒤 GitHub Pages를 열면 자동으로 연결됩니다.
- 새 Worker 이름으로 생성했다면, GitHub Pages 로그인 화면 하단의 **백엔드 서버 연결** 입력란에 새 `https://...workers.dev` 주소를 입력하고 **연결**을 누르세요.
