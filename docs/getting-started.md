# 시작하기

이 문서는 smart_buckler를 빌드하고 웹 서비스 앞에 두는 방법을 설명합니다.
현재 4단계(리버스 프록시, WAF, 이벤트 기록, 미끼 경로, 행위 점수와 챌린지, 일일 요약과 알림)까지 구현되어 있습니다.

## 빌드

Go가 설치되어 있어야 합니다. 버전은 `go.mod`를 따릅니다.

```sh
make build
```

`bin/smart_buckler` 단일 실행 파일이 만들어집니다. cgo를 쓰지 않으므로 다른 라이브러리 없이 바로 실행됩니다.

## 설정

YAML 파일 하나로 설정합니다. 꼭 적어야 하는 값은 `upstream` 하나뿐입니다.

```yaml
listen: ":8080"                      # smart_buckler가 요청을 받을 주소
upstream: "http://127.0.0.1:3000"    # 보호할 웹 서비스 주소
trusted_proxies: []                  # smart_buckler 앞에 있는 프록시 주소 (아래 설명 참고)

deception:
  enabled: true                      # 미끼 경로 사용 여부
  block_duration: 1h                 # 미끼에 접근한 클라이언트를 차단할 시간
  reserved_paths: []                 # 실제 서비스 경로 접두어. 미끼가 이 경로와 겹치지 않게 함

score:
  mode: challenge                    # challenge 또는 detect
  threshold: 10                      # 이 점수 이상이면 챌린지
  weights: {}                        # 신호별 가중치. 적은 항목만 기본값을 덮어씀

challenge:
  difficulty: 16                     # 작업 증명 난이도(8~24)
  pass_duration: 24h                 # 챌린지를 통과한 클라이언트를 다시 묻지 않는 시간

waf:
  mode: detect                       # detect 또는 block
  request_body_limit: 1048576        # 검사할 요청 본문 크기(바이트)

report:
  time: "09:00"                      # 전날 요약을 보낼 시각
  timezone: ""                       # 예: Asia/Seoul. 비우면 서버의 시간대

notify: {}                           # 알림 채널. 아래 "일일 요약과 알림" 참고

store:
  path: "smart_buckler.db"              # 이벤트를 저장할 SQLite 파일

log:
  level: info                        # debug, info, warn, error
```

설정 파일에 모르는 항목이 있으면 시작하지 않고 오류를 알립니다. 오타 때문에 설정이 조용히 무시되는 일을 막기 위해서입니다.

### WAF 모드

- `detect`(기본값): 요청을 막지 않고 기록만 합니다. 차단 모드였다면 막혔을 요청은 `would_block`으로 기록됩니다.
- `block`: OWASP CRS의 이상 점수가 기준을 넘는 요청을 403으로 막습니다.

처음에는 `detect`로 며칠 운영하면서 `would_block` 이벤트에 정상 요청이 섞여 있지 않은지 확인한 뒤 `block`으로 바꾸는 것을 권장합니다.

`request_body_limit`보다 큰 요청 본문은 앞부분만 검사하고 나머지는 그대로 전달합니다. 큰 파일 업로드가 막히지 않게 하기 위해서입니다.

### 앞단에 프록시가 있을 때 (`trusted_proxies`)

smart_buckler는 접속한 주소를 클라이언트로 봅니다. 앞에 Nginx, Cloudflare Tunnel, 로드밸런서 같은 프록시가 있으면 모든 요청이 그 프록시 주소에서 오는 것처럼 보입니다. 이 상태에서 미끼에 한 번만 접근해도 프록시 뒤의 모든 사용자가 함께 막힐 수 있습니다.

이런 구성이라면 프록시 주소를 꼭 적어 주세요.

```yaml
trusted_proxies: ["127.0.0.1", "10.0.0.0/8"]
```

이 주소에서 온 요청은 `X-Forwarded-For` 헤더로 실제 클라이언트를 찾습니다. 목록에 없는 주소가 보낸 `X-Forwarded-For`는 믿지 않습니다. 여기에 적은 주소는 미끼에 접근해도 차단하지 않고 경고만 남깁니다.

## 미끼 경로

처음 실행할 때 공격자가 노릴 만한 이름에 무작위 문자를 붙인 미끼 경로 4개를 만듭니다(예: `/config-backup-h4ej6o/`). 설치마다 다르고, 재시작해도 바뀌지 않습니다. 실행 로그의 `decoys active` 항목에서 확인할 수 있습니다.

미끼는 실제 서비스에 없는 경로이므로 정상 사용자가 접근할 일이 없습니다. 누군가 미끼에 접근하면 업스트림으로 보내지 않고, 그 클라이언트를 `block_duration` 동안 차단합니다. 차단 목록은 SQLite에 저장되어 재시작 후에도 유지됩니다.

공격 도구가 미끼를 찾게 만드는 통로는 두 가지입니다.

- **robots.txt**: 업스트림의 robots.txt 모든 그룹에 미끼를 `Disallow`로 추가합니다. 업스트림에 robots.txt가 없으면 새로 만들어 응답합니다. 규칙을 지키는 검색엔진은 미끼에 들어오지 않고, robots.txt를 공격 대상 목록으로 쓰는 도구는 걸립니다.
- **숨김 링크**: HTML 페이지의 `<body>` 바로 뒤에 미끼로 가는 링크를 하나 넣습니다. `hidden` 속성으로 화면에 보이지 않고, 스크린리더와 키보드 이동에서도 빠지며, `rel="nofollow"`가 붙습니다. 페이지 내용을 그대로 읽는 AI 에이전트와 크롤러가 이 링크를 따라오면 걸립니다.

숨김 링크는 미끼를 만들고 24시간이 지난 뒤부터 넣습니다. 검색엔진이 robots.txt를 최대 하루 동안 캐시하기 때문에, 새 robots.txt를 아직 모르는 검색엔진이 링크를 따라오는 일을 막기 위해서입니다.

브라우저가 미리 가져오기(`Sec-Purpose: prefetch`)로 미끼를 요청하면 차단하지 않고 404만 응답합니다.

### 실제 경로와 겹치지 않게 하기

미끼는 무작위 문자가 붙어 실제 경로와 겹칠 가능성이 거의 없습니다. 그래도 서비스에서 쓰는 경로 접두어를 `reserved_paths`에 적어 두면, 그 접두어로 시작하는 미끼는 만들지 않습니다. 이미 만들어진 미끼가 겹치면 다음 실행 때 새 미끼로 바꿉니다.

```yaml
deception:
  reserved_paths: ["/admin", "/api/"]
```

`/admin`처럼 적으면 `/admin-backup-...` 같은 미끼도 만들지 않습니다. 웹 서버가 경로를 앞부분 문자열로 비교하는 경우까지 피하기 위해서입니다.

### 압축과 캐시

HTML에 링크를 넣으려면 압축된 응답을 풀었다 다시 압축해야 합니다. 그래서 업스트림에 보내는 `Accept-Encoding`을 gzip으로 제한합니다. 업스트림이 brotli를 지원하더라도 gzip으로 응답하게 되고, 정적 파일도 마찬가지입니다. 링크를 넣은 페이지의 `ETag`는 약한 검증자(`W/`)로 바꿉니다.

## 행위 점수와 챌린지

smart_buckler는 클라이언트(IP 주소)마다 최근 2분 동안의 요청을 기억하고, 자동화 도구에서 흔히 보이는 행동을 찾아 점수를 매깁니다. 점수가 `threshold` 이상이 되면 다음 페이지 요청에 챌린지 화면을 보여 줍니다.

| 신호 | 기본 가중치 | 언제 켜지나 |
|---|---|---|
| `html_only` | 3 | 페이지를 5개 이상 받으면서 CSS, JS, 이미지는 하나도 받지 않음 |
| `high_404` | 6 | 정적 파일을 뺀 요청 10건 이상 중 절반 이상이 404 |
| `path_enumeration` | 6 | 1분 안에 서로 다른 경로 30개 이상 |
| `fast_requests` | 6 | 10초 안에 페이지 10개 이상 |
| `regular_interval` | 4 | 최근 페이지 요청 간격이 기계처럼 일정함 |
| `robots_disallowed` | 10 | robots.txt를 읽은 클라이언트가 업스트림 robots.txt에서 금지한 경로에 접근 |
| `error_retry` | 5 | 오류가 난 경로에 쿼리만 바꿔 5번 이상 다시 요청 |
| `waf_anomaly` | 10 | WAF가 차단 기준을 넘는 요청을 탐지함 |

신호 하나만으로는 대부분 기준에 못 미칩니다. 사람이 빠르게 여러 페이지를 넘기거나 오타로 404를 몇 번 내는 정도로는 챌린지가 나오지 않습니다. robots.txt 금지 경로 접근과 WAF 탐지만 단독으로 기준에 닿습니다. 브라우저는 robots.txt를 읽지 않기 때문입니다.

가중치를 바꾸려면 바꿀 항목만 적습니다. 0을 적으면 그 신호를 끕니다. 없는 신호 이름을 적으면 시작하지 않습니다.

```yaml
score:
  weights:
    html_only: 0       # 텍스트 위주 사이트라면 끄기
    high_404: 8
```

### 챌린지

챌린지는 브라우저가 몇 초 동안 계산 문제(SHA-256 작업 증명)를 풀게 하는 화면입니다. 사람은 잠깐 기다리기만 하면 원래 페이지로 돌아가고, 그 뒤 `pass_duration` 동안은 다시 묻지 않습니다. 대량으로 요청하는 도구는 요청마다 계산 비용을 치르게 됩니다. 같은 방식을 쓰는 Anubis를 참고했습니다.

- 챌린지는 브라우저 페이지 이동(GET, HTML을 받는 요청)에만 보여 줍니다. API 호출, 이미지, 폼 제출은 점수가 높아도 통과시키고 기록만 합니다. 이런 요청은 챌린지 화면을 보여 줄 수 없기 때문입니다.
- JavaScript가 꺼진 브라우저는 챌린지를 풀 수 없습니다.
- 통과 기록은 `l2b_pass` 쿠키에 담기며 IP 주소에 묶입니다. 모바일에서 네트워크가 바뀌면 다시 챌린지가 나올 수 있습니다.
- 챌린지 응답은 `/.l2b/pow` 경로로 받습니다. 이 경로는 업스트림에 전달하지 않습니다.
- `difficulty`를 1 올릴 때마다 계산량이 두 배가 됩니다. 기본값 16은 보통 브라우저에서 1초 안쪽입니다.

### 탐지 모드

`score.mode: detect`로 두면 챌린지를 보여 주지 않고 `would_challenge` 이벤트만 남깁니다. 정상 사용자가 걸리지 않는지 먼저 확인하고 싶을 때 씁니다.

## 실행

```sh
./bin/smart_buckler -config /etc/smart_buckler/smart_buckler.yaml
```

로그는 JSON 형식으로 표준 출력에 나옵니다. 종료 신호(SIGTERM, Ctrl+C)를 받으면 처리 중인 요청을 마치고, 남은 이벤트를 저장한 다음 종료합니다.

## 이벤트 확인

WAF 규칙에 걸리거나, 미끼에 접근하거나, 행위 점수가 기준을 넘은 요청은 SQLite 파일의 `events` 테이블에 쌓입니다.

```sh
sqlite3 smart_buckler.db \
  "SELECT datetime(ts/1000, 'unixepoch', 'localtime'), client_ip, method, path, status, action, score, signals, rules
   FROM events ORDER BY ts DESC LIMIT 20"
```

`action` 값의 뜻은 다음과 같습니다.

| 값 | 뜻 |
|---|---|
| `blocked` | 차단했습니다. |
| `would_block` | 탐지 모드라서 통과시켰지만, 차단 모드였다면 막았을 요청입니다. |
| `detected` | 규칙에 걸렸지만 차단 기준에는 못 미쳤습니다. |
| `trap_hit` | 미끼에 접근해서 차단했습니다. |
| `challenged` | 행위 점수가 기준을 넘어 챌린지를 보여 줬습니다. `score`와 `signals`에 점수와 켜진 신호가 있습니다. |
| `would_challenge` | 점수가 기준을 넘었지만 탐지 모드이거나 페이지 이동이 아니라서 통과시켰습니다. |
| `challenge_passed` | 챌린지를 풀었습니다. |

점수 이벤트는 같은 클라이언트에 대해 2분에 한 번만 남깁니다.

차단된 클라이언트가 그 뒤에 보내는 요청은 기록하지 않습니다. 차단된 봇은 짧은 시간에 수천 건을 보낼 수 있기 때문입니다. 현재 차단 목록은 `blocks` 테이블에서 볼 수 있습니다.

```sh
sqlite3 smart_buckler.db \
  "SELECT session_id, datetime(until/1000, 'unixepoch', 'localtime'), reason FROM blocks"
```

차단을 바로 풀려면 smart_buckler를 멈춘 뒤 해당 행을 지우고 다시 시작하세요.

차단 응답에는 `request id`가 함께 표시됩니다. 사용자가 차단 화면을 알려 오면 이 값으로 `events` 테이블의 `request_id`를 찾으면 됩니다.

### 기록하지 않는 것

- 요청 본문과 쿼리 문자열은 저장하지 않습니다.
- WAF 규칙에 걸린 실제 요청 값도 저장하지 않습니다. 규칙 번호와 설명만 남깁니다.
- 경로에 9자리 이상 이어진 숫자가 있으면 `[REDACTED]`로 바꿔 저장합니다. 주민등록번호, 카드번호, 계좌번호, 전화번호를 가리기 위해서입니다.

## 일일 요약과 알림

매일 `report.time`에 전날 하루 동안의 요약을 만들어 켜 둔 채널로 보냅니다. 요약에는 다음 내용이 들어갑니다.

- 미끼에 접근해 차단한 클라이언트 수, 챌린지를 받은 클라이언트 수와 그중 통과한 수, WAF가 막았거나 막았을 요청 수
- 가장 많이 걸린 클라이언트 IP, 가장 많이 노린 경로, 자주 걸린 WAF 규칙, 자주 나타난 자동화 징후 (각각 상위 5개)
- 챌린지를 통과한 비율이 높으면 사람이 걸렸을 수 있다는 안내

아무 일도 없던 날에도 "따로 알릴 일이 없었습니다"라는 요약을 보냅니다. smart_buckler가 살아 있다는 확인이 되기 때문입니다.

만든 요약은 SQLite의 `reports` 테이블에 날짜별로 남습니다. 같은 날의 요약은 한 번만 보내므로 재시작해도 중복으로 받지 않습니다. 발송 시각이 지난 뒤에 smart_buckler를 시작하면 놓친 전날 요약을 바로 보냅니다.

### 알림 채널

채널은 모두 꺼져 있고, 켠 채널로만 보냅니다. 한 채널이 실패해도 나머지 채널로는 보냅니다.

```yaml
notify:
  email:
    enabled: true
    host: "smtp.example.com"
    port: 587              # 465는 처음부터 TLS, 그 밖의 포트는 서버가 지원하면 STARTTLS
    username: "security@example.com"
    password: "앱 비밀번호"
    from: "smart_buckler <security@example.com>"
    to: ["ops@example.com"]
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."   # Incoming Webhook 주소
  telegram:
    enabled: true
    bot_token: "123456:ABC..."   # BotFather에서 받은 토큰
    chat_id: "-1001234567890"    # 메시지를 받을 대화방 ID
```

비밀번호와 토큰이 들어가므로 설정 파일은 smart_buckler 실행 계정만 읽을 수 있게 두세요(`chmod 600`). 이메일 비밀번호는 TLS 연결에서만 보냅니다(서버가 localhost인 경우는 예외).

요약에는 클라이언트 IP와 요청 경로가 들어갑니다. 알림을 받는 사람과 채널을 정할 때 참고하세요.

설정을 마쳤으면 테스트 메시지로 확인합니다.

```sh
./bin/smart_buckler notify-test -config smart_buckler.yaml
```

### 요약 미리 보기와 직접 보내기

```sh
./bin/smart_buckler report -config smart_buckler.yaml                    # 어제 요약을 화면에 출력
./bin/smart_buckler report -config smart_buckler.yaml -date 2026-10-31   # 특정 날짜
./bin/smart_buckler report -config smart_buckler.yaml -send              # 켜 둔 채널로 보내기
```

`-send`로 보낸 요약은 `reports` 테이블에 남기지 않으므로 정해진 시각의 발송에는 영향이 없습니다.

### AI 요약 (선택)

요약 맨 앞에 AI가 쓴 두세 문장을 붙일 수 있습니다. `provider`로 API 형식을 고릅니다.

- `openai`(기본): OpenAI 호환 API(`/v1/chat/completions`). 같은 서버의 [Ollama](https://ollama.com), LM Studio, vLLM 같은 로컬 모델과, 이 형식을 지원하는 외부 API에 쓸 수 있습니다.
- `anthropic`: Claude Messages API.

어떤 모델을 쓸지는 운영자가 정합니다. smart_buckler는 `model`과 `reasoning_effort`를 그대로 넘깁니다. 외부 라이브러리 없이 표준 라이브러리로 호출합니다.

로컬 Ollama:

```yaml
report:
  llm:
    enabled: true
    provider: openai
    model: "qwen3:4b"          # ollama pull로 받아 둔 모델
    reasoning_effort: "none"   # 아래 설명 참고
    timeout: 2m
```

Claude:

```yaml
report:
  llm:
    enabled: true
    provider: anthropic
    model: "claude-opus-5-5"
    api_key: "<Anthropic API 키>"
    reasoning_effort: "low"
    timeout: 1m
```

`url`을 비워 두면 `openai`는 `http://127.0.0.1:11434/v1`, `anthropic`은 `https://api.anthropic.com/v1`을 씁니다. 다른 서버나 외부 OpenAI 호환 API를 쓸 때만 적어 주세요.

- **보내는 내용**: 날짜, 집계 숫자, WAF 규칙 설명(CRS에 미리 정해진 영어 문구), 자동화 징후 이름만 보냅니다. 요청 경로, IP, User-Agent처럼 공격자가 마음대로 넣을 수 있는 값이나 개인정보는 보내지 않습니다. 공격자가 요청에 숨긴 문장으로 요약을 조작하지 못하게 하기 위해서이기도 합니다.
- **외부 API를 쓸 때**: 제공사는 이 서버가 smart_buckler를 쓴다는 사실과 하루 공격 규모를 알게 됩니다. 데이터 보관 정책은 제공사마다 다르니 확인한 뒤 켜 주세요. 원격 주소에 API 키를 보낼 때는 `https`만 허용합니다. 키가 들어 있는 설정 파일은 `chmod 600`으로 보호하세요.
- **`reasoning_effort`**: 추론 모델이 답하기 전에 생각하는 정도입니다. GPU 없이 CPU로 돌리면 생각 단계만으로 몇 분이 걸려 `timeout`을 넘길 수 있습니다.
  - `openai`: `none`, `minimal`, `low`, `medium`, `high`. Ollama의 qwen3 등은 `"none"`으로 생각 단계를 끄고, gpt-oss는 끌 수 없으므로 `"low"`를 권장합니다.
  - `anthropic`: `low`, `medium`, `high`, `xhigh`, `max`. 짧은 요약이므로 `"low"`면 충분합니다.
  - 비워 두면 모델 기본값을 따릅니다.
- AI 요약 아래에는 "정확한 내용은 아래 숫자를 기준으로 봐 주세요"라는 안내가 붙습니다. 숫자 목록은 AI를 거치지 않습니다.
- 모델마다 지시를 따르는 정도가 다릅니다. 요약이 아래 숫자를 되풀이하기만 한다면 다른 모델을 써 보세요.
- AI가 응답하지 않거나 오류가 나면 AI 요약 없이 보냅니다.
- 아무 일도 없던 날에는 모델을 부르지 않습니다.

## 관리 화면

브라우저에서 오늘의 현황, 이벤트, 차단 목록, 미끼 경로를 볼 수 있습니다. 프록시와 다른 주소(기본값 `127.0.0.1:8081`)에서 열리고, JavaScript 없이 서버가 그린 화면이라 가볍습니다.

### 비밀번호 정하기

처음에는 비밀번호가 없어서 관리 화면이 닫혀 있습니다. 서버에서 아래 명령을 실행해 비밀번호를 정하세요. 12자 이상이어야 하고, 두 번 입력합니다.

```sh
./bin/smart_buckler admin-password -config /etc/smart_buckler/smart_buckler.yaml
```

프록시가 실행 중이어도 바로 적용됩니다. 비밀번호를 바꾸면 이전에 로그인한 세션은 모두 끝납니다. 스크립트에서 쓸 때는 표준 입력으로 한 줄을 넘기면 됩니다.

### 접속하기

관리 화면은 기본적으로 서버 자신에게서만 접속할 수 있습니다. 다른 컴퓨터에서 보려면 SSH 터널을 쓰는 방법이 가장 간단합니다.

```sh
ssh -L 8081:127.0.0.1:8081 사용자@서버
```

그다음 내 컴퓨터의 브라우저에서 `http://127.0.0.1:8081`을 엽니다.

TLS를 처리하는 리버스 프록시(Caddy, nginx 등)를 앞에 두는 경우에는 그 프록시에서 쓰는 호스트 이름을 `admin.hosts`에 적으세요. 목록에 없는 Host로 온 요청은 거부합니다(DNS 리바인딩 방어). `admin.listen`을 루프백이 아닌 주소로 바꾸면 비밀번호가 평문으로 오가므로 기동 로그에 경고가 나옵니다.

```yaml
admin:
  enabled: true
  listen: "127.0.0.1:8081"
  hosts: []
  session_duration: 12h
```

### 화면 구성

- **개요**: 지금 차단 중인 주소 수, 오늘의 미끼 차단, 확인 화면, WAF 집계, 시간대별 막대그래프, 최근 7일, 많이 걸린 클라이언트와 경로, 보낸 일일 요약 목록. 막대에 마우스를 올리면 숫자가 나오고, "표로 보기"를 펼치면 같은 숫자를 표로 볼 수 있습니다. "오늘 요약 미리보기"는 AI 요약 없이 만들고 아무 데도 보내지 않습니다.
- **이벤트**: 날짜, 종류, IP, 경로로 찾습니다. 기본값은 가벼운 WAF 경고(`detected`)를 뺀 목록입니다. 항목을 누르면 무슨 일이었는지 쉬운 말로 설명합니다.
- **클라이언트**: 한 주소의 최근 7일 기록과 이벤트, 차단 상태.
- **차단**: 지금 차단 중인 주소와 남은 시간. 확인 단계를 거쳐 차단을 풀 수 있습니다. 해제는 `unblocked` 이벤트로 남습니다. 행위 점수 기록은 그대로라 같은 행동을 계속하면 다시 확인 화면이 나옵니다.
- **미끼**: 미끼 경로와 적중 수, 숨김 링크에 들어갔는지 여부.
- **설정**: 실행 정보와 현재 설정(비밀번호, 토큰, 웹훅 주소, API 키는 가림), 알림 테스트 버튼. 설정은 화면에서 바꿀 수 없습니다.

### 보안

- 로그인 5번 실패한 주소는 15분 동안 로그인할 수 없습니다.
- 세션 쿠키는 HttpOnly, SameSite=Strict이고, 모든 변경 요청은 CSRF 토큰과 Origin을 확인합니다.
- 화면에 나오는 경로, 호스트, 규칙 설명은 공격자가 조작할 수 있는 값이라 이스케이프하고 길면 자릅니다. 스크립트를 전혀 허용하지 않는 CSP를 보냅니다.
- 관리 화면에 문제가 생겨도 프록시는 계속 동작합니다. 관리 화면이 필요 없으면 `admin.enabled: false`로 끄세요.

## 알려진 제약

- 차단과 점수의 단위는 IP 주소입니다. 회사나 통신사 NAT처럼 여러 사람이 한 주소를 함께 쓰면, 그중 한 명이 미끼에 접근했을 때 모두 `block_duration` 동안 막힙니다. 점수도 함께 쌓이므로 사용자가 많은 NAT 뒤에서는 챌린지가 나올 수 있습니다.
- 행위 기록은 메모리에만 있어서 재시작하면 사라집니다. 기억하는 클라이언트 수는 최대 1만 개입니다.
- IP 주소로 직접 접속하면 CRS 920350 규칙("Host header is a numeric IP address")이 `detected`로 기록됩니다. 차단 기준에는 못 미치는 경고입니다.
- 업스트림 응답은 검사하지 않습니다.
- 요약과 관리 화면 문구는 현재 한국어만 있습니다.
- 관리 화면의 시간대별 집계는 정시 단위입니다. 30분 단위 시간대(예: 인도)에서는 막대가 30분씩 어긋납니다.
