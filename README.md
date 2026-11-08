# Smart Buckler

> 현재 개발 초기 단계입니다. 아직 실서비스에 쓸 수 있는 상태가 아닙니다.

smart-buckler(가칭)는 가볍고 셀프호스팅 가능한 리버스 프록시입니다. AI 에이전트를 이용한 자동화 공격을 막아 줍니다.
보호하려는 웹 서비스 앞에 두면 들어오는 요청을 규칙으로 검사하고 세션의 행동을 분석합니다. 공격자를 속이는 미끼를 깔고 위험도에 맞춰 단계적으로 대응합니다.

## 왜 만들었나

LLM 기반 에이전트가 등장하면서 취약점 탐색과 공격이 빠르고 값싸게 자동화되고 있습니다. 반면 이를 막는 보안 제품은 대부분 대기업을 위한 것이라 비싸고 운영하려면 전담 인력이 필요합니다.
l2-buckler는 보안 예산도 담당자도 없는 작은 조직이 설치만으로 기본적인 방어를 갖추게 하는 것을 목표로 합니다.

## 이런 분들을 위해 만듭니다

- 보안 예산과 보안 담당자가 없는 소규모 조직
- 서버를 직접 운영하는 개인 개발자와 소규모 팀
- Java, ASP.NET, PHP 같은 레거시 웹앱을 코드 수정 없이 보호하고 싶은 조직

## 설계 원칙

1. **설치하고 잊어도 됩니다.** 기본 설정만으로 안전하게 동작합니다. 튜닝하지 않아도 오탐 때문에 정상 사용자가 막히지 않도록 합니다.
2. **오탐보다 미탐이 낫습니다.** 의심스러운 단계에서는 차단하지 않고 챌린지를 보냅니다. 즉시 차단은 미끼 경로 접근처럼 확신이 높은 경우에만 합니다.
3. **가볍습니다.** 단일 정적 바이너리로 1 vCPU, 512MB 메모리에서 동작합니다. 요청당 추가 지연은 p99 기준 10ms 이내를 목표로 합니다.
4. **외부로 아무것도 보내지 않습니다.** 텔레메트리가 없습니다. 위협 피드, 알림, LLM 같은 외부 연동은 모두 명시적으로 켜야만 동작합니다.
5. **탐지 엔진의 오류가 서비스 장애로 이어지지 않습니다.** 탐지 모듈에 문제가 생기면 요청은 그대로 통과시키고 오류만 기록합니다(fail-open).
6. **사람의 말로 설명합니다.** 이벤트와 리포트는 보안 비전문가도 읽고 이해할 수 있게 작성합니다.

## 주요 기능

- **WAF 규칙 검사**: Coraza v3 엔진과 OWASP CRS로 SQL 인젝션, XSS, 경로 조작 같은 일반적인 웹 공격을 탐지합니다. 기본값은 탐지 전용이고 설정으로 차단 모드를 켤 수 있습니다.
- **행위 분석**: 정적 리소스 없이 HTML만 요청하는 패턴, 높은 404 비율, 체계적인 경로 열거, 기계적으로 일정한 요청 간격 등 자동화 도구의 흔적을 점수로 계산합니다.
- **기만(deception)**: 실제 서비스에 없는 미끼 경로와 사람 눈에 보이지 않는 숨김 링크, 허니토큰을 설치마다 무작위로 만들어 둡니다. 정상 사용자는 건드릴 일이 없으므로 여기에 접근하면 공격으로 판단합니다.
- **단계적 대응**: 위험도에 따라 기록, 작업 증명(PoW) 챌린지, 속도 제한, 차단 순으로 대응 강도를 높입니다.
- **리포트와 알림**: 이벤트를 모아 하루 단위 요약을 만들고 이메일, 슬랙, 텔레그램으로 알립니다. LLM을 연결하면 요약 맨 앞에 AI가 쓴 두세 문장을 붙일 수 있습니다(선택).
- **관리 화면**: 오늘의 현황, 이벤트 검색, 차단 목록과 해제, 미끼 경로를 브라우저에서 봅니다. 프록시와 다른 포트에서 열리고, JavaScript 없이 서버가 그립니다.

## AI 요약 (선택)

일일 요약에 LLM이 쓴 짧은 해설을 붙일 수 있습니다. 기본으로 꺼져 있습니다.

- **어떤 LLM이든 연결할 수 있습니다.** API 형식만 고르고 모델은 운영자가 정합니다.
  - `openai`: OpenAI 호환 API. Ollama, LM Studio, vLLM 같은 로컬 모델과 이 형식을 지원하는 외부 API
  - `anthropic`: Claude Messages API
- **숫자만 보냅니다.** 모델에는 날짜, 집계 숫자, WAF 규칙 설명(CRS의 고정 문구), 자동화 징후 이름만 전달합니다. 요청 경로, IP, User-Agent, 개인정보는 보내지 않습니다. 공격자가 요청에 숨긴 문장으로 요약을 조작하지 못하게 하려는 목적도 있습니다.
- **요청 처리에는 쓰지 않습니다.** LLM은 하루 한 번 리포트를 만들 때만 부릅니다. 탐지나 차단 판단에는 관여하지 않으므로 요청 지연이 늘지 않습니다. 모델이 느리거나 멈춰도 서비스에는 영향이 없습니다.
- **실패해도 리포트는 나갑니다.** 모델이 응답하지 않으면 AI 해설 없이 숫자 요약만 보냅니다.
- **외부 라이브러리를 쓰지 않습니다.** 두 형식 모두 Go 표준 라이브러리로 호출합니다.

```yaml
report:
  llm:
    enabled: true
    provider: anthropic        # 또는 openai (Ollama 등)
    model: "claude-opus-5-5"
    api_key: "<API 키>"         # 원격 주소에는 https만 허용
    reasoning_effort: "low"    # 추론 모델이 생각하는 정도
```

외부 API를 쓰면 제공사는 이 서버가 l2-buckler를 쓴다는 사실과 하루 공격 규모를 알게 됩니다. 설정 방법과 주의할 점은 [시작하기 문서](docs/getting-started.md#ai-요약-선택)에 있습니다.

## 하지 않는 것

- 금융권이나 대기업용 엔터프라이즈 보안 제품
- LLM 프롬프트 인젝션 방어(LLM 방화벽)
- SIEM, EDR 대체
- 클라우드 SaaS 형태의 서비스 (셀프호스팅이 기본입니다)

## 개인정보 보호

- 요청 본문 전체는 기록하지 않습니다.
- Authorization, Cookie, 비밀번호 필드는 로그에서 마스킹합니다.
- 주민등록번호, 카드번호, 계좌번호, 전화번호 형태의 값은 로그와 리포트에서 마스킹합니다.

## 설치

Linux 서버에 단일 바이너리로 설치하는 방법입니다. 보호할 웹 서비스가 같은 서버의 `127.0.0.1:3000`에서 돌고 있다고 가정합니다.

### 1. 빌드

Go(버전은 `go.mod` 기준)가 있으면 어디서든 빌드할 수 있습니다. cgo를 쓰지 않으므로 다른 OS에서 Linux용으로 바로 빌드됩니다.

```sh
make build                                   # 지금 쓰는 OS용, bin/l2-buckler
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w" -o l2-buckler ./cmd/l2-buckler   # Linux x86_64용
```

ARM 서버(`uname -m`이 `aarch64`)라면 `GOARCH=arm64`로 빌드하세요.

### 2. 서버에 설치

```sh
sudo install -m 755 l2-buckler /usr/local/bin/l2-buckler
sudo useradd --system --no-create-home --shell /usr/sbin/nologin l2-buckler
sudo mkdir -p /etc/l2-buckler /var/lib/l2-buckler
sudo chown l2-buckler: /var/lib/l2-buckler
```

### 3. 설정

`/etc/l2-buckler/l2-buckler.yaml`을 만듭니다. 적지 않은 항목은 기본값을 씁니다. 전체 항목과 설명은 [configs/dev.yaml](configs/dev.yaml)에 있습니다.

```yaml
listen: ":8080"                     # 사용자가 접속할 포트
upstream: "http://127.0.0.1:3000"   # 보호할 서비스

store:
  path: "/var/lib/l2-buckler/l2-buckler.db"

log:
  level: info

report:
  timezone: "Asia/Seoul"

admin:
  enabled: true
  listen: "127.0.0.1:8081"          # 관리 화면. 서버 안에서만 열립니다
```

알림 토큰이나 API 키를 넣는다면 다른 사용자가 읽지 못하게 권한을 좁힙니다.

```sh
sudo chown root:l2-buckler /etc/l2-buckler/l2-buckler.yaml
sudo chmod 640 /etc/l2-buckler/l2-buckler.yaml
```

### 4. 관리자 비밀번호

관리 화면은 비밀번호를 정하기 전까지 닫혀 있습니다. 12자 이상으로 두 번 입력합니다.

```sh
sudo -u l2-buckler l2-buckler admin-password -config /etc/l2-buckler/l2-buckler.yaml
```

### 5. 실행

먼저 앞에 띄워서 확인합니다. 로그에 `l2-buckler started`와 `admin UI started`가 나오면 정상입니다.

```sh
sudo -u l2-buckler l2-buckler -config /etc/l2-buckler/l2-buckler.yaml
```

확인이 끝나면 systemd 서비스로 등록합니다. `/etc/systemd/system/l2-buckler.service`:

```ini
[Unit]
Description=l2-buckler reverse proxy
After=network-online.target
Wants=network-online.target

[Service]
User=l2-buckler
ExecStart=/usr/local/bin/l2-buckler -config /etc/l2-buckler/l2-buckler.yaml
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/l2-buckler
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now l2-buckler
journalctl -u l2-buckler -f
```

### 6. 관리 화면 접속

관리 화면은 서버 자신에게서만 열려 있습니다. 내 컴퓨터에서 SSH 터널을 연 뒤 브라우저로 `http://127.0.0.1:8081`에 접속합니다.

```sh
ssh -N -L 8081:127.0.0.1:8081 사용자@서버
```

TLS 리버스 프록시를 앞에 두고 도메인으로 접속하려면 그 호스트 이름을 `admin.hosts`에 적으세요.

### 7. 동작 확인

서버 안에서 아래 요청을 보내면 관리 화면의 이벤트와 차트에 기록이 나타납니다.

```sh
curl -s -o /dev/null http://127.0.0.1:8080/
curl -s -o /dev/null "http://127.0.0.1:8080/?id=1%27%20OR%201=1--"   # WAF 차단 예정으로 기록
```

관리 화면의 **미끼** 메뉴에 있는 경로를 요청하면 그 주소가 바로 차단되고, **차단** 화면에서 풀 수 있습니다. 내 PC에서 시험하면 사무실 공인 IP가 막혀 같은 IP를 쓰는 사람도 함께 막히니, 서버 안에서 `127.0.0.1`로 시험하세요.

### 문제가 생기면

| 증상 | 확인할 것 |
|---|---|
| `address already in use` | `listen`이나 `admin.listen` 포트를 다른 프로세스가 쓰고 있습니다. |
| 로그인 화면에 비밀번호가 없다고 나옴 | 4번을 같은 설정 파일(`-config`)로 실행했는지 확인하세요. 비밀번호는 `store.path`의 DB에 저장됩니다. |
| 421 Misdirected Request | 허용되지 않은 호스트 이름으로 접속했습니다. 터널로 `127.0.0.1:8081`에 접속하거나 `admin.hosts`에 추가하세요. |
| 로그인이 막힘 | 5번 실패하면 15분 동안 막힙니다. |
| DB를 열 수 없다는 오류 | `/var/lib/l2-buckler`의 소유자가 `l2-buckler`인지 확인하세요. |

WAF 차단 모드, 앞단 프록시(`trusted_proxies`), 미끼, 행위 점수, 알림, AI 요약 설정은 [시작하기 문서](docs/getting-started.md)에 있습니다.

### 개발용 실행

```sh
make run                       # configs/dev.yaml로 실행
make run CONFIG=다른설정.yaml
```

## 기술 스택

Go, Coraza v3 + OWASP CRS, SQLite(`modernc.org/sqlite`, cgo 없음), YAML 설정, `log/slog` JSON 로그

## 라이선스

AGPL-3.0. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.

개발: (주)엘투소프트랩 (L2Softlab Inc)
