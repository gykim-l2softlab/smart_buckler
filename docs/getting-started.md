# 시작하기

이 문서는 l2-buckler를 빌드하고 웹 서비스 앞에 두는 방법을 설명합니다.
현재 1단계(리버스 프록시, WAF, 이벤트 기록)까지 구현되어 있습니다.

## 빌드

Go가 설치되어 있어야 합니다. 버전은 `go.mod`를 따릅니다.

```sh
make build
```

`bin/l2-buckler` 단일 실행 파일이 만들어집니다. cgo를 쓰지 않으므로 다른 라이브러리 없이 바로 실행됩니다.

## 설정

YAML 파일 하나로 설정합니다. 꼭 적어야 하는 값은 `upstream` 하나뿐입니다.

```yaml
listen: ":8080"                      # l2-buckler가 요청을 받을 주소
upstream: "http://127.0.0.1:3000"    # 보호할 웹 서비스 주소

waf:
  mode: detect                       # detect 또는 block
  request_body_limit: 1048576        # 검사할 요청 본문 크기(바이트)

store:
  path: "l2-buckler.db"              # 이벤트를 저장할 SQLite 파일

log:
  level: info                        # debug, info, warn, error
```

설정 파일에 모르는 항목이 있으면 시작하지 않고 오류를 알립니다. 오타 때문에 설정이 조용히 무시되는 일을 막기 위해서입니다.

### WAF 모드

- `detect`(기본값): 요청을 막지 않고 기록만 합니다. 차단 모드였다면 막혔을 요청은 `would_block`으로 기록됩니다.
- `block`: OWASP CRS의 이상 점수가 기준을 넘는 요청을 403으로 막습니다.

처음에는 `detect`로 며칠 운영하면서 `would_block` 이벤트에 정상 요청이 섞여 있지 않은지 확인한 뒤 `block`으로 바꾸는 것을 권장합니다.

`request_body_limit`보다 큰 요청 본문은 앞부분만 검사하고 나머지는 그대로 전달합니다. 큰 파일 업로드가 막히지 않게 하기 위해서입니다.

## 실행

```sh
./bin/l2-buckler -config /etc/l2-buckler/l2-buckler.yaml
```

로그는 JSON 형식으로 표준 출력에 나옵니다. 종료 신호(SIGTERM, Ctrl+C)를 받으면 처리 중인 요청을 마치고, 남은 이벤트를 저장한 다음 종료합니다.

## 이벤트 확인

WAF 규칙에 걸린 요청은 SQLite 파일의 `events` 테이블에 쌓입니다.

```sh
sqlite3 l2-buckler.db \
  "SELECT datetime(ts/1000, 'unixepoch', 'localtime'), client_ip, method, path, status, action, rules
   FROM events ORDER BY ts DESC LIMIT 20"
```

`action` 값의 뜻은 다음과 같습니다.

| 값 | 뜻 |
|---|---|
| `blocked` | 차단했습니다. |
| `would_block` | 탐지 모드라서 통과시켰지만, 차단 모드였다면 막았을 요청입니다. |
| `detected` | 규칙에 걸렸지만 차단 기준에는 못 미쳤습니다. |

차단 응답에는 `request id`가 함께 표시됩니다. 사용자가 차단 화면을 알려 오면 이 값으로 `events` 테이블의 `request_id`를 찾으면 됩니다.

### 기록하지 않는 것

- 요청 본문과 쿼리 문자열은 저장하지 않습니다.
- WAF 규칙에 걸린 실제 요청 값도 저장하지 않습니다. 규칙 번호와 설명만 남깁니다.
- 경로에 9자리 이상 이어진 숫자가 있으면 `[REDACTED]`로 바꿔 저장합니다. 주민등록번호, 카드번호, 계좌번호, 전화번호를 가리기 위해서입니다.

## 알려진 제약

- 클라이언트 IP는 접속한 주소를 그대로 씁니다. l2-buckler 앞에 다른 프록시나 로드밸런서가 있으면 모든 요청이 그 프록시의 IP로 기록됩니다.
- IP 주소로 직접 접속하면 CRS 920350 규칙("Host header is a numeric IP address")이 `detected`로 기록됩니다. 차단 기준에는 못 미치는 경고입니다.
- 업스트림 응답은 검사하지 않습니다.
