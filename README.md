# 🛡️ StealerWatcher (Lightweight Heuristic EDR Engine)

**StealerWatcher**는 제한된 자원을 가진 ARM 기반 리눅스 서버(Odroid M1S 등) 환경에 최적화된 초경량 파일 무결성 모니터링(FIM) 및 휴리스틱 기반 침입 탐지 시스템입니다. 
주로 `.env` 파일이나 중요 인증 키를 노리는 인포스틸러(Infostealer)의 악의적인 파일 시스템 접근(생성/수정)을 실시간으로 감지하고 점수화하여 알림을 보냅니다.

## ⚙️ Core Architecture

본 엔진은 3개의 독립적인 모듈이 내부 큐(Queue)를 통해 데이터를 주고받는 **이벤트 주도(Event-Driven) 파이프라인**으로 설계되었습니다.

1. **Collector (`FileWatcher`)**: `watchdog`을 활용하여 OS 커널 레벨의 파일 시스템 이벤트를 실시간으로 후킹합니다.
2. **Analyzer (`EventAnalyzer`)**: 단순 탐지를 넘어, 사전에 정의된 타겟 파일(`.env` 등)과 행위(Create/Modify)에 가중치를 부여해 위협 점수(Score 60~70 등)를 산출하는 휴리스틱 분석기입니다.
3. **Notifier (`ConsoleNotifier`, `MatrixNotifier`)**: **Strategy Pattern**을 적용하여 알림 방식을 유연하게 분리했습니다. E2EE(종단간 암호화)가 적용된 개인 Matrix 서버망을 통해 안전하게 경보를 전송할 수 있습니다.



## 🚀 Features

* **Zero-Bloatware**: 무거운 상용 보안 에이전트를 대체하기 위해 순수 Python 표준 라이브러리와 최소한의 패키지로 작성되었습니다.
* **Heuristic Scoring**: 단순 파일 변경이 아닌, 공격자의 목적에 따른 가중치 점수화 (예: `.env` 생성 = 60점, `.env` 수정 = 70점).
* **Asynchronous Processing**: 이벤트 폭주 시에도 시스템이 멈추지 않도록 스레드(Thread) 간 안전한 Queue 데이터 처리를 구현했습니다.
* **E2EE Alerting**: Matrix Protocol API 연동을 통해 외부 노출 없이 안전한 알림망을 구축할 수 있습니다.

## 🛠️ Environment & Stack

* **OS**: Linux
* **Language**: Python 3.x
* **Hardware Target**: x86, x64, and ARM architectures (Tested on Odroid M1S)
## 💻 How to Run (Local Test)

\`\`\`bash
# 1. Clone the repository
git clone https://github.com/cocomodo25/stealerwatcher.git
cd stealerwatcher

# 2. Install dependencies
pip install watchdog requests python-dotenv

# 3. Configure target directory & Matrix info in .env
# (Create a .env file and add necessary API keys/tokens)

# 4. Run the engine
python3 main.py
\`\`\`

---
*Developed for Homelab Security & Infrastructure Automation.*
