import sys
import time
from collector import FileWatcher
from analyzer import EventAnalyzer
from Notifier import NotificationManager, ConsoleNotifier

def main():
    # 1. 실행 시 경로를 입력받았는지 확인
    # 예: python3 main.py /home/user
    if len(sys.argv) < 2:
        print("❌ 사용법: python3 main.py <감시경로1> <감시경로2> ...")
        sys.exit(1)
    
    watch_paths = sys.argv[1:] # 입력받은 모든 경로를 리스트로 저장

    # 부품 초기화
    analyzer = EventAnalyzer()
    notifier_mgr = NotificationManager(minimum_level="Info")
    notifier_mgr.add_notifier(ConsoleNotifier(), minimum_level="Info")

    # 콜백 함수: Collector가 던져준 데이터를 Analyzer와 Notifier로 연결
    def on_event(event):
        analyzed_data = analyzer.analyze(event)
        notifier_mgr.notify(analyzed_data)

    print(f"🚀Security System 기동... (감시 구역: {watch_paths})")
    
    # 2. 지정된 경로들로 FileWatcher 실행
    with FileWatcher(paths=watch_paths, callback=on_event) as watcher:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 시스템 종료")

if __name__ == "__main__":
    main()