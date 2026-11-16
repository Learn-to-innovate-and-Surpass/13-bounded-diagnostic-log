"""Generate synthetic diagnostics and independently preserve synthetic feedback."""
from tempfile import TemporaryDirectory

from bounded_log import BoundedLog


def main():
    with TemporaryDirectory() as directory:
        log = BoundedLog(directory, max_bytes=1024, max_entries=3, max_event_bytes=256)
        print("关键反馈：", log.append_critical("synthetic-task-1",
              {"status": "COMPLETE", "wire": "W001", "destination": "H001"}))
        for index in range(30):
            log.append_diagnostic({"message": "合成阶段说明", "sequence": index})
        summary = log.append_diagnostic({"message": "合成大事件" * 2000})
        print("普通诊断边界：", log.diagnostic_stats())
        print("超大事件处理：", summary["kind"])
        reopened = BoundedLog(directory, max_bytes=1024, max_entries=3, max_event_bytes=256)
        print("重启后关键反馈：", reopened.critical_feedback())
        print("重复反馈：", reopened.append_critical("synthetic-task-1",
              {"status": "COMPLETE", "wire": "W001", "destination": "H001"}))


if __name__ == "__main__":
    main()
