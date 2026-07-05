from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from services.account_service import AccountService, account_service
from services.config import DATA_DIR
from services.register import openai_register


REGISTER_FILE = DATA_DIR / "register.json"
DEFAULT_REGISTER_MODE = "available"
DEFAULT_TARGET_AVAILABLE = 10
DEFAULT_CHECK_INTERVAL = 600


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_config() -> dict:
    return {**openai_register.config, "mode": DEFAULT_REGISTER_MODE, "target_quota": 100, "target_available": DEFAULT_TARGET_AVAILABLE, "check_interval": DEFAULT_CHECK_INTERVAL, "enabled": False, "stats": {"success": 0, "fail": 0, "done": 0, "running": 0, "threads": openai_register.config["threads"], "elapsed_seconds": 0, "avg_seconds": 0, "success_rate": 0, "current_quota": 0, "current_available": 0}}


def _safe_bool(value: object, fallback: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return fallback
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return fallback


def _normalize(raw: dict) -> dict:
    cfg = _default_config()
    cfg.update({k: v for k, v in raw.items() if k not in {"stats", "logs"}})
    cfg["total"] = max(1, int(cfg.get("total") or 1))
    cfg["threads"] = max(1, int(cfg.get("threads") or 1))
    cfg["mode"] = str(cfg.get("mode") or DEFAULT_REGISTER_MODE).strip() if str(cfg.get("mode") or DEFAULT_REGISTER_MODE).strip() in {"total", "quota", "available"} else DEFAULT_REGISTER_MODE
    cfg["target_quota"] = max(1, int(cfg.get("target_quota") or 1))
    cfg["target_available"] = max(1, int(cfg.get("target_available") or 1))
    cfg["check_interval"] = max(1, int(cfg.get("check_interval") or DEFAULT_CHECK_INTERVAL))
    cfg["proxy"] = str(cfg.get("proxy") or "").strip()
    default_mail = _default_config()["mail"] if isinstance(_default_config().get("mail"), dict) else {}
    mail = cfg.get("mail") if isinstance(cfg.get("mail"), dict) else {}
    cfg["mail"] = {**default_mail, **mail}
    cfg["mail"]["api_use_register_proxy"] = _safe_bool(cfg["mail"].get("api_use_register_proxy"), True)
    cfg["mail"].pop("proxy", None)
    cfg["enabled"] = bool(cfg.get("enabled"))
    # openai_register.config 已在启动时合并环境变量；保存归一化不能再次覆盖页面提交值。
    stats = {**_default_config()["stats"], **(raw.get("stats") if isinstance(raw.get("stats"), dict) else {}),
             "threads": cfg["threads"]}
    cfg["stats"] = stats
    return cfg


class RegisterService:
    def __init__(self, store_file: Path):
        self._store_file = store_file
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._runner: threading.Thread | None = None
        self._logs: list[dict] = []
        self._last_pool_refresh_at = 0.0
        self._last_pool_check_log = ""
        self._last_pool_check_log_at = 0.0
        openai_register.register_log_sink = self._append_log
        self._config = self._load()
        if self._config["enabled"]:
            self.start()

    def _load(self) -> dict:
        try:
            return _normalize(json.loads(self._store_file.read_text(encoding="utf-8")))
        except Exception:
            return _normalize({})

    def _save(self) -> None:
        self._store_file.parent.mkdir(parents=True, exist_ok=True)
        self._store_file.write_text(json.dumps(self._config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def get(self) -> dict:
        with self._lock:
            return json.loads(json.dumps({**self._config, "logs": self._logs[-300:]}, ensure_ascii=False))

    def _drop_mail_proxy(self) -> None:
        if isinstance(self._config.get("mail"), dict):
            self._config["mail"].pop("proxy", None)

    def update(self, updates: dict) -> dict:
        with self._lock:
            self._config = _normalize({**self._config, **updates})
            self._drop_mail_proxy()
            openai_register.config.update({k: self._config[k] for k in ("mail", "proxy", "total", "threads")})
            self._save()
            return self.get()

    def start(self) -> dict:
        with self._lock:
            if self._runner and self._runner.is_alive():
                self._stop_event.clear()
                self._config["enabled"] = True
                self._save()
                return self.get()
            self._config["enabled"] = True
            self._stop_event.clear()
            self._drop_mail_proxy()
            self._logs = []
            metrics = self._pool_metrics()
            self._config["stats"] = {"job_id": uuid.uuid4().hex, "success": 0, "fail": 0, "done": 0, "running": 0, "threads": self._config["threads"], **metrics, "started_at": _now(), "updated_at": _now()}
            openai_register.config.update({k: self._config[k] for k in ("mail", "proxy", "total", "threads")})
            with openai_register.stats_lock:
                openai_register.stats.update({"done": 0, "success": 0, "fail": 0, "start_time": time.time()})
            self._save()
            self._runner = threading.Thread(target=self._run, daemon=True, name="openai-register")
            self._runner.start()
            self._append_log(f"注册任务启动，模式={self._config['mode']}，线程数={self._config['threads']}", "yellow")
            return self.get()

    def stop(self) -> dict:
        with self._lock:
            self._config["enabled"] = False
            self._config["stats"]["updated_at"] = _now()
            self._stop_event.set()
            self._save()
            self._append_log("已请求停止注册任务，正在等待当前运行任务结束", "yellow")
            return self.get()

    def reset(self) -> dict:
        with self._lock:
            self._logs = []
            self._last_pool_check_log = ""
            self._last_pool_check_log_at = 0.0
            self._config["stats"] = {"success": 0, "fail": 0, "done": 0, "running": 0, "threads": self._config["threads"], "elapsed_seconds": 0, "avg_seconds": 0, "success_rate": 0, **self._pool_metrics(), "updated_at": _now()}
            with openai_register.stats_lock:
                openai_register.stats.update({"done": 0, "success": 0, "fail": 0, "start_time": 0.0})
            self._save()
            return self.get()

    def _append_log(self, text: str, color: str = "") -> None:
        with self._lock:
            value = str(text)
            if len(value) > 480:
                value = value[:477].rstrip() + "..."
            self._logs.append({"time": _now(), "text": value, "level": str(color or "info")})
            self._logs = self._logs[-300:]

    def _append_pool_check_log(self, text: str) -> None:
        now = time.monotonic()
        with self._lock:
            if text == self._last_pool_check_log and now - self._last_pool_check_log_at < 60:
                return
            self._last_pool_check_log = text
            self._last_pool_check_log_at = now
        self._append_log(text, "yellow")

    def _refresh_pool_accounts(self, cfg: dict) -> None:
        mode = str(cfg.get("mode") or "total")
        if mode not in {"quota", "available"}:
            return
        try:
            interval_seconds = max(1, int(cfg.get("check_interval") or 5))
        except (TypeError, ValueError):
            interval_seconds = 5
        now = time.monotonic()
        if self._last_pool_refresh_at and now - self._last_pool_refresh_at < interval_seconds:
            return
        self._last_pool_refresh_at = now
        tokens = account_service.list_tokens()
        if not tokens:
            return
        # 保号检查必须基于最新远端额度和异常状态，否则会误判“已达标”。
        self._append_log(f"刷新号池账号信息：{len(tokens)} 个账号", "yellow")
        result = account_service.refresh_accounts(tokens, confirm_invalid=True)
        errors = result.get("errors") or []
        if errors:
            self._append_log(f"刷新号池账号信息部分失败：{len(errors)} 个账号", "yellow")

    def _pool_metrics(self) -> dict:
        items = account_service.list_accounts()
        # 目标可用账号必须与真实图片候选池一致；待确认异常账号不再参与保号统计。
        available = [
            item
            for item in items
            if AccountService._is_image_account_available(item)
               and int(item.get("invalid_count") or 0) <= 0
        ]
        return {
            "current_quota": sum(int(item.get("quota") or 0) for item in available if not item.get("image_quota_unknown")),
            "current_available": len(available),
        }

    def _target_reached(self, cfg: dict, submitted: int) -> bool:
        mode = str(cfg.get("mode") or "total")
        self._refresh_pool_accounts(cfg)
        metrics = self._pool_metrics()
        self._bump(**metrics)
        if mode == "quota":
            reached = metrics["current_quota"] >= int(cfg.get("target_quota") or 1)
            self._append_pool_check_log(f"检查号池：当前可用账号={metrics['current_available']}，当前剩余额度={metrics['current_quota']}，目标额度={cfg.get('target_quota')}，{'跳过注册' if reached else '继续注册'}")
            return reached
        if mode == "available":
            reached = metrics["current_available"] >= int(cfg.get("target_available") or 1)
            self._append_pool_check_log(f"检查号池：当前可用账号={metrics['current_available']}，目标账号={cfg.get('target_available')}，当前剩余额度={metrics['current_quota']}，{'跳过注册' if reached else '继续注册'}")
            return reached
        return submitted >= int(cfg.get("total") or 1)

    def _bump(self, **updates) -> None:
        with self._lock:
            self._config["stats"].update(updates)
            stats = self._config["stats"]
            started_at = str(stats.get("started_at") or "")
            if started_at:
                try:
                    elapsed = max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(started_at)).total_seconds())
                except Exception:
                    elapsed = 0.0
                done = int(stats.get("done") or 0)
                success = int(stats.get("success") or 0)
                fail = int(stats.get("fail") or 0)
                stats["elapsed_seconds"] = round(elapsed, 1)
                stats["avg_seconds"] = round(elapsed / success, 1) if success else 0
                stats["success_rate"] = round(success * 100 / max(1, success + fail), 1)
            self._config["stats"]["updated_at"] = _now()
            self._save()

    def _run(self) -> None:
        threads = int(self.get()["threads"])
        submitted, done, success, fail = 0, 0, 0, 0
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = set()
            while True:
                cfg = self.get()
                while self.get()["enabled"] and not self._target_reached(cfg, submitted) and len(futures) < threads:
                    submitted += 1
                    futures.add(executor.submit(openai_register.worker, submitted))
                self._bump(running=len(futures), done=done, success=success, fail=fail)
                if not futures and (not self.get()["enabled"] or str(cfg.get("mode") or "total") == "total"):
                    break
                if not futures:
                    # 空闲保号监控使用可唤醒等待，避免停止时卡在较长 check_interval。
                    if self._stop_event.wait(timeout=max(1, int(cfg.get("check_interval") or 5))):
                        break
                    continue
                finished, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in finished:
                    done += 1
                    try:
                        result = future.result()
                        success += 1 if result.get("ok") else 0
                        fail += 0 if result.get("ok") else 1
                    except Exception:
                        fail += 1
        self._bump(running=0, done=done, success=success, fail=fail, finished_at=_now())
        with self._lock:
            self._config["enabled"] = False
            self._save()
        self._append_log(f"注册任务结束，成功{success}，失败{fail}", "yellow")


register_service = RegisterService(REGISTER_FILE)
