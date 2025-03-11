import threading
from datetime import datetime, timedelta
from alerta.app import db

# Кэшик для паттернов, чтобы не гонять по кд запросы в базу
class PatternCache:
    _instance = None
    _lock = threading.Lock()
    _patterns = []
    _last_updated = None
    _refresh_interval = timedelta(minutes=5)  # Интервал обновления данных

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self._load_patterns()

    def _load_patterns(self):
        try:
            self._patterns = db.get_patterns()
            self._last_updated = datetime.utcnow()
        except Exception as e:
            print(f"Failed to load patterns: {e}")
            self._patterns = []

    def get_patterns(self):
        """Возвращает паттерны, обновляет их, если требуется."""
        if not self._patterns or self._is_stale():
            self._load_patterns()
        return self._patterns

    def _is_stale(self):
        """Проверяет, истек ли интервал обновления."""
        return self._last_updated is None or datetime.utcnow() - self._last_updated > self._refresh_interval

    def get_pattern_priority_by_name(self, name):
        """Возвращает приоритет паттерна по имени."""
        for pattern in self.get_patterns():
            if pattern['name'] == name:
                return pattern['priority']
        return 99999

    def force_reload(self):
        """Принудительно обновляет паттерны."""
        self._load_patterns()

    def update_cache(self, patterns):
        """Обновляет кэш вручную."""
        self._patterns = patterns
        self._last_updated = datetime.utcnow()