from datetime import datetime
from uuid import uuid4
from alerta.app import db

JSON = dict

class Pattern:

    def __init__(self, id: str = None, name: str = None, sql_rule: str = None, priority: int = None, is_active: bool = True, create_time: datetime = None, update_time: datetime = None, **kwargs):
        self.id = id or str(uuid4())
        self.name = name
        self.sql_rule = sql_rule
        self.priority = priority
        self.is_active = is_active
        self.create_time = create_time or datetime.utcnow()
        self.update_time = update_time or self.create_time

    @classmethod
    def parse(cls, json: JSON) -> 'Pattern':
        return Pattern(
            id=json.get('id'),
            name=json.get('name'),
            sql_rule=json.get('sql_rule'),
            priority=json.get('priority'),
            is_active=json.get('is_active', True),
            create_time=datetime.strptime(json['createTime'], '%Y-%m-%dT%H:%M:%S') if 'createTime' in json else None,
            update_time=datetime.strptime(json['updateTime'], '%Y-%m-%dT%H:%M:%S') if 'updateTime' in json else None
        )

    @classmethod
    def from_db(cls, record: dict) -> 'Pattern':
        """
        Создание объекта Pattern из записи базы данных.
        """
        return cls(
            id=record['id'],
            name=record['name'],
            sql_rule=record['sql_rule'],
            priority=record['priority'],
            is_active=record['is_active'],
            create_time=record['create_time'],
            update_time=record['update_time']
        )

    @classmethod
    def find_by_id(cls, pattern_id: str) -> 'Pattern':
        """
        Найти паттерн по ID с использованием метода из класса db.
        """
        patterns = db.get_patterns()
        for pattern in patterns:
            if pattern['id'] == pattern_id:
                return cls.from_db(pattern)
        return None

    def create(self) -> 'Pattern':
        """
        Создать паттерн в бд.
        """
        pattern_id = db.create_pattern(self.name, self.sql_rule, self.priority, self.is_active)
        self.id = pattern_id
        return self

    def update(self) -> 'Pattern':
        """
        Обновить паттерн в бд.
        """
        db.update_pattern(self.id, self.name, self.sql_rule, self.priority, self.is_active)
        return self

    def delete(self) -> bool:
        """
        Удалить паттерн из бд.
        """
        db.delete_pattern(self.id)
        return True

    @property
    def serialize(self) -> dict:
        """
        Сериализовать объект в JSON.
        """
        return {
            'id': self.id,
            'name': self.name,
            'sql_rule': self.sql_rule,
            'priority': self.priority,
            'is_active': self.is_active,
            'createTime': self.create_time.isoformat(),
            'updateTime': self.update_time.isoformat(),
        }

    def __repr__(self) -> str:
        return f"Pattern(id={self.id!r}, name={self.name!r}, priority={self.priority!r}, is_active={self.is_active!r}, create_time={self.create_time!r})"