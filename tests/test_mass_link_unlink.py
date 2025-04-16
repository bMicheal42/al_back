#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import copy

from alerta.models.alert import Alert
from alerta.models.issue import Issue


class TestMassLinkUnlink(unittest.TestCase):
    """Тесты для проверки оптимизированного массового линкования и отлинкования алертов"""

    def setUp(self):
        """Настройка тестовых данных"""
        # Используем datetime.now() вместо utcnow() для избежания DeprecationWarning
        now = datetime.now()
        
        self.alert_data_base = {
            "resource": "TST-WEBC-300",
            "event": "Тестовое событие",
            "environment": "Production",
            "severity": "medium",
            "correlate": [],
            "status": "open",
            "service": ["Тест"],
            "group": "Тестовая группа",
            "value": "0",
            "text": "Тестовый текст",
            "tags": ["ProjectGroup:AF", "InfoSystem:INFRA"],
            "attributes": {
                "host_critical": "0"
            },
            "origin": "Тестовый источник",
            "type": "Тестовый тип",
            "create_time": now,
            "timeout": 86400,
            "raw_data": "null",
            "customer": None,
            "duplicate_count": 0,
            "repeat": False,
            "last_receive_id": "a3c4aeda-8776-490e-bc8c-8d5c9a4ddf55",
            "last_receive_time": now,
            "history": [],
            "id": "alert1"
        }
        
        # Создаем набор алертов с различными данными
        self.alert_data_list = []
        for i in range(1, 501):  # 500 алертов
            alert_data = copy.deepcopy(self.alert_data_base)
            alert_data["id"] = f"alert{i}"
            alert_data["resource"] = f"TST-WEBC-{300+i}"
            if i % 3 == 0:
                alert_data["severity"] = "high"
            if i % 5 == 0:
                alert_data["severity"] = "critical"
                alert_data["attributes"]["host_critical"] = "1"
            if i % 10 == 0:
                alert_data["tags"].append("InfoSystem:EXTRA")
            if i % 20 == 0:
                alert_data["tags"].append("ProjectGroup:MAIN")
            
            self.alert_data_list.append(alert_data)
    
    @patch('alerta.models.alert.db')
    @patch('alerta.models.alert.hasattr')
    @patch('alerta.models.alert.g')
    def test_mass_link_to_issue(self, mock_g, mock_hasattr, mock_db):
        """Тест массового связывания 500 алертов с issue"""
        # Настраиваем Mock для Flask g
        mock_hasattr.return_value = True
        mock_g.login = "test_user"
        
        # Создаем список объектов Alert из данных
        alerts = [Alert.parse(data) for data in self.alert_data_list]
        alert_ids = [alert.id for alert in alerts]
        
        # Настраиваем мок для mass_update_issue_id
        mock_db.mass_update_issue_id.return_value = alerts
        
        # Выполняем метод массового линкования
        result = Alert.mass_link_to_issue(alert_ids, "issue123")
        
        # Проверяем, что метод mass_update_issue_id был вызван с правильными параметрами
        mock_db.mass_update_issue_id.assert_called_once()
        call_args = mock_db.mass_update_issue_id.call_args[0]
        
        # Проверяем параметры вызова
        self.assertEqual(call_args[0], alert_ids)  # Проверка alert_ids
        self.assertEqual(call_args[1], "issue123")  # Проверка issue_id
        # В call_args[2] должно быть время обновления (datetime)
        self.assertIsInstance(call_args[2], datetime)
        self.assertEqual(call_args[3], "test_user")  # Проверка пользователя
        
        # Проверяем результат
        self.assertEqual(len(result), 500)
        
    @patch('alerta.models.alert.db')
    @patch('alerta.models.issue.Issue.find_by_id')
    @patch('alerta.models.alert.hasattr')
    @patch('alerta.models.alert.g')
    def test_mass_unlink_from_issue(self, mock_g, mock_hasattr, mock_find_by_id, mock_db):
        """Тест массового отвязывания алертов от issue"""
        # Настраиваем Mock для Flask g
        mock_hasattr.return_value = True
        mock_g.login = "test_user"
        
        # Создаем список ID алертов для отвязывания
        alert_ids = [f"alert{i}" for i in range(1, 401)]  # 400 алертов
        issue_id = "issue123"
        
        # Мокаем Issue.find_by_id для возврата объекта Issue с алертами
        all_alert_ids = [f"alert{i}" for i in range(1, 501)]  # 500 алертов в issue
        mock_issue = MagicMock()
        mock_issue.id = issue_id
        mock_issue.alerts = all_alert_ids
        mock_find_by_id.return_value = mock_issue
        
        # Настраиваем мок для mass_update_issue_id
        mock_db.mass_update_issue_id.return_value = [Alert.parse(self.alert_data_base) for _ in range(400)]
        
        # Выполняем метод массового отвязывания
        result = Alert.mass_unlink_from_issue(alert_ids, issue_id)
        
        # Проверяем, что метод mass_update_issue_id был вызван с правильными параметрами
        mock_db.mass_update_issue_id.assert_called_once()
        call_args = mock_db.mass_update_issue_id.call_args[0]
        
        # Проверяем параметры вызова
        self.assertEqual(call_args[0], alert_ids)  # Проверка alert_ids
        self.assertIsNone(call_args[1])  # Проверка issue_id (должен быть None для отвязывания)
        # В call_args[2] должно быть время обновления (datetime)
        self.assertIsInstance(call_args[2], datetime)
        self.assertEqual(call_args[3], "test_user")  # Проверка пользователя
        
        # Проверяем результат
        self.assertEqual(len(result), 400)
    
    @patch('alerta.models.alert.db')
    @patch('alerta.models.issue.Issue.find_by_id')
    @patch('alerta.models.alert.hasattr')
    @patch('alerta.models.alert.g')
    def test_reject_unlink_last_alert(self, mock_g, mock_hasattr, mock_find_by_id, mock_db):
        """Тест отказа от отвязывания последнего алерта от issue"""
        # Настраиваем Mock для Flask g
        mock_hasattr.return_value = True
        mock_g.login = "test_user"
        
        # Создаем список ID алертов для отвязывания (все алерты issue)
        alert_ids = ["alert1"]
        issue_id = "issue123"
        
        # Мокаем Issue.find_by_id для возврата объекта Issue с одним алертом
        mock_issue = MagicMock()
        mock_issue.id = issue_id
        mock_issue.alerts = ["alert1"]
        mock_find_by_id.return_value = mock_issue
        
        # Проверяем, что вызывается исключение при попытке отвязать последний алерт
        with self.assertRaises(ValueError) as context:
            Alert.mass_unlink_from_issue(alert_ids, issue_id)
        
        # Проверяем текст исключения
        self.assertIn("Невозможно отвязать все алерты от issue", str(context.exception))
        
        # Проверяем, что метод mass_update_issue_id не был вызван
        mock_db.mass_update_issue_id.assert_not_called()
    
    @patch('alerta.models.issue.db')
    @patch('alerta.models.alert.Alert.mass_link_to_issue')
    @patch('alerta.models.issue.hasattr')
    @patch('alerta.models.issue.g')
    def test_issue_mass_add_alerts(self, mock_g, mock_hasattr, mock_mass_link, mock_db):
        """Тест метода Issue.mass_add_alerts с использованием оптимизированного массового линкования"""
        # Настраиваем Mock для Flask g
        mock_hasattr.return_value = True
        mock_g.login = "test_user"
        
        # Создаем объект Issue
        issue = Issue(
            summary="Тестовый Issue",
            id="issue123",
            severity="medium",
            host_critical="0",
            alerts=["existing_alert"],
            hosts=["TST-WEBC-300"],
            project_groups=["AF"],
            info_systems=["INFRA"]
        )
        
        # Создаем список алертов для добавления
        alerts = [Alert.parse(data) for data in self.alert_data_list[:100]]  # 100 алертов
        
        # Мокаем метод update Issue для возврата обновленного Issue
        mock_db.update_issue.return_value = {
            "id": "issue123",
            "summary": "Тестовый Issue",
            "severity": "critical",  # Обновлено из-за добавленных алертов
            "host_critical": "1",    # Обновлено из-за добавленных алертов
            "alerts": ["existing_alert"] + [a.id for a in alerts],
            "hosts": ["TST-WEBC-300"] + [a.resource for a in alerts],
            "project_groups": ["AF", "MAIN"],
            "info_systems": ["INFRA", "EXTRA"]
        }
        
        # Выполняем метод массового добавления алертов
        updated_issue = issue.mass_add_alerts(alerts)
        
        # Проверяем, что метод update_issue был вызван с правильными параметрами
        mock_db.update_issue.assert_called_once()
        
        # Проверяем, что метод Alert.mass_link_to_issue был вызван с правильными параметрами
        mock_mass_link.assert_called_once()
        call_args = mock_mass_link.call_args[0]
        
        # Первый аргумент должен быть список ID добавляемых алертов
        self.assertEqual(len(call_args[0]), 100)
        # Второй аргумент должен быть ID issue
        self.assertEqual(call_args[1], "issue123")
        
        # Проверяем обновленные свойства Issue
        self.assertEqual(updated_issue.severity, "critical")
        self.assertEqual(updated_issue.host_critical, "1")
        self.assertEqual(len(updated_issue.alerts), 101)  # 1 существующий + 100 новых
        self.assertEqual(len(updated_issue.hosts), 101)
        self.assertEqual(len(updated_issue.project_groups), 2)
        self.assertEqual(len(updated_issue.info_systems), 2)
    
    @patch('alerta.models.issue.db')
    @patch('alerta.models.alert.Alert.mass_unlink_from_issue')
    @patch('alerta.models.issue.hasattr')
    @patch('alerta.models.issue.g')
    def test_issue_mass_remove_alerts(self, mock_g, mock_hasattr, mock_mass_unlink, mock_db):
        """Тест метода Issue.mass_remove_alerts с использованием оптимизированного массового отлинкования"""
        # Настраиваем Mock для Flask g
        mock_hasattr.return_value = True
        mock_g.login = "test_user"
        
        # Создаем список ID алертов
        alert_ids = [f"alert{i}" for i in range(1, 501)]  # 500 алертов
        
        # Создаем объект Issue с алертами
        issue = Issue(
            summary="Тестовый Issue",
            id="issue123",
            severity="critical",
            host_critical="1",
            alerts=alert_ids,
            hosts=[f"TST-WEBC-{300+i}" for i in range(1, 501)],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA"]
        )
        
        # Создаем список ID алертов для удаления
        alerts_to_remove = alert_ids[:400]  # Удаляем 400 из 500 алертов
        
        # Мокаем Alert.find_by_ids для возврата оставшихся алертов
        remaining_alerts = [Alert.parse(self.alert_data_list[i]) for i in range(400, 500)]
        with patch('alerta.models.alert.Alert.find_by_ids', return_value=remaining_alerts):
            # Мокаем метод update Issue для возврата обновленного Issue
            mock_db.update_issue.return_value = {
                "id": "issue123",
                "summary": "Тестовый Issue",
                "severity": "high",  # Обновлено из-за удаленных алертов
                "host_critical": "0", # Обновлено из-за удаленных алертов
                "alerts": alert_ids[400:],  # Оставшиеся 100 алертов
                "hosts": [f"TST-WEBC-{300+i}" for i in range(401, 501)],
                "project_groups": ["AF"],
                "info_systems": ["INFRA"]
            }
            
            # Выполняем метод массового удаления алертов
            updated_issue = issue.mass_remove_alerts(alerts_to_remove)
            
            # Проверяем, что метод update_issue был вызван с правильными параметрами
            mock_db.update_issue.assert_called_once()
            
            # Проверяем, что метод Alert.mass_unlink_from_issue был вызван с правильными параметрами
            mock_mass_unlink.assert_called_once()
            call_args = mock_mass_unlink.call_args[0]
            
            # Первый аргумент должен быть список ID удаляемых алертов
            self.assertEqual(len(call_args[0]), 400)
            # Второй аргумент должен быть ID issue
            self.assertEqual(call_args[1], "issue123")
            
            # Проверяем обновленные свойства Issue
            self.assertEqual(updated_issue.severity, "high")
            self.assertEqual(updated_issue.host_critical, "0")
            self.assertEqual(len(updated_issue.alerts), 100)  # Остались 100 из 500
            self.assertEqual(len(updated_issue.hosts), 100)
            self.assertEqual(len(updated_issue.project_groups), 1)
            self.assertEqual(len(updated_issue.info_systems), 1)


if __name__ == '__main__':
    unittest.main() 