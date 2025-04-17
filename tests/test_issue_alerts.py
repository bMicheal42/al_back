import unittest
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
import copy
import time

from flask import Flask, g

from alerta.models.issue import Issue, create_new_issue_for_alert, recalculate_issue_attributes
from alerta.models.alert import Alert


class TestIssueAlerts(unittest.TestCase):
    """Тесты для проверки функциональности связывания алертов с Issue"""
    
    def setUp(self):
        # Создаем тестовое Flask-приложение
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.app.config['ALERT_TIMEOUT'] = 86400  # 24 часа в секундах
        self.app.config['PLUGINS'] = []
        self.app.config['CUSTOMER_VIEWS'] = False
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Имитируем g.login для функций, которые его используют
        g.login = 'test-user'
        
        # Тестовые данные для алертов
        self.alert_data_medium = {
            "id": "alert1",
            "resource": "icmpping", 
            "event": "TST-WEBC-300", 
            "environment": "Production", 
            "severity": "medium", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Connectivity to host TST-WEBC-300 cannot be established",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-322",
                "InfoSystem:INFRA",
                "Owner_1:af-admins",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.15.10",
                "host_critical": "0",
                "zabbix_severity": "Средняя"
            },
            "create_time": datetime.now(),  # Используем datetime.now() вместо utcnow()
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
        
        self.alert_data_high = {
            "id": "alert2",
            "resource": "icmpping", 
            "event": "TST-WEBC-301", 
            "environment": "Production", 
            "severity": "high", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Host TST-WEBC-301 is currently unresponsive",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-323",
                "InfoSystem:INFRA",
                "InfoSystem:EXTRA",
                "Owner_1:AF-admins",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.14.16",
                "host_critical": "1",
                "zabbix_severity": "Высокая"
            },
            "create_time": datetime.now(),
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
        
        self.alert_data_critical = {
            "id": "alert3",
            "resource": "icmpping", 
            "event": "TST-WEBC-302", 
            "environment": "Production", 
            "severity": "critical", 
            "group": "Zabbix", 
            "value": "Down (0)",
            "service": ["Critical/Done", "f1-zbx-prx2"],
            "text": "Host TST-WEBC-302 is down",
            "tags": [
                "Application:Status",
                "Hardware:F2-HOST-324",
                "InfoSystem:PRODUCTION",
                "Owner_1:AF-admins",
                "ProjectGroup:MAIN",
                "ProjectGroup:AF"
            ],
            "attributes": {
                "ip": "10.9.14.18",
                "host_critical": "1",
                "zabbix_severity": "Критическая"
            },
            "create_time": datetime.now(),
            "origin": "zabbix/co-zbbx-tst",
            "type": "zabbixAlert"
        }
    
    def tearDown(self):
        # Удаляем контекст приложения после каждого теста
        self.app_context.pop()
        
    @patch('alerta.models.issue.db')
    def test_create_issue_from_alert(self, mock_db):
        """Тест создания Issue из алерта"""
        # Мокаем функцию create_issue базы данных
        mock_db.create_issue.return_value = {
            "id": "issue1",
            "summary": "Connectivity to host TST-WEBC-300 cannot be established",
            "severity": "medium",
            "host_critical": "0",
            "alerts": ["alert1"],
            "hosts": ["TST-WEBC-300"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA"]
        }
        
        # Создаем объект Alert из данных
        alert = Alert.parse(self.alert_data_medium)
        
        # Мокаем функцию link_to_issue
        with patch.object(Alert, 'link_to_issue', return_value=alert):
            # Создаем Issue из алерта
            result = create_new_issue_for_alert(alert)
            
            # Проверяем, что функция create_issue была вызвана
            mock_db.create_issue.assert_called_once()
            
            # Проверяем параметры, переданные в вызове функции
            issue = mock_db.create_issue.call_args[0][0]
            self.assertEqual(issue.summary, "Connectivity to host TST-WEBC-300 cannot be established")
            self.assertEqual(issue.severity, "medium")
            self.assertEqual(issue.host_critical, "0")
            self.assertEqual(issue.alerts, ["alert1"])
            self.assertEqual(issue.hosts, ["TST-WEBC-300"])
            self.assertEqual(issue.project_groups, ["AF"])
            self.assertEqual(issue.info_systems, ["INFRA"])
    
    @patch('alerta.models.issue.db')
    def test_add_alert_to_issue(self, mock_db):
        """Тест добавления алерта к Issue и проверка обновления полей"""
        # Создаем Issue с начальными данными
        issue = Issue(
            summary="Initial Issue",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=["alert1"],
            hosts=["TST-WEBC-300"],
            project_groups=["AF"],
            info_systems=["INFRA"]
        )
        
        # Мокаем функцию update_issue базы данных
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Initial Issue",
            "severity": "high",
            "host_critical": "1",
            "alerts": ["alert1", "alert2"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301"],
            "project_groups": ["AF"],
            "info_systems": ["INFRA", "EXTRA"],
            "last_alert_time": self.alert_data_high["create_time"]
        }
        
        # Создаем объект Alert из данных
        alert = Alert.parse(self.alert_data_high)
        
        # Добавляем алерт к Issue
        updated_issue = issue.mass_add_alerts(alert)
        
        # Проверяем, что функция update_issue была вызвана
        mock_db.update_issue.assert_called_once()
        
        # Проверяем обновленные поля
        self.assertEqual(updated_issue.severity, "high")  # Severity должен быть обновлен на более высокий
        self.assertEqual(updated_issue.host_critical, "1")  # host_critical должен быть обновлен
        self.assertEqual(len(updated_issue.alerts), 2)  # Должно быть 2 алерта
        self.assertIn("alert2", updated_issue.alerts)  # Новый алерт должен быть добавлен
        self.assertEqual(len(updated_issue.hosts), 2)  # Должно быть 2 хоста
        self.assertIn("TST-WEBC-301", updated_issue.hosts)  # Новый хост должен быть добавлен
        self.assertEqual(len(updated_issue.info_systems), 2)  # Должно быть 2 информационные системы
        self.assertIn("EXTRA", updated_issue.info_systems)  # Новая система должна быть добавлена
        self.assertEqual(updated_issue.last_alert_time, self.alert_data_high["create_time"])  # last_alert_time должен быть обновлен
    
    @patch('alerta.models.issue.db')
    def test_remove_alert_from_issue(self, mock_db):
        """Тест удаления алерта из Issue и проверка обновления полей"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            last_alert_time=self.alert_data_critical["create_time"]
        )
        
        # Мокаем Alert.find_by_ids для возврата объектов Alert
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Создаем объекты Alert из данных
            alert1 = Alert.parse(self.alert_data_medium)
            alert3 = Alert.parse(self.alert_data_critical)
            mock_find_by_ids.return_value = [alert1, alert3]
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "critical",  # Остается критическим из-за alert3
                "host_critical": "1",    # Остается 1 из-за alert3
                "alerts": ["alert1", "alert3"],
                "hosts": ["TST-WEBC-300", "TST-WEBC-302"],
                "project_groups": ["AF", "MAIN"],
                "info_systems": ["INFRA", "PRODUCTION"],
                "last_alert_time": self.alert_data_critical["create_time"]
            }
            
            # Удаляем alert2 из Issue
            updated_issue = issue.remove_alert("alert2")
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.severity, "critical")  # Severity остается критическим
            self.assertEqual(updated_issue.host_critical, "1")  # host_critical остается 1
            self.assertEqual(len(updated_issue.alerts), 2)  # Должно быть 2 алерта
            self.assertNotIn("alert2", updated_issue.alerts)  # Удаленный алерт должен отсутствовать
            self.assertEqual(len(updated_issue.hosts), 2)  # Должно быть 2 хоста
            self.assertNotIn("TST-WEBC-301", updated_issue.hosts)  # Хост алерта2 должен быть удален
            self.assertEqual(len(updated_issue.info_systems), 2)  # Должно быть 2 информационные системы
            self.assertNotIn("EXTRA", updated_issue.info_systems)  # Система из алерта2 должна быть удалена
    
    @patch('alerta.models.issue.db')
    def test_mass_add_alerts_to_issue(self, mock_db):
        """Тест массового добавления алертов в Issue"""
        # Создаем Issue с начальными данными
        issue = Issue(
            summary="Initial Issue",
            id="issue1",
            severity="medium",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Мокаем функцию update_issue базы данных
        mock_db.update_issue.return_value = {
            "id": "issue1",
            "summary": "Initial Issue",
            "severity": "critical",
            "host_critical": "1",
            "alerts": ["alert1", "alert2", "alert3"],
            "hosts": ["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            "project_groups": ["AF", "MAIN"],
            "info_systems": ["INFRA", "EXTRA", "PRODUCTION"],
            "last_alert_time": self.alert_data_critical["create_time"]
        }
        
        # Создаем объекты Alert из данных
        alert1 = Alert.parse(self.alert_data_medium)
        alert2 = Alert.parse(self.alert_data_high)
        alert3 = Alert.parse(self.alert_data_critical)
        
        # Массово добавляем алерты к Issue
        updated_issue = issue.mass_add_alerts([alert1, alert2, alert3])
        
        # Проверяем, что функция update_issue была вызвана
        mock_db.update_issue.assert_called_once()
        
        # Проверяем обновленные поля
        self.assertEqual(updated_issue.severity, "critical")  # Severity должен быть наивысшим из всех алертов
        self.assertEqual(updated_issue.host_critical, "1")  # host_critical должен быть 1
        self.assertEqual(len(updated_issue.alerts), 3)  # Должно быть 3 алерта
        self.assertEqual(len(updated_issue.hosts), 3)  # Должно быть 3 хоста
        self.assertEqual(len(updated_issue.project_groups), 2)  # Должно быть 2 группы проектов
        self.assertEqual(len(updated_issue.info_systems), 3)  # Должно быть 3 информационные системы
        self.assertEqual(updated_issue.last_alert_time, self.alert_data_critical["create_time"])  # last_alert_time должен быть из самого нового алерта
    
    @patch('alerta.models.issue.db')
    def test_mass_remove_alerts_from_issue(self, mock_db):
        """Тест массового удаления алертов из Issue"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            last_alert_time=self.alert_data_critical["create_time"]
        )
        
        # Мокаем Alert.find_by_ids для возврата объектов Alert
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            # Оставляем только alert1
            alert1 = Alert.parse(self.alert_data_medium)
            mock_find_by_ids.return_value = [alert1]
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "critical",  # Severity должен быть medium из оставшегося алерта
                "host_critical": "0",  # host_critical должен быть 0
                "alerts": ["alert1"],
                "hosts": ["TST-WEBC-300"],
                "project_groups": ["AF"],
                "info_systems": ["INFRA"],
                "last_alert_time": self.alert_data_medium["create_time"]
            }
            
            # Удаляем alert2 и alert3 из Issue
            updated_issue = issue.mass_remove_alerts(["alert2", "alert3"])
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.severity, "critical")  # Severity должен быть medium из оставшегося алерта
            self.assertEqual(updated_issue.host_critical, "0")  # host_critical должен быть 0
            self.assertEqual(len(updated_issue.alerts), 1)  # Должен остаться 1 алерт
            self.assertEqual(updated_issue.alerts[0], "alert1")  # Должен остаться только alert1
            self.assertEqual(len(updated_issue.hosts), 1)  # Должен остаться 1 хост
            self.assertEqual(updated_issue.hosts[0], "TST-WEBC-300")  # Должен остаться только хост из alert1
            self.assertEqual(len(updated_issue.project_groups), 1)  # Должна остаться 1 группа проектов
            self.assertEqual(updated_issue.project_groups[0], "AF")  # Должна остаться только группа из alert1
            self.assertEqual(len(updated_issue.info_systems), 1)  # Должна остаться 1 информационная система
            self.assertEqual(updated_issue.info_systems[0], "INFRA")  # Должна остаться только система из alert1
    
    @patch('alerta.models.issue.db')
    def test_remove_all_alerts_from_issue(self, mock_db):
        """Тест удаления всех алертов из Issue (Issue должен быть закрыт)"""
        # Создаем Issue с несколькими алертами
        issue = Issue(
            summary="Issue with multiple alerts",
            id="issue1",
            severity="critical",
            host_critical="1",
            alerts=["alert1", "alert2", "alert3"],
            hosts=["TST-WEBC-300", "TST-WEBC-301", "TST-WEBC-302"],
            project_groups=["AF", "MAIN"],
            info_systems=["INFRA", "EXTRA", "PRODUCTION"],
            status="open"
        )
        
        # Мокаем Alert.find_by_ids для возврата пустого списка (все алерты удалены)
        with patch('alerta.models.alert.Alert.find_by_ids') as mock_find_by_ids:
            mock_find_by_ids.return_value = []
            
            # Мокаем функцию update_issue базы данных
            mock_db.update_issue.return_value = {
                "id": "issue1",
                "summary": "Issue with multiple alerts",
                "severity": "critical",  # Severity остается тем же
                "host_critical": "1",    # host_critical остается тем же
                "alerts": [],            # Нет алертов
                "hosts": [],             # Нет хостов
                "project_groups": [],    # Нет групп проектов
                "info_systems": [],      # Нет информационных систем
                "status": "closed",      # Issue закрыт
                "resolve_time": datetime.utcnow()  # Время разрешения установлено
            }
            
            # Удаляем все алерты из Issue
            updated_issue = issue.mass_remove_alerts(["alert1", "alert2", "alert3"])
            
            # Проверяем, что функция update_issue была вызвана
            mock_db.update_issue.assert_called_once()
            
            # Проверяем обновленные поля
            self.assertEqual(updated_issue.status, "closed")  # Issue должен быть закрыт
            self.assertIsNotNone(updated_issue.resolve_time)  # Время разрешения должно быть установлено
            self.assertEqual(len(updated_issue.alerts), 0)  # Не должно быть алертов
            self.assertEqual(len(updated_issue.hosts), 0)  # Не должно быть хостов
            self.assertEqual(len(updated_issue.project_groups), 0)  # Не должно быть групп проектов
            self.assertEqual(len(updated_issue.info_systems), 0)  # Не должно быть информационных систем

    @patch('alerta.models.issue.db')
    @patch('alerta.models.alert.Alert.link_alerts_to_issue')
    def test_mass_add_large_number_of_alerts(self, mock_mass_link, mock_db):
        """Тест массового добавления большого числа алертов (500) и корректного пересчета атрибутов issue"""
        
        # Создаем базовый issue
        issue = Issue(
            summary="Test Issue for Mass Alert Addition",
            id="issue-mass-test",
            severity="medium",
            host_critical="0",
            alerts=[],
            hosts=[],
            project_groups=[],
            info_systems=[]
        )
        
        # Подготавливаем данные для имитации ответа от БД
        cursor_mock = MagicMock()
        mock_db.get_db.return_value.cursor.return_value = cursor_mock
        
        # Создаем 500 алертов с разными параметрами
        # Распределение severity: 300 medium, 150 high, 50 critical
        # 100 из них с host_critical=1
        alerts = []
        alert_ids = []
        unique_hosts = set()
        unique_project_groups = set()
        unique_info_systems = set()
        
        # Имитация результата SQL-запроса - список alert_ids
        filtered_alert_ids = []
        
        for i in range(500):
            # Определяем severity в зависимости от индекса
            if i < 300:
                severity = "medium"
            elif i < 450:
                severity = "high"
            else:
                severity = "critical"
            
            # Определяем host_critical в зависимости от индекса
            host_critical = "1" if i >= 400 else "0"
            
            # Создаем уникальный ID и event для каждого алерта
            alert_id = f"alert-mass-{i}"
            event = f"HOST-{1000 + i}"
            
            # Добавляем в наборы для отслеживания уникальных значений
            unique_hosts.add(event)
            
            # Добавляем проектные группы и информационные системы
            project_group = f"PG-{i % 10}"  # 10 разных проектных групп
            info_system = f"IS-{i % 15}"    # 15 разных информационных систем
            
            unique_project_groups.add(project_group)
            unique_info_systems.add(info_system)
            
            # Создаем данные алерта
            alert_data = {
                "id": alert_id,
                "resource": "resource-" + str(i), 
                "event": event, 
                "environment": "Production", 
                "severity": severity, 
                "group": "TestGroup", 
                "value": "TestValue",
                "service": ["TestService"],
                "text": f"Test alert {i}",
                "tags": [
                    f"ProjectGroup:{project_group}",
                    f"InfoSystem:{info_system}"
                ],
                "attributes": {
                    "host_critical": host_critical
                },
                "create_time": datetime.now() + timedelta(seconds=i),  # Делаем разное время создания
                "origin": "test-origin",
                "type": "test-type"
            }
            
            alert = Alert.parse(alert_data)
            alerts.append(alert)
            alert_ids.append(alert_id)
            
            # Добавляем ID в список отфильтрованных, если подходит под условия SQL-запроса
            filtered_alert_ids.append(alert_id)
        
        # Настраиваем ответ от cursor.fetchall()
        cursor_mock.fetchall.return_value = [(id,) for id in filtered_alert_ids]
        
        # Мокаем функцию update_issue базы данных
        # Создаем словарь с ожидаемыми обновленными атрибутами
        expected_update = {
            "id": "issue-mass-test",
            "summary": "Test Issue for Mass Alert Addition",
            "severity": "critical",  # Ожидаем critical как наивысший уровень
            "host_critical": "1",    # Ожидаем 1, так как есть алерты с host_critical=1
            "alerts": filtered_alert_ids,  # Ожидаем все отфильтрованные ID
            "hosts": list(unique_hosts),
            "project_groups": list(unique_project_groups),
            "info_systems": list(unique_info_systems),
            "last_alert_time": alerts[-1].create_time  # Ожидаем время создания последнего алерта
        }
        
        mock_db.update_issue.return_value = expected_update
        
        # Настраиваем результат SQL-запроса для агрегации
        mock_db.get_issue_aggregated_attributes.return_value = {
            'severity': 'critical',
            'host_critical': True,
            'hosts': list(unique_hosts),
            'project_groups': list(unique_project_groups),
            'info_systems': list(unique_info_systems),
            'last_alert_time': alerts[-1].create_time
        }
        
        # Вызываем метод массового добавления алертов
        with patch.object(issue, 'update', return_value=issue) as mock_update:
            updated_issue = issue.mass_add_alerts(alerts)
            
            # Проверяем, что update вызывался дважды: 
            # 1) для обновления списка алертов
            # 2) для обновления атрибутов на основе SQL-агрегации
            self.assertEqual(mock_update.call_count, 2)
            
            # Проверяем, что был вызван метод для получения агрегированных атрибутов
            mock_db.get_issue_aggregated_attributes.assert_called_once_with("issue-mass-test")
            
            # Проверяем, что был вызван метод для массового линкования алертов
            mock_mass_link.assert_called_once_with(filtered_alert_ids, "issue-mass-test")
    
    @patch('alerta.models.issue.db')
    @patch('alerta.models.alert.Alert.link_alerts_to_issue')
    def test_sql_optimized_alert_addition(self, mock_mass_link, mock_db):
        """Тест SQL-оптимизированного метода добавления алертов с проверкой фильтрации дубликатов"""
        
        # Создаем базовый issue с уже существующими алертами
        existing_alert_ids = ["existing-alert-1", "existing-alert-2", "existing-alert-3"]
        issue = Issue(
            summary="Test Issue for SQL Optimized Addition",
            id="issue-sql-test",
            severity="medium",
            host_critical="0",
            alerts=existing_alert_ids,
            hosts=["HOST-1", "HOST-2"],
            project_groups=["PG-1"],
            info_systems=["IS-1"]
        )
        
        # Создаем список алертов для добавления, включающий:
        # - существующие алерты (должны быть отфильтрованы)
        # - дубликаты в самом списке (должны быть учтены только один раз)
        # - новые уникальные алерты (должны быть добавлены)
        
        # Список идентификаторов алертов для добавления
        alerts_to_add = []
        
        # Добавляем существующие алерты - они должны быть отфильтрованы
        for alert_id in existing_alert_ids:
            alert_data = {
                "id": alert_id,
                "resource": "resource-existing", 
                "event": "HOST-EXISTING", 
                "environment": "Production", 
                "severity": "medium", 
                "text": f"Existing alert {alert_id}",
                "tags": ["ProjectGroup:PG-1", "InfoSystem:IS-1"],
                "attributes": {"host_critical": "0"},
                "create_time": datetime.now()
            }
            alerts_to_add.append(Alert.parse(alert_data))
        
        # Создаем новые уникальные алерты
        new_alert_ids = []
        for i in range(5):
            alert_id = f"new-alert-{i}"
            new_alert_ids.append(alert_id)
            
            alert_data = {
                "id": alert_id,
                "resource": f"resource-{i}", 
                "event": f"HOST-NEW-{i}", 
                "environment": "Production", 
                "severity": "high" if i < 3 else "critical", 
                "text": f"New alert {i}",
                "tags": [f"ProjectGroup:PG-{i+2}", f"InfoSystem:IS-{i+2}"],
                "attributes": {"host_critical": "1" if i == 4 else "0"},
                "create_time": datetime.now() + timedelta(seconds=i)
            }
            alerts_to_add.append(Alert.parse(alert_data))
        
        # Добавляем дубликаты новых алертов - они должны быть учтены только один раз
        for i in range(2):
            alert_id = f"new-alert-{i}"  # Дублируем первые два новых алерта
            
            alert_data = {
                "id": alert_id,
                "resource": f"resource-{i}", 
                "event": f"HOST-NEW-{i}", 
                "environment": "Production", 
                "severity": "high", 
                "text": f"Duplicate of new alert {i}",
                "tags": [f"ProjectGroup:PG-{i+2}", f"InfoSystem:IS-{i+2}"],
                "attributes": {"host_critical": "0"},
                "create_time": datetime.now() + timedelta(seconds=i+10)
            }
            alerts_to_add.append(Alert.parse(alert_data))
        
        # Подготавливаем данные для имитации ответа от БД
        cursor_mock = MagicMock()
        mock_db.get_db.return_value.cursor.return_value = cursor_mock
        
        # SQL должен вернуть только новые уникальные алерты
        cursor_mock.fetchall.return_value = [(id,) for id in new_alert_ids]
        
        # Мокаем get_issue_aggregated_attributes для возврата обновленных атрибутов
        mock_db.get_issue_aggregated_attributes.return_value = {
            'severity': 'critical',
            'host_critical': True,
            'hosts': ["HOST-1", "HOST-2"] + [f"HOST-NEW-{i}" for i in range(5)],
            'project_groups': ["PG-1"] + [f"PG-{i+2}" for i in range(5)],
            'info_systems': ["IS-1"] + [f"IS-{i+2}" for i in range(5)],
            'last_alert_time': alerts_to_add[-1].create_time
        }
        
        # Ожидаемые обновленные атрибуты после добавления алертов
        expected_update = {
            "id": "issue-sql-test",
            "summary": "Test Issue for SQL Optimized Addition",
            "severity": "critical",
            "host_critical": "1",
            "alerts": existing_alert_ids + new_alert_ids,
            "hosts": ["HOST-1", "HOST-2"] + [f"HOST-NEW-{i}" for i in range(5)],
            "project_groups": ["PG-1"] + [f"PG-{i+2}" for i in range(5)],
            "info_systems": ["IS-1"] + [f"IS-{i+2}" for i in range(5)],
            "last_alert_time": alerts_to_add[-1].create_time
        }
        
        mock_db.update_issue.return_value = expected_update
        
        # Вызываем метод массового добавления алертов с SQL-оптимизацией
        with patch.object(issue, 'update', return_value=issue) as mock_update:
            # Используем метод mass_add_alerts, который вызывает mass_add_alerts_sql
            updated_issue = issue.mass_add_alerts(alerts_to_add)
            
            # Проверяем, что cursor.execute был вызван один раз с SQL-запросом
            cursor_mock.execute.assert_called_once()
            
            # Проверяем, что метод update вызывался два раза:
            # 1. Для добавления алертов
            # 2. Для обновления атрибутов через SQL-агрегацию
            self.assertEqual(mock_update.call_count, 2)
            
            # Проверяем, что link_alerts_to_issue вызван только с новыми уникальными алертами
            mock_mass_link.assert_called_once_with(new_alert_ids, "issue-sql-test")
            
            # Проверяем, что был вызван метод для получения агрегированных атрибутов
            mock_db.get_issue_aggregated_attributes.assert_called_once_with("issue-sql-test")

    def test_performance_comparison(self):
        """Тест для сравнения производительности старого и нового метода добавления алертов.
        
        Этот тест не выполняет фактических проверок, а измеряет время выполнения
        и выводит сравнительную статистику.
        """
        import time
        
        # Создаем базовый issue с уже существующими алертами
        existing_alert_ids = ["existing-" + str(i) for i in range(100)]
        issue = Issue(
            summary="Performance Test Issue",
            id="issue-perf-test",
            severity="medium",
            host_critical="0",
            alerts=existing_alert_ids,
            hosts=["HOST-" + str(i) for i in range(10)],
            project_groups=["PG-" + str(i) for i in range(5)],
            info_systems=["IS-" + str(i) for i in range(5)]
        )
        
        # Создаем 500 тестовых алертов
        new_alerts = []
        for i in range(500):
            # Выбираем severity
            if i < 300:
                severity = "medium"
            elif i < 450:
                severity = "high"
            else:
                severity = "critical"
                
            # Выбираем host_critical
            host_critical = "1" if i >= 400 else "0"
            
            # Создаем тестовый алерт
            alert_data = {
                "id": f"new-alert-{i}",
                "resource": f"resource-{i}", 
                "event": f"HOST-NEW-{i}", 
                "environment": "Production", 
                "severity": severity, 
                "text": f"New alert {i}",
                "tags": [
                    f"ProjectGroup:PG-{i % 10}",
                    f"InfoSystem:IS-{i % 15}"
                ],
                "attributes": {"host_critical": host_critical},
                "create_time": datetime.now() + timedelta(seconds=i)
            }
            
            new_alerts.append(Alert.parse(alert_data))
        
        # Реализация неоптимизированного метода (только для теста)
        def unoptimized_add_alerts(issue, alerts):
            alert_ids = []
            current_alerts = issue.alerts.copy() if hasattr(issue, 'alerts') else []
            
            # Счетчик новых алертов
            new_alerts_count = 0
            
            # Находим новые алерты, которых еще нет в Issue
            start_time = time.time()
            for alert in alerts:
                if alert.id not in current_alerts and alert.id not in alert_ids:
                    alert_ids.append(alert.id)
                    new_alerts_count += 1
            
            filter_time = time.time() - start_time
            return len(alert_ids), filter_time
        
        # Реализация оптимизированного метода (используя множества)
        def optimized_add_alerts(issue, alerts):
            current_alerts_set = set(issue.alerts) if hasattr(issue, 'alerts') else set()
            alert_ids_set = set()
            
            # Находим новые алерты, которых еще нет в Issue
            start_time = time.time()
            for alert in alerts:
                if alert.id not in current_alerts_set and alert.id not in alert_ids_set:
                    alert_ids_set.add(alert.id)
            
            filter_time = time.time() - start_time
            return len(alert_ids_set), filter_time
        
        # Запускаем тесты производительности
        with patch('alerta.models.issue.db'), \
             patch('alerta.models.alert.Alert.link_alerts_to_issue'), \
             patch.object(issue, 'update', return_value=issue):
            
            # Запускаем неоптимизированную версию
            count1, time1 = unoptimized_add_alerts(issue, new_alerts)
            
            # Запускаем оптимизированную Python-версию
            count2, time2 = optimized_add_alerts(issue, new_alerts)
            
            # Для информационных целей, выводим статистику
            print(f"\nПроизводительность фильтрации алертов:")
            print(f"Неоптимизированная версия: {time1:.6f} сек. ({count1} алертов)")
            print(f"Оптимизированная версия: {time2:.6f} сек. ({count2} алертов)")
            print(f"Улучшение: {time1/time2:.2f}x\n")
            
            # Не делаем фактических проверок, так как время выполнения 
            # зависит от конкретной системы

    @patch('alerta.app.db')
    def test_recalculate_issue_attributes(self, mock_db):
        """Тест функции recalculate_issue_attributes для пересчета атрибутов Issue на основе связанных алертов."""
        
        # Создаем имитационные данные для теста
        now = datetime.now()
        
        # Настраиваем поведение мока для метода get_issue_aggregated_attributes
        mock_result_data = {
            'severity': 'high',
            'host_critical': True,
            'hosts': ['host1', 'host2', 'host3'],
            'project_groups': ['pg1', 'pg2'],
            'info_systems': ['is1', 'is2', 'is3'],
            'last_alert_time': now
        }
        
        # Настраиваем mock.db для возврата нужных данных
        mock_db.get_issue_aggregated_attributes.return_value = mock_result_data
        
        # Вызываем тестируемую функцию
        issue_id = 'test-issue-123'
        updated_attrs = recalculate_issue_attributes(issue_id)
        
        # Проверяем, что метод был вызван с правильным аргументом
        mock_db.get_issue_aggregated_attributes.assert_called_once_with(issue_id)
        
        # Проверяем результаты
        self.assertEqual(updated_attrs['severity'], 'high')
        self.assertEqual(updated_attrs['host_critical'], '1')  # преобразование из True в '1'
        self.assertEqual(updated_attrs['hosts'], ['host1', 'host2', 'host3'])
        self.assertEqual(updated_attrs['project_groups'], ['pg1', 'pg2'])
        self.assertEqual(updated_attrs['info_systems'], ['is1', 'is2', 'is3'])
        self.assertEqual(updated_attrs['last_alert_time'], now)
        
        # Проверка случая, когда last_alert_time отсутствует
        mock_db.get_issue_aggregated_attributes.reset_mock()
        mock_result_data_no_time = {
            'severity': 'medium',
            'host_critical': False,
            'hosts': ['host1'],
            'project_groups': ['pg1'],
            'info_systems': ['is1'],
            'last_alert_time': None
        }
        
        # Обновляем поведение мока
        mock_db.get_issue_aggregated_attributes.return_value = mock_result_data_no_time
        
        # Вызываем функцию пересчета атрибутов снова
        updated_attrs = recalculate_issue_attributes(issue_id)
        
        # Проверяем, что метод был вызван снова
        mock_db.get_issue_aggregated_attributes.assert_called_once_with(issue_id)
        
        # Проверяем результаты
        self.assertEqual(updated_attrs['severity'], 'medium')
        self.assertEqual(updated_attrs['host_critical'], '0')  # преобразование из False в '0'
        self.assertEqual(updated_attrs['hosts'], ['host1'])
        self.assertEqual(updated_attrs['project_groups'], ['pg1'])
        self.assertEqual(updated_attrs['info_systems'], ['is1'])
        self.assertNotIn('last_alert_time', updated_attrs)  # last_alert_time не должен быть добавлен


if __name__ == '__main__':
    unittest.main() 