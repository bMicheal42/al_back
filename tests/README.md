# Тесты для Issue и Alert

## Общее описание

Этот каталог содержит тесты для основных компонентов системы Alerta API, включая:
- Тесты для класса `Issue`
- Тесты для класса `Alert`
- Тесты для взаимодействия между `Issue` и `Alert`

## Тесты для Issue и Alert взаимодействия

### Файл `test_issue_alerts.py`

Этот файл содержит тесты, которые проверяют взаимодействие между `Issue` и `Alert` классами.

Основные тесты:

1. **test_create_issue_from_alert**: Проверяет создание нового Issue из Alert.
2. **test_add_alert_to_issue**: Проверяет добавление Alert в существующий Issue.
3. **test_remove_alert_from_issue**: Проверяет удаление Alert из Issue.
4. **test_mass_add_alerts_to_issue**: Проверяет массовое добавление нескольких Alert к Issue.
5. **test_mass_remove_alerts_from_issue**: Проверяет массовое удаление нескольких Alert из Issue.
6. **test_remove_all_alerts_from_issue**: Проверяет, что при удалении всех Alert из Issue, Issue закрывается.
7. **test_cannot_unlink_last_alert_from_issue**: Проверяет, что нельзя отлинковать последний Alert от Issue.

Новые тесты:

8. **test_recalculate_issue_attributes**: Проверяет работу функции recalculate_issue_attributes_sql для пересчета атрибутов Issue (severity, host_critical, hosts, project_groups, info_systems, last_alert_time) на основе связанных алертов с использованием SQL-агрегации.

Планируемые тесты (не реализованы):

9. **test_unique_arrays_update**: Проверка обновления уникальных массивов hosts, project_groups и info_systems при добавлении и удалении алертов.
10. **test_severity_changes_with_alerts**: Проверка изменения severity при добавлении и удалении алертов с разной степенью важности.
11. **test_host_critical_changes_with_alerts**: Проверка изменения host_critical при добавлении и удалении алертов.
12. **test_last_alert_time_updates**: Проверка обновления last_alert_time при добавлении и удалении алертов.
13. **test_arrays_updates**: Проверка обновления уникальных массивов hosts, project_groups и info_systems при добавлении и удалении алертов.
14. **test_alert_issue_link_unlink**: Проверка корректного связывания alert_id и issue_id при линковании и отлинковании.

## Запуск тестов

Для запуска всех тестов:

```bash
cd /path/to/alerta_api
python -m unittest discover -s tests
```

Для запуска конкретного теста:
```bash
cd /path/to/alerta_api
python -m unittest tests.test_issue_alerts.TestIssueAlerts.test_severity_changes_with_alerts
```

## Запуск тестов для Issue с подробным выводом

Для запуска всех тестов Issue с подробным выводом:

```bash
cd /path/to/alerta_api
python run_issue_tests.py
```

Для запуска конкретного теста:
```bash
cd /path/to/alerta_api
python run_issue_tests.py test_recalculate_issue_attributes
```

## Дополнительные скрипты

- **run_issue_tests.py** - запускает все тесты для функциональности Issue с подробным выводом 