import logging
from typing import List, Optional

from flask import g

from alerta.app import create_celery_app
from alerta.exceptions import InvalidAction, RejectException
from alerta.models.alert import Alert
from alerta.utils.api import process_action, process_status

celery = create_celery_app()


@celery.task
def action_alerts(alerts: List[str], action: str, text: str, timeout: Optional[int], login: str) -> None:
    updated = []
    errors = []
    for alert_id in alerts:
        alert = Alert.find_by_id(alert_id)

        try:
            g.login = login
            previous_status = alert.status
            # pre action
            alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout)
            # update status
            alert = alert.from_action(action, text, timeout)
            if was_updated:
                alert = alert.recalculate_incident_close()
                alert.recalculate_status_durations()
                alert.update_attributes(alert.attributes)
            # post action
            alert, action, text, timeout, was_updated = process_action(alert, action, text, timeout, post_action=True)
        except RejectException as e:
            errors.append(str(e))
            continue
        except InvalidAction as e:
            errors.append(str(e))
            continue
        except Exception as e:
            errors.append(str(e))
            continue

        # if previous_status != alert.status:
        #     try:
        #         alert, status, text = process_status(alert, alert.status, text)
        #         alert = alert.from_status(status, text, timeout)
        #     except RejectException as e:
        #         errors.append(str(e))
        #         continue
        #     except Exception as e:
        #         errors.append(str(e))
        #         continue

        updated.append(alert.id)
