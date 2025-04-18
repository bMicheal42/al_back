import logging
import traceback
import threading
import time
from collections import defaultdict, namedtuple
from datetime import datetime, timezone
from typing import List, Dict, Any
import json
import re

import psycopg2
from flask import current_app
from psycopg2.extensions import AsIs, adapt, register_adapter
from psycopg2.extras import Json, NamedTupleCursor, register_composite

from alerta.app import alarm_model
from alerta.database.base import Database
from alerta.exceptions import NoCustomerMatch
from alerta.models.enums import ADMIN_SCOPES
from alerta.models.heartbeat import HeartbeatStatus
from alerta.utils.format import DateTime
from alerta.utils.response import absolute_url

from .utils import Query

MAX_RETRIES = 5


class HistoryAdapter:
    def __init__(self, history):
        self.history = history
        self.conn = None

    def prepare(self, conn):
        self.conn = conn

    def getquoted(self):
        def quoted(o):
            if isinstance(o, datetime):
                o = DateTime.iso8601(o)
            a = adapt(o)
            if hasattr(a, 'prepare'):
                a.prepare(self.conn)
            return a.getquoted().decode('utf-8')

        history_str = '({}, {}, {}, {}, {}, {}, {}, {}::timestamp, {}, {})::history'.format(
            quoted(self.history.id),
            quoted(self.history.event),
            quoted(self.history.severity),
            quoted(self.history.status),
            quoted(self.history.value),
            quoted(self.history.text),
            quoted(self.history.change_type),
            quoted(self.history.update_time),
            quoted(self.history.user),
            quoted(self.history.timeout)
        )
        
        return history_str

    def __str__(self):
        return str(self.getquoted())


Record = namedtuple('Record', [
    'id', 'resource', 'event', 'environment', 'severity', 'status', 'service',
    'group', 'value', 'text', 'tags', 'attributes', 'origin', 'update_time',
    'user', 'timeout', 'type', 'customer'
])


class Backend(Database):

    def create_engine(self, app, uri, dbname=None, schema='public', raise_on_error=True):
        self.uri = uri
        self.dbname = dbname
        self.schema = schema

        lock = threading.Lock()
        with lock:
            conn = self.connect()

            with app.open_resource('sql/schema.sql') as f:
                try:
                    conn.cursor().execute(f.read())
                    conn.commit()
                except Exception as e:
                    if raise_on_error:
                        raise
                    app.logger.warning(e)

        register_adapter(dict, Json)
        register_adapter(datetime, self._adapt_datetime)
        register_composite(
            schema + '.history' if schema else 'history',
            conn,
            globally=True
        )
        from alerta.models.alert import History
        register_adapter(History, HistoryAdapter)

    def _bind_param(self):
        """
        Возвращает плейсхолдер для параметра в SQL запросе в зависимости от драйвера БД.
        Для PostgreSQL это %s
        """
        return '%s'
        
    def connect(self):
        retry = 0
        while True:
            try:
                conn = psycopg2.connect(
                    dsn=self.uri,
                    dbname=self.dbname,
                    cursor_factory=NamedTupleCursor
                )

                conn.set_client_encoding('UTF8')
                break
            except Exception as e:
                print(e)  # FIXME - should log this error instead of printing, but current_app is unavailable here
                retry += 1
                if retry > MAX_RETRIES:
                    conn = None
                    break
                else:
                    backoff = 2 ** retry
                    print(f'Retry attempt {retry}/{MAX_RETRIES} (wait={backoff}s)...')
                    time.sleep(backoff)

        if conn:
            conn.cursor().execute('SET search_path TO {}'.format(self.schema))
            conn.commit()
            return conn
        else:
            raise RuntimeError(f'Database connect error. Failed to connect after {MAX_RETRIES} retries.')

    @staticmethod
    def _adapt_datetime(dt):
        iso_dt = DateTime.iso8601(dt)
        return AsIs(f'{adapt(iso_dt)}')

    @property
    def name(self):
        cursor = self.get_db().cursor()
        cursor.execute('SELECT current_database()')
        return cursor.fetchone()[0]

    @property
    def version(self):
        cursor = self.get_db().cursor()
        cursor.execute('SHOW server_version')
        return cursor.fetchone()[0]

    @property
    def is_alive(self):
        cursor = self.get_db().cursor()
        cursor.execute('SELECT true')
        return cursor.fetchone()

    def close(self, db):
        db.close()

    def destroy(self):
        conn = self.connect()
        cursor = conn.cursor()
        for table in ['alerts', 'blackouts', 'customers', 'groups', 'heartbeats', 'keys', 'metrics', 'perms', 'users']:
            cursor.execute(f'DROP TABLE IF EXISTS {table}')
        conn.commit()
        conn.close()

    # ALERTS

    def get_severity(self, alert):
        select = """
            SELECT severity FROM alerts
             WHERE environment=%(environment)s AND resource=%(resource)s
               AND ((event=%(event)s AND severity!=%(severity)s)
                OR (event!=%(event)s AND %(event)s=ANY(correlate)))
               AND {customer}
            """.format(customer='customer=%(customer)s' if alert.customer else 'customer IS NULL')
        return self._fetchone(select, vars(alert)).severity

    def get_status(self, alert):
        select = """
            SELECT status FROM alerts
             WHERE environment=%(environment)s AND resource=%(resource)s
              AND (event=%(event)s OR %(event)s=ANY(correlate))
              AND {customer}
            """.format(customer='customer=%(customer)s' if alert.customer else 'customer IS NULL')
        return self._fetchone(select, vars(alert)).status

    def are_potential_duplicates(self, alert):
        select = """
            SELECT * FROM alerts
             WHERE environment=%(environment)s
               AND (attributes->>'incident')::boolean = true
               AND id != %(id)s
               AND (
                   resource = %(resource)s OR
                   event = %(event)s OR
                   service = %(service)s
                )
               AND status != 'closed'
            """
        return self._fetchall(select, vars(alert))

    def pattern_match_duplicated(self, alert, pattern_query):
        select = """
            SELECT * FROM alerts
             WHERE environment=%(environment)s
               AND (attributes->>'incident')::boolean = true
               AND id != %(id)s
               AND ({pattern_query})
               ORDER BY create_time DESC
            """

        select = select.format(pattern_query=pattern_query)

        alert_vars = dict(vars(alert))
        raw_tags = alert.tags
        additional_fields_dict = {}
        for tag in raw_tags:
            if ":" not in tag:
                logging.warning(f"Tag '{tag}' does not contain a ':'. Skipping it.")
                continue
            key, value = tag.split(":", 1)
            additional_fields_dict[f"tags.{key}"] = tag
        if alert.attributes:
            for key, value in alert.attributes.items():
                additional_fields_dict[f"attributes.{key}"] = value

        alert_vars.update(additional_fields_dict)

        required_keys = set(re.findall(r"%\((tags\.\w+)\)s", pattern_query))

        for key in required_keys:
            if key not in alert_vars:
                logging.warning(f"Pattern query requires key {key}, but it is missing in {alert.id}")
                alert_vars[key] = None  # Избегаем KeyError

        try:
            return self._fetchall(select, alert_vars, 5000000)
        except KeyError as e:
            missing_key = str(e)
            logging.warning(f"Missing key in alert variables: {missing_key}. (pattern_match_duplicated)")
            return []

    def all_children_match_pattern(self, parent_alert, child_alert_ids, pattern_query):
        select = """
            SELECT id FROM alerts
             WHERE environment=%(environment)s
               AND ({pattern_query})
        """

        select = select.format(pattern_query=pattern_query)

        parent_vars = dict(vars(parent_alert))
        raw_tags = parent_alert.tags
        additional_fields_dict = {}

        for tag in raw_tags:
            if ":" not in tag:
                logging.warning(f"Tag '{tag}' does not contain a ':'. Skipping it.")
                continue
            key, value = tag.split(":", 1)
            additional_fields_dict[f"tags.{key}"] = tag

        if parent_alert.attributes:
            for key, value in parent_alert.attributes.items():
                additional_fields_dict[f"attributes.{key}"] = value

        parent_vars.update(additional_fields_dict)
        parent_vars["child_alert_ids"] = tuple(child_alert_ids)

        required_keys = set(re.findall(r"%\((tags\.\w+)\)s", pattern_query))

        for key in required_keys:
            if key not in parent_vars:
                logging.warning(f"Pattern query requires key {key}, but it is missing in {parent_alert.id}")
                parent_vars[key] = None

        try:
            matched_records = self._fetchall(select, parent_vars, 5000000)
            matched_ids = {row.id for row in matched_records}

            res = set(child_alert_ids).issubset(matched_ids)

            return res
        except KeyError as e:
            missing_key = str(e)
            logging.warning(f"Missing key in parent alert variables: {missing_key}. (all_children_match_pattern)")
            return False

    def is_correlated(self, alert):
        select = """
            SELECT * FROM alerts
             WHERE environment=%(environment)s AND resource=%(resource)s
               AND ((event=%(event)s AND severity!=%(severity)s)
                OR (event!=%(event)s AND %(event)s=ANY(correlate)))
               AND {customer}
        """.format(customer='customer=%(customer)s' if alert.customer else 'customer IS NULL')
        return self._fetchone(select, vars(alert))

    def is_flapping(self, alert, window=1800, count=2):
        """
        Return true if alert severity has changed more than X times in Y seconds
        """
        select = """
            SELECT COUNT(*)
              FROM alerts, unnest(history) h
             WHERE environment=%(environment)s
               AND resource=%(resource)s
               AND h.event=%(event)s
               AND h.update_time > (NOW() at time zone 'utc' - INTERVAL '{window} seconds')
               AND h.type='severity'
               AND {customer}
        """.format(window=window, customer='customer=%(customer)s' if alert.customer else 'customer IS NULL')
        return self._fetchone(select, vars(alert)).count > count

    # def dedup_alert(self, alert, history):
    #     """
    #     Update alert status, service, value, text, timeout and rawData, increment duplicate count and set
    #     repeat=True, and keep track of last receive id and time but don't append to history unless status changes.
    #     """
    #     alert.history = history
    #     update = """
    #         UPDATE alerts
    #            SET status=%(status)s, service=%(service)s, value=%(value)s, text=%(text)s,
    #                timeout=%(timeout)s, raw_data=%(raw_data)s, repeat=%(repeat)s,
    #                last_receive_id=%(last_receive_id)s, last_receive_time=%(last_receive_time)s,
    #                tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(tags)s)), attributes=attributes || %(attributes)s,
    #                duplicate_count=duplicate_count + 1, {update_time}, history=(%(history)s || history)[1:{limit}]
    #          WHERE environment=%(environment)s
    #            AND resource=%(resource)s
    #            AND event=%(event)s
    #            AND severity=%(severity)s
    #            AND {customer}
    #      RETURNING *
    #     """.format(
    #         limit=current_app.config['HISTORY_LIMIT'],
    #         update_time='update_time=%(update_time)s' if alert.update_time else 'update_time=update_time',
    #         customer='customer=%(customer)s' if alert.customer else 'customer IS NULL'
    #     )
    #     return self._updateone(update, vars(alert), returning=True)

    def dedup_alert(self, id, last_receive_id, last_receive_time):
        """
        Update last_receive_id and last_receive_time for the given alert ID.
        """
        update = """
            UPDATE alerts
            SET last_receive_time=%(last_receive_time)s
            WHERE id=%(id)s OR id LIKE %(like_id)s
        RETURNING *
        """
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'last_receive_id': last_receive_id, 'last_receive_time': last_receive_time}, returning=True)
    
    def correlate_alert(self, alert, history):
        alert.history = history
        update = """
            UPDATE alerts
               SET event=%(event)s, severity=%(severity)s, status=%(status)s, service=%(service)s, value=%(value)s,
                   text=%(text)s, create_time=%(create_time)s, timeout=%(timeout)s, raw_data=%(raw_data)s,
                   duplicate_count=%(duplicate_count)s, repeat=%(repeat)s, previous_severity=%(previous_severity)s,
                   trend_indication=%(trend_indication)s, receive_time=%(receive_time)s, last_receive_id=%(last_receive_id)s,
                   last_receive_time=%(last_receive_time)s, tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(tags)s)),
                   attributes=attributes || %(attributes)s, {update_time}, history=(%(history)s || history)[1:{limit}]
             WHERE environment=%(environment)s
               AND resource=%(resource)s
               AND ((event=%(event)s AND severity!=%(severity)s) OR (event!=%(event)s AND %(event)s=ANY(correlate)))
               AND {customer}
         RETURNING *
        """.format(
            limit=current_app.config['HISTORY_LIMIT'],
            update_time='update_time=%(update_time)s' if alert.update_time else 'update_time=update_time',
            customer='customer=%(customer)s' if alert.customer else 'customer IS NULL'
        )
        return self._updateone(update, vars(alert), returning=True)

    def create_alert(self, alert):
        insert = """
            INSERT INTO alerts (id, resource, event, environment, severity, correlate, status, service, "group",
                value, text, tags, attributes, origin, type, create_time, timeout, raw_data, customer,
                duplicate_count, repeat, previous_severity, trend_indication, receive_time, last_receive_id,
                last_receive_time, update_time, history)
            VALUES (%(id)s, %(resource)s, %(event)s, %(environment)s, %(severity)s, %(correlate)s, %(status)s,
                %(service)s, %(group)s, %(value)s, %(text)s, %(tags)s, %(attributes)s, %(origin)s,
                %(event_type)s, %(create_time)s, %(timeout)s, %(raw_data)s, %(customer)s, %(duplicate_count)s,
                %(repeat)s, %(previous_severity)s, %(trend_indication)s, %(receive_time)s, %(last_receive_id)s,
                %(last_receive_time)s, %(update_time)s, %(history)s::history[])
            RETURNING *
        """
        return self._insert(insert, vars(alert))

    def set_alert(self, id, severity, status, tags, attributes, timeout, previous_severity, update_time, history=None):
        update = """
            UPDATE alerts
               SET severity=%(severity)s, status=%(status)s, tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(tags)s)),
                   attributes=%(attributes)s, timeout=%(timeout)s, previous_severity=%(previous_severity)s,
                   update_time=%(update_time)s, history=(%(change)s || history)[1:{limit}]
             WHERE id=%(id)s OR id LIKE %(like_id)s
         RETURNING *
        """.format(limit=current_app.config['HISTORY_LIMIT'])
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'severity': severity, 'status': status,
                                        'tags': tags, 'attributes': attributes, 'timeout': timeout,
                                        'previous_severity': previous_severity, 'update_time': update_time,
                                        'change': history}, returning=True)

    
    # def set_alert(self, id, severity=None, status=None, tags=None, attributes=None, timeout=None, 
    #             previous_severity=None, update_time=None, history=None):
    #     fields_to_update = []
    #     params = {'id': id, 'like_id': id + '%'}
        
    #     def add_update_field(field_name, field_value, sql_expression=None):
    #         if field_value is not None:
    #             fields_to_update.append(sql_expression or f"{field_name}=%({field_name})s")
    #             params[field_name] = field_value

    #     add_update_field('severity', severity)
    #     add_update_field('status', status)
    #     add_update_field('tags', tags, "tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(tags)s))")
    #     add_update_field('attributes', attributes)
    #     add_update_field('timeout', timeout)
    #     add_update_field('previous_severity', previous_severity)
    #     add_update_field('update_time', update_time)
    #     add_update_field('history', history, f"history=(%(change)s || history)[1:{current_app.config['HISTORY_LIMIT']}]")

    #     if not fields_to_update:
    #         raise ValueError("No fields to update")

    #     update_query = f"""
    #         UPDATE alerts
    #             SET {", ".join(fields_to_update)}
    #             WHERE id=%(id)s OR id LIKE %(like_id)s
    #         RETURNING *
    #     """

    #     return self._updateone(update_query, params, returning=True)


    def get_alert(self, id, customers=None):
        select = """
            SELECT * FROM alerts
             WHERE (id ~* (%(id)s) OR id LIKE %(like_id)s)
               AND {customer}
        """.format(customer='customer=ANY(%(customers)s)' if customers else '1=1')
        return self._fetchone(select, {'id': '^' + id, 'like_id': id + '%', 'customers': customers})

    def get_parent(self, id):
        select = """
            SELECT * FROM alerts
            WHERE attributes->'duplicate alerts' ? :id
        """
        return self._fetchone(select, {'id': id})

    def get_parent_with_children(self, id):
        select = """
            WITH parent AS (
                SELECT * 
                FROM alerts 
                WHERE attributes->'duplicate alerts' @> to_jsonb(%s::text)
            ),
            children AS (
                SELECT * 
                FROM alerts 
                WHERE id IN (
                    SELECT jsonb_array_elements_text(attributes->'duplicate alerts') 
                    FROM parent
                )
            )
            SELECT * FROM parent 
            UNION ALL
            SELECT * FROM children
        """
        try:
            return self._fetchall(select, (str(id),), 5000000)
        except Exception as e:
            logging.error(f"Error fetching parent with children ({id}): {e}")
            return []

    # STATUS, TAGS, ATTRIBUTES

    def set_status(self, id, status, timeout, update_time, history=None):
        update = """
            UPDATE alerts
            SET status=%(status)s, timeout=%(timeout)s, update_time=%(update_time)s, history=(%(change)s || history)[1:{limit}]
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING *
        """.format(limit=current_app.config['HISTORY_LIMIT'])
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'status': status, 'timeout': timeout, 'update_time': update_time, 'change': history}, returning=True)

    def tag_alert(self, id, tags):
        update = """
            UPDATE alerts
            SET tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(tags)s))
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING *
        """
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'tags': tags}, returning=True)

    def untag_alert(self, id, tags):
        update = """
            UPDATE alerts
            SET tags=(select array_agg(t) FROM unnest(tags) AS t WHERE NOT t=ANY(%(tags)s) )
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING *
        """
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'tags': tags}, returning=True)

    def update_tags(self, id, tags):
        update = """
            UPDATE alerts
            SET tags=%(tags)s
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING *
        """
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'tags': tags}, returning=True)

    def update_attributes(self, id, old_attrs, new_attrs):
        old_attrs.update(new_attrs)
        attrs = {k: v for k, v in old_attrs.items() if v is not None}

        update = """
            UPDATE alerts
            SET attributes=%(attrs)s
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING attributes
        """
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'attrs': attrs}, returning=True).attributes

    def mass_update_attributes(self, updates: List[Dict[str, Any]]) -> bool:
        if not updates:
            return True  # nothing to update

        try:
            values = [(update['id'], json.dumps(update['attributes'])) for update in updates]
            values_sql = ', '.join(["(%s, %s::jsonb)"] * len(values))
            update_query = f"""
                UPDATE alerts
                SET attributes = attributes || data.new_attrs
                FROM (VALUES {values_sql}) AS data(id, new_attrs)
                WHERE alerts.id = data.id
            """
            query_params = [param for item in values for param in item]
            self._updateall(update_query, query_params)
            return True
        except Exception as e:
            logging.error("Error updating attributes: %s", repr(e))
            return False

    def mass_update_last_receive_time(self, updates: List[Dict[str, Any]]) -> bool:
        if not updates:
            return True  # nothing to update

        try:
            values = [(update["id"], update["last_receive_time"]) for update in updates]
            values_sql = ', '.join(["(%s, %s)"] * len(values))
            update_query = f"""
                UPDATE alerts
                SET last_receive_time = data.new_time::timestamp
                FROM (VALUES {values_sql}) AS data(id, new_time)
                WHERE alerts.id = data.id
            """
            query_params = [param for item in values for param in item]
            self._updateall(update_query, query_params)
            return True
        except Exception as e:
            logging.error("Error updating last_receive_time: %s", repr(e))
            return False

    def mass_update_status(self, alert_ids, status, timeout, update_time):
        """
        Массовое обновление статусов для списка алертов
        
        :param alert_ids: Список ID алертов для обновления
        :param status: Новый статус
        :param timeout: Значение таймаута
        :param update_time: Время обновления
        :return: Список ID обновленных алертов
        """
        if not alert_ids:
            return []
        
        try:
            # Преобразуем список ID в строку для SQL запроса
            placeholders = ','.join(['%s'] * len(alert_ids))
            
            # Запрос для обновления статусов нескольких алертов одновременно
            update_query = f"""
                UPDATE alerts
                SET status=%s, timeout=%s, update_time=%s
                WHERE id IN ({placeholders})
                RETURNING id
            """
            
            # Подготавливаем параметры запроса
            query_params = [status, timeout, update_time] + alert_ids
            
            # Выполняем запрос и возвращаем список обновленных ID
            result = self._updateall(update_query, query_params, returning=True)
            return [row[0] for row in result]
        except Exception as e:
            logging.error("Error in mass_update_status: %s", repr(e))
            return []

    def delete_alert(self, id):
        delete = """
            DELETE FROM alerts
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING id
        """
        return self._deleteone(delete, {'id': id, 'like_id': id + '%'}, returning=True)

    # BULK

    def tag_alerts(self, query=None, tags=None):
        query = query or Query()
        update = f"""
            UPDATE alerts
            SET tags=ARRAY(SELECT DISTINCT UNNEST(tags || %(_tags)s))
            WHERE {query.where}
            RETURNING id
        """
        return [row[0] for row in self._updateall(update, {**query.vars, **{'_tags': tags}}, returning=True)]

    def untag_alerts(self, query=None, tags=None):
        query = query or Query()
        update = """
            UPDATE alerts
            SET tags=(select array_agg(t) FROM unnest(tags) AS t WHERE NOT t=ANY(%(_tags)s) )
            WHERE {where}
            RETURNING id
        """.format(where=query.where)
        return [row[0] for row in self._updateall(update, {**query.vars, **{'_tags': tags}}, returning=True)]

    def update_attributes_by_query(self, query=None, attributes=None):
        update = f"""
            UPDATE alerts
            SET attributes=attributes || %(_attributes)s
            WHERE {query.where}
            RETURNING id
        """
        return [row[0] for row in self._updateall(update, {**query.vars, **{'_attributes': attributes}}, returning=True)]

    def delete_alerts(self, query=None):
        query = query or Query()
        delete = f"""
            DELETE FROM alerts
            WHERE {query.where}
            RETURNING id
        """
        return [row[0] for row in self._deleteall(delete, query.vars, returning=True)]

    # SEARCH & HISTORY

    def add_history(self, id, history):
        update = """
            UPDATE alerts
               SET history=(%(history)s || history)[1:{limit}]
             WHERE id=%(id)s OR id LIKE %(like_id)s
         RETURNING *
        """.format(limit=current_app.config['HISTORY_LIMIT'])
        return self._updateone(update, {'id': id, 'like_id': id + '%', 'history': history}, returning=True)


    def get_alerts(self, query=None, raw_data=False, history=False, page=None, page_size=20):
        query = query or Query()
        if raw_data and history:
            select = '*'
        else:
            select = (
                'id, resource, event, environment, severity, correlate, status, service, "group", value, "text",'
                + 'tags, attributes, origin, type, create_time, timeout, {raw_data}, customer, duplicate_count, repeat,'
                + 'previous_severity, trend_indication, receive_time, last_receive_id, last_receive_time, update_time,'
                + '{history}'
            ).format(
                raw_data='raw_data' if raw_data else 'NULL as raw_data',
                history='history' if history else 'array[]::history[] as history'
            )

        join = ''
        if 's.code' in query.sort:
            join += 'JOIN (VALUES {}) AS s(sev, code) ON alerts.severity = s.sev '.format(
                ', '.join((f"('{k}', {v})" for k, v in alarm_model.Severity.items()))
            )
        if 'st.state' in query.sort:
            join += 'JOIN (VALUES {}) AS st(sts, state) ON alerts.status = st.sts '.format(
                ', '.join((f"('{k}', '{v}')" for k, v in alarm_model.Status.items()))
            )

        select = f"""
            WITH incident_alerts AS (
                SELECT *
                FROM alerts {join}
                WHERE (attributes->>'incident')::boolean = true AND {query.where}
                ORDER BY {query.sort or 'last_receive_time'}
                OFFSET {(page - 1) * page_size}
                LIMIT {page_size}
            ),
            duplicate_alerts AS (
                SELECT a.*
                FROM alerts a
                JOIN incident_alerts ia
                    ON a.id IN (
                        SELECT jsonb_array_elements_text(ia.attributes -> 'duplicate alerts')::text
                    )
            )
            SELECT {select}
            FROM incident_alerts
            UNION ALL
            SELECT {select}
            FROM duplicate_alerts
        """
        return self._fetchall(select, query.vars, limit=page_size*5000, offset=0)


    def get_allAlerts(self, query=None):
        query = query or Query()

        select = """
            SELECT id, resource, event, environment, severity, correlate, status, service, "group", value, "text",
                   tags, attributes, origin, type, create_time, timeout, raw_data, customer, duplicate_count, repeat,
                   previous_severity, trend_indication, receive_time, last_receive_id, last_receive_time, update_time, history
            FROM alerts
            WHERE {where}
            ORDER BY {sort}
        """.format(
            where=query.where or 'true',
            sort=query.sort or 'last_receive_time DESC'
        )
        return self._fetchall(select, query.vars)


    def find_by_ids(self, ids: List[str]):
        if not ids:
            return []
        select = """
            SELECT * FROM alerts
            WHERE id = ANY(%(ids)s)
            ORDER BY create_time DESC
        """

        try:
            return self._fetchall(select, {'ids': ids}, 5000000)
        except Exception as e:
            logging.error(f"Error fetching alerts by IDs: {e}")
            return []

    def find_by_jira_keys(self, ids: List[str]):
        if not ids:
            return []
        select = """
            SELECT * FROM alerts
            WHERE attributes->>'incident' = 'true'
            AND attributes->>'jira_key' = ANY(%(ids)s)
            ORDER BY create_time DESC
        """

        try:
            return self._fetchall(select, {'ids': ids})
        except Exception as e:
            logging.error(f"Error fetching alerts by Jira keys: {e}")
            return []

    def find_by_zabbix_meta(self, zabbix_id: str, origin: str):
        select = """
            SELECT * FROM alerts
            WHERE origin = %(origin)s
            AND attributes->>'zabbix_id' = %(zabbix_id)s
            ORDER BY create_time DESC
        """

        try:
            return self._fetchall(select, {'origin': origin, 'zabbix_id': zabbix_id}, 5000000)
        except Exception as e:
            logging.error(f"Error fetching alerts by Zabbix meta [{origin}, {zabbix_id}]: {e}")
            return []

    def get_alert_history(self, alert, page=None, page_size=None):
        select = """
            SELECT resource, environment, service, "group", tags, attributes, origin, customer, h.*
              FROM alerts, unnest(history[1:{limit}]) h
             WHERE alerts.id=%(id)s
          ORDER BY update_time DESC
            """.format(
            customer='customer=%(customer)s' if alert.customer else 'customer IS NULL',
            limit=current_app.config['HISTORY_LIMIT']
        )
        return [
            Record(
                id=h.id,
                resource=h.resource,
                event=h.event,
                environment=h.environment,
                severity=h.severity,
                status=h.status,
                service=h.service,
                group=h.group,
                value=h.value,
                text=h.text,
                tags=h.tags,
                attributes=h.attributes,
                origin=h.origin,
                update_time=h.update_time,
                user=getattr(h, 'user', None),
                timeout=getattr(h, 'timeout', None),
                type=h.type,
                customer=h.customer
            ) for h in self._fetchall(select, vars(alert), limit=page_size, offset=(page - 1) * page_size)
        ]

    def get_history(self, query=None, page=None, page_size=None):
        query = query or Query()
        if 'id' in query.vars:
            select = """
                SELECT a.id
                  FROM alerts a, unnest(history[1:{limit}]) h
                 WHERE h.id LIKE %(id)s
            """.format(limit=current_app.config['HISTORY_LIMIT'])
            query.vars['id'] = self._fetchone(select, query.vars)

        select = """
            SELECT resource, environment, service, "group", tags, attributes, origin, customer, history, h.*
              FROM alerts, unnest(history[1:{limit}]) h
             WHERE {where}
          ORDER BY update_time DESC
        """.format(where=query.where, limit=current_app.config['HISTORY_LIMIT'])

        return [
            Record(
                id=h.id,
                resource=h.resource,
                event=h.event,
                environment=h.environment,
                severity=h.severity,
                status=h.status,
                service=h.service,
                group=h.group,
                value=h.value,
                text=h.text,
                tags=h.tags,
                attributes=h.attributes,
                origin=h.origin,
                update_time=h.update_time,
                user=getattr(h, 'user', None),
                timeout=getattr(h, 'timeout', None),
                type=h.type,
                customer=h.customer
            ) for h in self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)
        ]

    # ANALYTICS
    def get_analytics_data(self, from_date=None, to_date=None, full: bool = False):
        from_date = from_date or datetime(1970, 1, 1, tzinfo=timezone.utc)
        to_date = to_date or datetime.now(timezone.utc)

        from_date = from_date.replace(microsecond=0).isoformat()
        to_date = to_date.replace(microsecond=0).isoformat()
        fullColumns = """
            ,a.text,
            a.attributes->>'zabbix_trigger_id' AS zabbix_trigger_id,
            a.attributes->>'zabbix_id' AS zabbix_id,
            t.project_group,
            t.info_system
        """ if full else ''
        select = f"""
            WITH history_parsed AS (
                SELECT 
                    a.id,
                    hist_elements[4] AS event_status,    
                    trim(both '"' from hist_elements[6]) AS event_comment,  
                    hist_elements[7] AS event_action,
                    CASE 
                        WHEN trim(both '"' from hist_elements[8]) ~ '^\d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}\.\d+$' 
                        THEN trim(both '"' from hist_elements[8])::timestamp
                        ELSE NULL 
                    END AS event_time
                FROM alerts a, unnest(a.history) AS hist_str
                CROSS JOIN LATERAL (
                    SELECT regexp_split_to_array(trim(both '()' from hist_str::TEXT), ',') AS hist_elements
                ) AS extracted
            ),
            time_extracted AS (
                SELECT 
                    id,
                    MIN(event_time) FILTER (WHERE event_status = 'ack') AS ack_time,
                    MIN(event_time) FILTER (WHERE event_status = 'false-positive') AS false_positive_time,
                    MIN(event_time) FILTER (WHERE event_status = 'fixing-by-24/7') AS fixing_time,
                    MIN(event_time) FILTER (WHERE event_status = 'closed') AS resolve_time,
                    MIN(event_time) FILTER (WHERE event_comment = 'Resolved inc alert from zabbix') AS zabbix_resolve_time
                FROM history_parsed
                GROUP BY id
            ),
            tags_extracted AS (
                SELECT 
                    id,
                    MAX(split_part(tag, ':', 2)) FILTER (WHERE tag LIKE 'ProjectGroup:%') AS project_group,
                    MAX(split_part(tag, ':', 2)) FILTER (WHERE tag LIKE 'InfoSystem:%') AS info_system
                FROM alerts, unnest(tags) AS tag
                GROUP BY id
            )
            SELECT 
                a.severity,
                a.event AS host,
                a.id,
                a.attributes->>'acked-by' AS acked_by,
                (a.attributes->>'incident')::boolean AS incident,
                a.attributes->>'jira_url' AS jira_url,
                COALESCE(
                    (SELECT array_agg(value) FROM jsonb_array_elements_text((a.attributes->'duplicate alerts')::jsonb) AS value),
                    ARRAY[]::text[]
                ) AS duplicate_alerts,
                a.status,
                a.receive_time,
                (a.attributes->>'wasIncident')::boolean AS was_incident,
                te.ack_time,
                te.false_positive_time,
                te.fixing_time,
                te.resolve_time,
                te.zabbix_resolve_time
                {fullColumns}
            FROM alerts a
            LEFT JOIN time_extracted te ON a.id = te.id
            LEFT JOIN tags_extracted t ON a.id = t.id
            WHERE 
                a.receive_time BETWEEN '{from_date}' AND '{to_date}'
            ORDER BY a.receive_time DESC
        """

        try:
            cursor = self.get_db().cursor()
            cursor.execute(select)
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            result = [dict(zip(columns, row)) for row in rows]
            return result
        except Exception as e:
            raise RuntimeError(f"Failed to fetch analytics data: {e}")
        finally:
            cursor.close()

    # COUNTS

    def get_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM alerts
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def get_counts(self, query=None, group=None):
        query = query or Query()
        if group is None:
            raise ValueError('Must define a group')
        select = """
            SELECT {group}, COUNT(*) FROM alerts
             WHERE {where}
            GROUP BY {group}
        """.format(where=query.where, group=group)
        return {s['group']: s.count for s in self._fetchall(select, query.vars)}

    def get_counts_by_severity(self, query=None):
        query = query or Query()
        select = f"""
            SELECT severity, COUNT(*) FROM alerts
             WHERE {query.where}
            GROUP BY severity
        """
        return {s.severity: s.count for s in self._fetchall(select, query.vars)}

    def get_counts_by_status(self, query=None):
        query = query or Query()
        select = f"""
            SELECT status, COUNT(*) FROM alerts
            WHERE {query.where}
            GROUP BY status
        """
        return {s.status: s.count for s in self._fetchall(select, query.vars)}

    def get_topn_count(self, query=None, topn=100):
        query = query or Query()
        group = 'event'
        if query and query.group:
            group = query.group[0]

        select = """
            SELECT {group}, COUNT(1) as count, SUM(duplicate_count) AS duplicate_count,
                   array_agg(DISTINCT environment) AS environments, array_agg(DISTINCT svc) AS services,
                   array_agg(DISTINCT ARRAY[id, resource]) AS resources
              FROM alerts, UNNEST (service) svc
             WHERE {where}
          GROUP BY {group}
          ORDER BY count DESC
        """.format(where=query.where, group=group)
        return [
            {
                'count': t.count,
                'duplicateCount': t.duplicate_count,
                'environments': t.environments,
                'services': t.services,
                group: getattr(t, group),
                'resources': [{'id': r[0], 'resource': r[1], 'href': absolute_url(f'/alert/{r[0]}')} for r in t.resources]
            } for t in self._fetchall(select, query.vars, limit=topn)
        ]

    def get_topn_flapping(self, query=None, topn=100):
        query = query or Query()
        group = 'event'
        if query and query.group:
            group = query.group[0]
        select = """
            WITH topn AS (SELECT * FROM alerts WHERE {where})
            SELECT topn.{group}, COUNT(1) as count, SUM(duplicate_count) AS duplicate_count,
                   array_agg(DISTINCT environment) AS environments, array_agg(DISTINCT svc) AS services,
                   array_agg(DISTINCT ARRAY[topn.id, resource]) AS resources
              FROM topn, UNNEST (service) svc, UNNEST (history) hist
             WHERE hist.type='severity'
          GROUP BY topn.{group}
          ORDER BY count DESC
        """.format(where=query.where, group=group)
        return [
            {
                'count': t.count,
                'duplicateCount': t.duplicate_count,
                'environments': t.environments,
                'services': t.services,
                group: getattr(t, group),
                'resources': [{'id': r[0], 'resource': r[1], 'href': absolute_url(f'/alert/{r[0]}')} for r in t.resources]
            } for t in self._fetchall(select, query.vars, limit=topn)
        ]

    def get_topn_standing(self, query=None, topn=100):
        query = query or Query()
        group = 'event'
        if query and query.group:
            group = query.group[0]
        select = """
            WITH topn AS (SELECT * FROM alerts WHERE {where})
            SELECT topn.{group}, COUNT(1) as count, SUM(duplicate_count) AS duplicate_count,
                   SUM(last_receive_time - create_time) as life_time,
                   array_agg(DISTINCT environment) AS environments, array_agg(DISTINCT svc) AS services,
                   array_agg(DISTINCT ARRAY[topn.id, resource]) AS resources
              FROM topn, UNNEST (service) svc, UNNEST (history) hist
             WHERE hist.type='severity'
          GROUP BY topn.{group}
          ORDER BY life_time DESC
        """.format(where=query.where, group=group)
        return [
            {
                'count': t.count,
                'duplicateCount': t.duplicate_count,
                'environments': t.environments,
                'services': t.services,
                group: getattr(t, group),
                'resources': [{'id': r[0], 'resource': r[1], 'href': absolute_url(f'/alert/{r[0]}')} for r in t.resources]
            } for t in self._fetchall(select, query.vars, limit=topn)
        ]

    # PATTERTNS

    def get_patterns(self):
        query = "SELECT id, name, sql_rule, priority, is_active, create_time, update_time FROM patterns ORDER BY priority"
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            patterns = [
                {
                    "id": row.id,
                    "name": row.name,
                    "sql_rule": row.sql_rule,
                    "priority": row.priority,
                    "is_active": row.is_active,
                    "create_time": row.create_time,
                    "update_time": row.update_time,
                }
                for row in rows
            ]
            return patterns
        except Exception as e:
            LOG.error(f"Error fetching patterns: {e}")
            raise ApiError("Failed to fetch patterns", 500)
        finally:
            cursor.close()
            conn.close()

    def create_pattern(self, name, sql_rule, priority, is_active=True):
        query = """
            INSERT INTO patterns (name, sql_rule, priority, is_active, create_time, update_time)
            VALUES (%s, %s, %s, %s, now(), now())
            RETURNING id
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, (name, sql_rule, priority, is_active))
            conn.commit()
            return cursor.fetchone()[0]
        except UniqueViolation:
            conn.rollback()
            raise ApiError("Pattern with this name already exists", 400)
        except Exception as e:
            conn.rollback()
            LOG.error(f"Error creating pattern: {e}")
            raise ApiError("Failed to create pattern", 500)
        finally:
            cursor.close()
            conn.close()

    def update_pattern(self, pattern_id, name=None, sql_rule=None, priority=None, is_active=None):
        updates = []
        values = []

        if name:
            updates.append("name = %s")
            values.append(name)
        if sql_rule:
            updates.append("sql_rule = %s")
            values.append(sql_rule)
        if priority is not None:
            updates.append("priority = %s")
            values.append(priority)
        if is_active is not None:
            updates.append("is_active = %s")
            values.append(is_active)

        if not updates:
            raise ApiError("No fields to update", 400)

        query = f"""
            UPDATE patterns
            SET {', '.join(updates)}, update_time = now()
            WHERE id = %s
            RETURNING id
        """
        values.append(pattern_id)

        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, tuple(values))
            if cursor.rowcount == 0:
                raise ApiError(f"Pattern with id {pattern_id} not found", 404)
            conn.commit()
            return pattern_id
        except Exception as e:
            conn.rollback()
            LOG.error(f"Error updating pattern: {e}")
            raise ApiError("Failed to update pattern", 500)
        finally:
            cursor.close()
            conn.close()

    def delete_pattern(self, pattern_id):
        """
        Удалить паттерн по ID.
        """
        query = "DELETE FROM patterns WHERE id = %s"
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, (pattern_id,))
            if cursor.rowcount == 0:
                raise ApiError(f"Pattern with id {pattern_id} not found", 404)
            conn.commit()
        except Exception as e:
            conn.rollback()
            LOG.error(f"Error deleting pattern: {e}")
            raise ApiError("Failed to delete pattern", 500)
        finally:
            cursor.close()
            conn.close()

    # PATTERN HISTORY

    def add_pattern_history(self, pattern_name: str, pattern_id: str, incident_id: str, alert_id: str) -> None:
        insert = """
            INSERT INTO pattern_history (pattern_name, pattern_id, incident_id, alert_id)
            VALUES (%s, %s, %s, %s)
        """
        vars = (pattern_name, pattern_id, incident_id, alert_id)

        try:
            cursor = self.get_db().cursor()
            cursor.execute(insert, vars)
            self.get_db().commit()
        except Exception as e:
            self.get_db().rollback()
            raise RuntimeError(f"Failed to insert into pattern_history: {e}")

    def get_pattern_history(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        select = """
            SELECT
                id, 
                pattern_name,
                pattern_id,
                incident_id,
                alert_id,
                create_time,
                COUNT(pattern_id) OVER (PARTITION BY pattern_id) AS count
            FROM pattern_history
            ORDER BY create_time DESC
            LIMIT %s OFFSET %s
        """
        vars = (limit, offset)

        try:
            cursor = self.get_db().cursor()
            cursor.execute(select, vars)
            rows = cursor.fetchall()
            return [
                {
                    "id": row.id,
                    "pattern_name": row.pattern_name,
                    "pattern_id": row.pattern_id,
                    "incident_id": row.incident_id,
                    "alert_id": row.alert_id,
                    "create_time": row.create_time,
                    "count": row.count
                }
                for row in rows
            ]
        except Exception as e:
            raise RuntimeError(f"Failed to fetch pattern history: {e}")

    # ALERTS MOVE (MERGE) HISTORY

    def add_move_history(self, user_name: str, attributes_dict: Dict[str, Dict]) -> None:
        insert = """
            INSERT INTO alert_move_history (incident_id, attributes_updated, user_name)
            VALUES (%s, %s, %s)
        """

        try:
            cursor = self.get_db().cursor()

            for incident_id, attributes in attributes_dict.items():
                vars = (incident_id, json.dumps(attributes), user_name)
                cursor.execute(insert, vars)

            self.get_db().commit()
        except Exception as e:
            self.get_db().rollback()
            raise RuntimeError(f"Failed to insert into alert_move_history: {e}")

    def get_move_history(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        select = """
            SELECT
                id,
                incident_id,
                attributes_updated,
                user_name,
                create_time
            FROM alert_move_history
            ORDER BY create_time DESC
            LIMIT %s OFFSET %s
        """
        vars = (limit, offset)

        try:
            cursor = self.get_db().cursor()
            cursor.execute(select, vars)
            rows = cursor.fetchall()
            return [
                {
                    "id": row.id,
                    "incident_id": row.incident_id,
                    "attributes_updated": row.attributes_updated,
                    "user_name": row.user_name,
                    "create_time": row.create_time,
                }
                for row in rows
            ]
        except Exception as e:
            raise RuntimeError(f"Failed to fetch move history: {e}")

    # ENVIRONMENTS

    def get_environments(self, query=None, topn=1000):
        query = query or Query()
        select = f"""
            SELECT environment, severity, status, count(1) FROM alerts
            WHERE {query.where}
            GROUP BY environment, CUBE(severity, status)
        """
        result = self._fetchall(select, query.vars, limit=topn)

        severity_count = defaultdict(list)
        status_count = defaultdict(list)
        total_count = defaultdict(int)

        for row in result:
            if row.severity and not row.status:
                severity_count[row.environment].append((row.severity, row.count))
            if not row.severity and row.status:
                status_count[row.environment].append((row.status, row.count))
            if not row.severity and not row.status:
                total_count[row.environment] = row.count

        select = """SELECT DISTINCT environment FROM alerts"""
        environments = self._fetchall(select, {})
        return [
            {
                'environment': e.environment,
                'severityCounts': dict(severity_count[e.environment]),
                'statusCounts': dict(status_count[e.environment]),
                'count': total_count[e.environment]
            } for e in environments]

    # SERVICES

    def get_services(self, query=None, topn=1000):
        query = query or Query()
        select = """
            SELECT environment, svc, severity, status, count(1) FROM alerts, UNNEST(service) svc
            WHERE {where}
            GROUP BY environment, svc, CUBE(severity, status)
        """.format(where=query.where)
        result = self._fetchall(select, query.vars, limit=topn)

        severity_count = defaultdict(list)
        status_count = defaultdict(list)
        total_count = defaultdict(int)

        for row in result:
            if row.severity and not row.status:
                severity_count[(row.environment, row.svc)].append((row.severity, row.count))
            if not row.severity and row.status:
                status_count[(row.environment, row.svc)].append((row.status, row.count))
            if not row.severity and not row.status:
                total_count[(row.environment, row.svc)] = row.count

        select = """SELECT DISTINCT environment, svc FROM alerts, UNNEST(service) svc"""
        services = self._fetchall(select, {})
        return [
            {
                'environment': s.environment,
                'service': s.svc,
                'severityCounts': dict(severity_count[(s.environment, s.svc)]),
                'statusCounts': dict(status_count[(s.environment, s.svc)]),
                'count': total_count[(s.environment, s.svc)]
            } for s in services]

    # ALERT GROUPS

    def get_alert_groups(self, query=None, topn=1000):
        query = query or Query()
        select = f"""
            SELECT environment, "group", count(1) FROM alerts
            WHERE {query.where}
            GROUP BY environment, "group"
        """
        return [
            {
                'environment': g.environment,
                'group': g.group,
                'count': g.count
            } for g in self._fetchall(select, query.vars, limit=topn)]

    # ALERT TAGS

    def get_alert_tags(self, query=None, topn=1000):
        query = query or Query()
        select = """
            SELECT environment, tag, count(1) FROM alerts, UNNEST(tags) tag
            WHERE {where}
            GROUP BY environment, tag
        """.format(where=query.where)
        return [{'environment': t.environment, 'tag': t.tag, 'count': t.count} for t in self._fetchall(select, query.vars, limit=topn)]

    # BLACKOUTS

    def create_blackout(self, blackout):
        insert = """
            INSERT INTO blackouts (id, priority, environment, service, resource, event,
                "group", tags, origin, customer, start_time, end_time,
                duration, "user", create_time, text)
            VALUES (%(id)s, %(priority)s, %(environment)s, %(service)s, %(resource)s, %(event)s,
                %(group)s, %(tags)s, %(origin)s, %(customer)s, %(start_time)s, %(end_time)s,
                %(duration)s, %(user)s, %(create_time)s, %(text)s)
            RETURNING *, duration AS remaining
        """
        return self._insert(insert, vars(blackout))

    def get_blackout(self, id, customers=None):
        select = """
            SELECT *, GREATEST(EXTRACT(EPOCH FROM (end_time - GREATEST(start_time, NOW() at time zone 'utc'))), 0) AS remaining
            FROM blackouts
            WHERE id=%(id)s
              AND {customer}
        """.format(customer='customer=ANY(%(customers)s)' if customers else '1=1')
        return self._fetchone(select, {'id': id, 'customers': customers})

    def get_blackouts(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = """
            SELECT *, GREATEST(EXTRACT(EPOCH FROM (end_time - GREATEST(start_time, NOW() at time zone 'utc'))), 0) AS remaining
              FROM blackouts
             WHERE {where}
          ORDER BY {order}
        """.format(where=query.where, order=query.sort)
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_blackouts_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM blackouts
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def is_blackout_period(self, alert):
        select = """
            SELECT *
            FROM blackouts
            WHERE start_time <= %(create_time)s AND end_time > %(create_time)s
              AND environment=%(environment)s
              AND (
                 ( resource IS NULL AND service='{}' AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource IS NULL AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service='{}' AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event IS NULL AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group" IS NULL AND tags <@ %(tags)s AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags='{}' AND origin=%(origin)s )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin IS NULL )
              OR ( resource=%(resource)s AND service <@ %(service)s AND event=%(event)s AND "group"=%(group)s AND tags <@ %(tags)s AND origin=%(origin)s )
                 )
        """
        if current_app.config['CUSTOMER_VIEWS']:
            select += ' AND (customer IS NULL OR customer=%(customer)s)'
        if self._fetchone(select, vars(alert)):
            return True
        return False

    def update_blackout(self, id, **kwargs):
        update = """
            UPDATE blackouts
            SET
        """
        if kwargs.get('environment') is not None:
            update += 'environment=%(environment)s, '
        if 'service' in kwargs:
            update += 'service=%(service)s, '
        if 'resource' in kwargs:
            update += 'resource=%(resource)s, '
        if 'event' in kwargs:
            update += 'event=%(event)s, '
        if 'group' in kwargs:
            update += '"group"=%(group)s, '
        if 'tags' in kwargs:
            update += 'tags=%(tags)s, '
        if 'origin' in kwargs:
            update += 'origin=%(origin)s, '
        if 'customer' in kwargs:
            update += 'customer=%(customer)s, '
        if kwargs.get('startTime') is not None:
            update += 'start_time=%(startTime)s, '
        if kwargs.get('endTime') is not None:
            update += 'end_time=%(endTime)s, '
        if 'duration' in kwargs:
            update += 'duration=%(duration)s, '
        if 'text' in kwargs:
            update += 'text=%(text)s, '
        update += """
            "user"=COALESCE(%(user)s, "user")
            WHERE id=%(id)s
            RETURNING *, GREATEST(EXTRACT(EPOCH FROM (end_time - GREATEST(start_time, NOW() at time zone 'utc'))), 0) AS remaining
        """
        kwargs['id'] = id
        kwargs['user'] = kwargs.get('user')
        return self._updateone(update, kwargs, returning=True)

    def delete_blackout(self, id):
        delete = """
            DELETE FROM blackouts
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    # HEARTBEATS

    def upsert_heartbeat(self, heartbeat):
        upsert = """
            INSERT INTO heartbeats (id, origin, tags, attributes, type, create_time, timeout, receive_time, customer)
            VALUES (%(id)s, %(origin)s, %(tags)s, %(attributes)s, %(event_type)s, %(create_time)s, %(timeout)s, %(receive_time)s, %(customer)s)
            ON CONFLICT (origin, COALESCE(customer, '')) DO UPDATE
                SET tags=%(tags)s, attributes=%(attributes)s, create_time=%(create_time)s, timeout=%(timeout)s, receive_time=%(receive_time)s
            RETURNING *,
                   EXTRACT(EPOCH FROM (receive_time - create_time)) AS latency,
                   EXTRACT(EPOCH FROM (NOW() - receive_time)) AS since
        """
        return self._upsert(upsert, vars(heartbeat))

    def get_heartbeat(self, id, customers=None):
        select = """
            SELECT *,
                   EXTRACT(EPOCH FROM (receive_time - create_time)) AS latency,
                   EXTRACT(EPOCH FROM (NOW() - receive_time)) AS since
              FROM heartbeats
             WHERE (id=%(id)s OR id LIKE %(like_id)s)
               AND {customer}
        """.format(customer='customer=%(customers)s' if customers else '1=1')
        return self._fetchone(select, {'id': id, 'like_id': id + '%', 'customers': customers})

    def get_heartbeats(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = """
            SELECT *,
                   EXTRACT(EPOCH FROM (receive_time - create_time)) AS latency,
                   EXTRACT(EPOCH FROM (NOW() - receive_time)) AS since
              FROM heartbeats
             WHERE {where}
          ORDER BY {order}
        """.format(where=query.where, order=query.sort)
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_heartbeats_by_status(self, status=None, query=None, page=None, page_size=None):
        status = status or list()
        query = query or Query()

        swhere = ''
        if status:
            q = list()
            if HeartbeatStatus.OK in status:
                q.append(
                    """
                    (EXTRACT(EPOCH FROM (NOW() at time zone 'utc' - receive_time)) <= timeout
                    AND EXTRACT(EPOCH FROM (receive_time - create_time)) * 1000 <= {max_latency})
                    """.format(max_latency=current_app.config['HEARTBEAT_MAX_LATENCY']))
            if HeartbeatStatus.Expired in status:
                q.append("(EXTRACT(EPOCH FROM (NOW() at time zone 'utc' - receive_time)) > timeout)")
            if HeartbeatStatus.Slow in status:
                q.append(
                    """
                    (EXTRACT(EPOCH FROM (NOW() at time zone 'utc' - receive_time)) <= timeout
                    AND EXTRACT(EPOCH FROM (receive_time - create_time)) * 1000 > {max_latency})
                    """.format(max_latency=current_app.config['HEARTBEAT_MAX_LATENCY']))
            if q:
                swhere = 'AND (' + ' OR '.join(q) + ')'

        select = """
            SELECT *,
                   EXTRACT(EPOCH FROM (receive_time - create_time)) AS latency,
                   EXTRACT(EPOCH FROM (NOW() - receive_time)) AS since
              FROM heartbeats
             WHERE {where}
             {swhere}
          ORDER BY {order}
        """.format(where=query.where, swhere=swhere, order=query.sort)
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_heartbeats_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM heartbeats
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def delete_heartbeat(self, id):
        delete = """
            DELETE FROM heartbeats
            WHERE id=%(id)s OR id LIKE %(like_id)s
            RETURNING id
        """
        return self._deleteone(delete, {'id': id, 'like_id': id + '%'}, returning=True)

    # API KEYS

    def create_key(self, key):
        insert = """
            INSERT INTO keys (id, key, "user", scopes, text, expire_time, "count", last_used_time, customer)
            VALUES (%(id)s, %(key)s, %(user)s, %(scopes)s, %(text)s, %(expire_time)s, %(count)s, %(last_used_time)s, %(customer)s)
            RETURNING *
        """
        return self._insert(insert, vars(key))

    def get_key(self, key, user=None):
        select = f"""
            SELECT * FROM keys
             WHERE (id=%(key)s OR key=%(key)s)
               AND {'"user"=%(user)s' if user else '1=1'}
        """
        return self._fetchone(select, {'key': key, 'user': user})

    def get_keys(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = f"""
            SELECT * FROM keys
             WHERE {query.where}
          ORDER BY {query.sort}
        """
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_keys_by_user(self, user):
        select = """
            SELECT * FROM keys
             WHERE "user"=%s
        """
        return self._fetchall(select, (user,))

    def get_keys_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM keys
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def update_key(self, key, **kwargs):
        update = """
            UPDATE keys
            SET
        """
        if 'user' in kwargs:
            update += '"user"=%(user)s, '
        if 'scopes' in kwargs:
            update += 'scopes=%(scopes)s, '
        if 'text' in kwargs:
            update += 'text=%(text)s, '
        if 'expireTime' in kwargs:
            update += 'expire_time=%(expireTime)s, '
        if 'customer' in kwargs:
            update += 'customer=%(customer)s, '
        update += """
            id=id
            WHERE (id=%(key)s OR key=%(key)s)
            RETURNING *
        """
        kwargs['key'] = key
        return self._updateone(update, kwargs, returning=True)

    def update_key_last_used(self, key):
        update = """
            UPDATE keys
            SET last_used_time=NOW() at time zone 'utc', count=count + 1
            WHERE id=%s OR key=%s
        """
        return self._updateone(update, (key, key))

    def delete_key(self, key):
        delete = """
            DELETE FROM keys
            WHERE id=%s OR key=%s
            RETURNING key
        """
        return self._deleteone(delete, (key, key), returning=True)

    # USERS

    def create_user(self, user):
        insert = """
            INSERT INTO users (id, name, login, password, email, status, roles, attributes,
                create_time, last_login, text, update_time, email_verified)
            VALUES (%(id)s, %(name)s, %(login)s, %(password)s, %(email)s, %(status)s, %(roles)s, %(attributes)s, %(create_time)s,
                %(last_login)s, %(text)s, %(update_time)s, %(email_verified)s)
            RETURNING *
        """
        return self._insert(insert, vars(user))

    def get_user(self, id):
        select = """SELECT * FROM users WHERE id=%s"""
        return self._fetchone(select, (id,))

    def get_users(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = f"""
            SELECT * FROM users
             WHERE {query.where}
          ORDER BY {query.sort}
        """
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_users_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM users
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def get_user_by_username(self, username):
        select = """SELECT * FROM users WHERE login=%s OR email=%s"""
        return self._fetchone(select, (username, username))

    def get_user_by_email(self, email):
        select = """SELECT * FROM users WHERE email=%s"""
        return self._fetchone(select, (email,))

    def get_user_by_hash(self, hash):
        select = """SELECT * FROM users WHERE hash=%s"""
        return self._fetchone(select, (hash,))

    def update_last_login(self, id):
        update = """
            UPDATE users
            SET last_login=NOW() at time zone 'utc'
            WHERE id=%s
        """
        return self._updateone(update, (id,))

    def update_user(self, id, **kwargs):
        update = """
            UPDATE users
            SET
        """
        if kwargs.get('name', None) is not None:
            update += 'name=%(name)s, '
        if kwargs.get('login', None) is not None:
            update += 'login=%(login)s, '
        if kwargs.get('password', None) is not None:
            update += 'password=%(password)s, '
        if kwargs.get('email', None) is not None:
            update += 'email=%(email)s, '
        if kwargs.get('status', None) is not None:
            update += 'status=%(status)s, '
        if kwargs.get('roles', None) is not None:
            update += 'roles=%(roles)s, '
        if kwargs.get('attributes', None) is not None:
            update += 'attributes=attributes || %(attributes)s, '
        if kwargs.get('text', None) is not None:
            update += 'text=%(text)s, '
        if kwargs.get('email_verified', None) is not None:
            update += 'email_verified=%(email_verified)s, '
        update += """
            update_time=NOW() at time zone 'utc'
            WHERE id=%(id)s
            RETURNING *
        """
        kwargs['id'] = id
        return self._updateone(update, kwargs, returning=True)

    def update_user_attributes(self, id, old_attrs, new_attrs):
        from alerta.utils.collections import merge
        merge(old_attrs, new_attrs)
        attrs = {k: v for k, v in old_attrs.items() if v is not None}
        update = """
            UPDATE users
               SET attributes=%(attrs)s, update_time=NOW() at time zone 'utc'
             WHERE id=%(id)s
            RETURNING id
        """
        return bool(self._updateone(update, {'id': id, 'attrs': attrs}, returning=True))

    def delete_user(self, id):
        delete = """
            DELETE FROM users
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    def set_email_hash(self, id, hash):
        update = """
            UPDATE users
            SET hash=%s, update_time=NOW() at time zone 'utc'
            WHERE id=%s
        """
        return self._updateone(update, (hash, id))

    # GROUPS

    def create_group(self, group):
        insert = """
            INSERT INTO groups (id, name, text)
            VALUES (%(id)s, %(name)s, %(text)s)
            RETURNING *, 0 AS count
        """
        return self._insert(insert, vars(group))

    def get_group(self, id):
        select = """SELECT *, COALESCE(CARDINALITY(users), 0) AS count FROM groups WHERE id=%s"""
        return self._fetchone(select, (id,))

    def get_groups(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = """
            SELECT *, COALESCE(CARDINALITY(users), 0) AS count FROM groups
             WHERE {where}
          ORDER BY {order}
        """.format(where=query.where, order=query.sort)
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_groups_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM groups
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def get_group_users(self, id):
        select = """
            SELECT u.id, u.login, u.email, u.name, u.status
              FROM (SELECT id, UNNEST(users) as uid FROM groups) g
            INNER JOIN users u on g.uid = u.id
            WHERE g.id = %s
        """
        return self._fetchall(select, (id,))

    def update_group(self, id, **kwargs):
        update = """
            UPDATE groups
            SET
        """
        if kwargs.get('name', None) is not None:
            update += 'name=%(name)s, '
        if kwargs.get('text', None) is not None:
            update += 'text=%(text)s, '
        update += """
            update_time=NOW() at time zone 'utc'
            WHERE id=%(id)s
            RETURNING *, COALESCE(CARDINALITY(users), 0) AS count
        """
        kwargs['id'] = id
        return self._updateone(update, kwargs, returning=True)

    def add_user_to_group(self, group, user):
        update = """
            UPDATE groups
            SET users=ARRAY(SELECT DISTINCT UNNEST(users || %(users)s))
            WHERE id=%(id)s
            RETURNING *
        """
        return self._updateone(update, {'id': group, 'users': [user]}, returning=True)

    def remove_user_from_group(self, group, user):
        update = """
            UPDATE groups
            SET users=(select array_agg(u) FROM unnest(users) AS u WHERE NOT u=%(user)s )
            WHERE id=%(id)s
            RETURNING *
        """
        return self._updateone(update, {'id': group, 'user': user}, returning=True)

    def delete_group(self, id):
        delete = """
            DELETE FROM groups
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    def get_groups_by_user(self, user):
        select = """
            SELECT *, COALESCE(CARDINALITY(users), 0) AS count
              FROM groups
            WHERE %s=ANY(users)
        """
        return self._fetchall(select, (user,))

    # PERMISSIONS

    def create_perm(self, perm):
        insert = """
            INSERT INTO perms (id, match, scopes)
            VALUES (%(id)s, %(match)s, %(scopes)s)
            RETURNING *
        """
        return self._insert(insert, vars(perm))

    def get_perm(self, id):
        select = """SELECT * FROM perms WHERE id=%s"""
        return self._fetchone(select, (id,))

    def get_perms(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = f"""
            SELECT * FROM perms
             WHERE {query.where}
          ORDER BY {query.sort}
        """
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_perms_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM perms
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def update_perm(self, id, **kwargs):
        update = """
            UPDATE perms
            SET
        """
        if 'match' in kwargs:
            update += 'match=%(match)s, '
        if 'scopes' in kwargs:
            update += 'scopes=%(scopes)s, '
        update += """
            id=%(id)s
            WHERE id=%(id)s
            RETURNING *
        """
        kwargs['id'] = id
        return self._updateone(update, kwargs, returning=True)

    def delete_perm(self, id):
        delete = """
            DELETE FROM perms
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    def get_scopes_by_match(self, login, matches):
        if login in current_app.config['ADMIN_USERS']:
            return ADMIN_SCOPES

        scopes = list()
        for match in matches:
            if match in current_app.config['ADMIN_ROLES']:
                return ADMIN_SCOPES
            if match in current_app.config['USER_ROLES']:
                scopes.extend(current_app.config['USER_DEFAULT_SCOPES'])
            if match in current_app.config['GUEST_ROLES']:
                scopes.extend(current_app.config['GUEST_DEFAULT_SCOPES'])
            select = """SELECT scopes FROM perms WHERE match=%s"""
            response = self._fetchone(select, (match,))
            if response:
                scopes.extend(response.scopes)
        return sorted(set(scopes))

    # CUSTOMERS

    def create_customer(self, customer):
        insert = """
            INSERT INTO customers (id, match, customer)
            VALUES (%(id)s, %(match)s, %(customer)s)
            RETURNING *
        """
        return self._insert(insert, vars(customer))

    def get_customer(self, id):
        select = """SELECT * FROM customers WHERE id=%s"""
        return self._fetchone(select, (id,))

    def get_customers(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = f"""
            SELECT * FROM customers
             WHERE {query.where}
          ORDER BY {query.sort}
        """
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_customers_count(self, query=None):
        query = query or Query()
        select = f"""
            SELECT COUNT(1) FROM customers
             WHERE {query.where}
        """
        return self._fetchone(select, query.vars).count

    def update_customer(self, id, **kwargs):
        update = """
            UPDATE customers
            SET
        """
        if 'match' in kwargs:
            update += 'match=%(match)s, '
        if 'customer' in kwargs:
            update += 'customer=%(customer)s, '
        update += """
            id=%(id)s
            WHERE id=%(id)s
            RETURNING *
        """
        kwargs['id'] = id
        return self._updateone(update, kwargs, returning=True)

    def delete_customer(self, id):
        delete = """
            DELETE FROM customers
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    def get_customers_by_match(self, login, matches):
        if login in current_app.config['ADMIN_USERS']:
            return '*'  # all customers

        customers = []
        for match in [login] + matches:
            select = """SELECT customer FROM customers WHERE match=%s"""
            response = self._fetchall(select, (match,))
            if response:
                customers.extend([r.customer for r in response])

        if customers:
            if '*' in customers:
                return '*'  # all customers
            return customers

        raise NoCustomerMatch(f"No customer lookup configured for user '{login}' or '{','.join(matches)}'")

    # NOTES

    def create_note(self, note):
        insert = """
            INSERT INTO notes (id, text, "user", attributes, type,
                create_time, update_time, alert, customer)
            VALUES (%(id)s, %(text)s, %(user)s, %(attributes)s, %(note_type)s,
                %(create_time)s, %(update_time)s, %(alert)s, %(customer)s)
            RETURNING *
        """
        return self._insert(insert, vars(note))

    def get_note(self, id):
        select = """
            SELECT * FROM notes
            WHERE id=%s
        """
        return self._fetchone(select, (id,))

    def get_notes(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = f"""
            SELECT * FROM notes
             WHERE {query.where}
          ORDER BY {query.sort or 'create_time'}
        """
        return self._fetchall(select, query.vars, limit=page_size, offset=(page - 1) * page_size)

    def get_alert_notes(self, id, page=None, page_size=None):
        select = """
            SELECT * FROM notes
             WHERE alert ~* (%s)
        """
        return self._fetchall(select, (id,), limit=page_size, offset=(page - 1) * page_size)

    def get_customer_notes(self, customer, page=None, page_size=None):
        select = """
            SELECT * FROM notes
             WHERE customer=%s
        """
        return self._fetchall(select, (customer,), limit=page_size, offset=(page - 1) * page_size)

    def update_note(self, id, **kwargs):
        update = """
            UPDATE notes
            SET
        """
        if kwargs.get('text', None) is not None:
            update += 'text=%(text)s, '
        if kwargs.get('attributes', None) is not None:
            update += 'attributes=attributes || %(attributes)s, '
        update += """
            "user"=COALESCE(%(user)s, "user"),
            update_time=NOW() at time zone 'utc'
            WHERE id=%(id)s
            RETURNING *
        """
        kwargs['id'] = id
        kwargs['user'] = kwargs.get('user')
        return self._updateone(update, kwargs, returning=True)

    def delete_note(self, id):
        delete = """
            DELETE FROM notes
            WHERE id=%s
            RETURNING id
        """
        return self._deleteone(delete, (id,), returning=True)

    # METRICS

    def get_metrics(self, type=None):
        select = """SELECT * FROM metrics"""
        if type:
            select += ' WHERE type=%s'
        return self._fetchall(select, (type,))

    def set_gauge(self, gauge):
        upsert = """
            INSERT INTO metrics ("group", name, title, description, value, type)
            VALUES (%(group)s, %(name)s, %(title)s, %(description)s, %(value)s, %(type)s)
            ON CONFLICT ("group", name, type) DO UPDATE
                SET value=%(value)s
            RETURNING *
        """
        return self._upsert(upsert, vars(gauge))

    def inc_counter(self, counter):
        upsert = """
            INSERT INTO metrics ("group", name, title, description, count, type)
            VALUES (%(group)s, %(name)s, %(title)s, %(description)s, %(count)s, %(type)s)
            ON CONFLICT ("group", name, type) DO UPDATE
                SET count=metrics.count + %(count)s
            RETURNING *
        """
        return self._upsert(upsert, vars(counter))

    def update_timer(self, timer):
        upsert = """
            INSERT INTO metrics ("group", name, title, description, count, total_time, type)
            VALUES (%(group)s, %(name)s, %(title)s, %(description)s, %(count)s, %(total_time)s, %(type)s)
            ON CONFLICT ("group", name, type) DO UPDATE
                SET count=metrics.count + %(count)s, total_time=metrics.total_time + %(total_time)s
            RETURNING *
        """
        return self._upsert(upsert, vars(timer))

    # HOUSEKEEPING

    def get_expired(self, expired_threshold, info_threshold):
        # delete 'closed' or 'expired' alerts older than "expired_threshold" seconds
        # and 'informational' alerts older than "info_threshold" seconds

        if expired_threshold:
            delete = """
                DELETE FROM alerts
                 WHERE (status IN ('closed', 'expired')
                        AND last_receive_time < (NOW() at time zone 'utc' - INTERVAL '%(expired_threshold)s seconds'))
            """
            self._deleteall(delete, {'expired_threshold': expired_threshold})

        if info_threshold:
            delete = """
                DELETE FROM alerts
                 WHERE (severity=%(inform_severity)s
                        AND last_receive_time < (NOW() at time zone 'utc' - INTERVAL '%(info_threshold)s seconds'))
            """
            self._deleteall(delete, {'inform_severity': alarm_model.DEFAULT_INFORM_SEVERITY, 'info_threshold': info_threshold})

        # get list of alerts to be newly expired
        select = """
            SELECT *
              FROM alerts
             WHERE status NOT IN ('expired') AND COALESCE(timeout, {timeout})!=0
               AND (last_receive_time + INTERVAL '1 second' * timeout) < NOW() at time zone 'utc'
        """.format(timeout=current_app.config['ALERT_TIMEOUT'])

        return self._fetchall(select, {})

    def get_unshelve(self):
        # get list of alerts to be unshelved
        select = """
            SELECT DISTINCT ON (a.id) a.*
              FROM alerts a, UNNEST(history) h
             WHERE a.status='shelved'
               AND h.type='shelve'
               AND h.status='shelved'
               AND COALESCE(h.timeout, {timeout})!=0
               AND (a.update_time + INTERVAL '1 second' * h.timeout) < NOW() at time zone 'utc'
          ORDER BY a.id, a.update_time DESC
        """.format(timeout=current_app.config['SHELVE_TIMEOUT'])
        return self._fetchall(select, {})

    def get_unack(self):
        # get list of alerts to be unack'ed
        select = """
            SELECT DISTINCT ON (a.id) a.*
              FROM alerts a, UNNEST(history) h
             WHERE a.status='ack'
               AND h.type='ack'
               AND h.status='ack'
               AND COALESCE(h.timeout, {timeout})!=0
               AND (a.update_time + INTERVAL '1 second' * h.timeout) < NOW() at time zone 'utc'
          ORDER BY a.id, a.update_time DESC
        """.format(timeout=current_app.config['ACK_TIMEOUT'])
        return self._fetchall(select, {})

    # SQL HELPERS

    def _insert(self, query, vars):
        """
        Insert, with return.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        self.get_db().commit()
        return cursor.fetchone()

    def _fetchone(self, query, vars):
        """
        Return none or one row.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        return cursor.fetchone()

    def _fetchall(self, query, vars=None, limit=None, offset=None):
        """
        Выполняет SELECT запрос и возвращает все результаты.
        
        :param query: SQL запрос
        :param vars: Параметры для запроса
        :param limit: Ограничение количества результатов
        :param offset: Смещение результатов
        :return: Список результатов
        """
        connection = self.get_db()
        cursor = connection.cursor()
        
        # Проверка, содержит ли запрос уже LIMIT или OFFSET
        has_limit = re.search(r'\bLIMIT\b', query, re.IGNORECASE)
        has_offset = re.search(r'\bOFFSET\b', query, re.IGNORECASE)
        
        # Если запрос уже содержит LIMIT или OFFSET, используем его как есть
        if has_limit or has_offset:
            modified_query = query
        else:
            # Иначе добавляем LIMIT и OFFSET к запросу, если они предоставлены
            modified_query = query
            if limit is not None:
                modified_query += f" LIMIT {limit}"
            if offset is not None:
                modified_query += f" OFFSET {offset}"
        
        try:
            # Добавляем отладочное логирование
            logging.debug(f"Executing SQL: {modified_query}")
            logging.debug(f"With parameters: {vars}")
            
            cursor.execute(modified_query, vars)
            return cursor.fetchall()
        except Exception as e:
            logging.error(f"SQL Error: {str(e)}")
            logging.error(f"Query: {modified_query}")
            logging.error(f"Parameters: {vars}")
            self.get_db().rollback()
            raise e

    def _updateone(self, query, vars, returning=False):
        """
        Update, with optional return.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        self.get_db().commit()
        return cursor.fetchone() if returning else None

    def _updateall(self, query, vars, returning=False):
        """
        Update, with optional return.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        self.get_db().commit()
        return cursor.fetchall() if returning else None

    def _upsert(self, query, vars):
        """
        Insert or update, with return.
        """
        return self._insert(query, vars)

    def _deleteone(self, query, vars, returning=False):
        """
        Delete, with optional return.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        self.get_db().commit()
        return cursor.fetchone() if returning else None

    def _deleteall(self, query, vars, returning=False):
        """
        Delete multiple rows, with optional return.
        """
        cursor = self.get_db().cursor()
        self._log(cursor, query, vars)
        cursor.execute(query, vars)
        self.get_db().commit()
        return cursor.fetchall() if returning else None

    def _log(self, cursor, query, vars):
        current_app.logger.debug('{stars}\n{query}\n{stars}'.format(
            stars='*' * 40, query=cursor.mogrify(query, vars).decode('utf-8')))

    # ISSUES

    def create_issue(self, issue):
        from datetime import datetime
        from alerta.utils.format import DateTime
        
        # Создаем копию словаря атрибутов issue
        issue_dict = {}
        
        # Сериализуем все datetime объекты в строки
        for key, value in vars(issue).items():
            if isinstance(value, datetime):
                issue_dict[key] = DateTime.iso8601(value)
            else:
                issue_dict[key] = value
        
        # issue_history не нуждается в преобразовании, так как HistoryAdapter
        # уже зарегистрирован и будет вызван автоматически
        
        insert = """
            INSERT INTO issues (id, summary, severity, host_critical, duty_admin, description, status, 
                status_duration, create_time, last_alert_time, resolve_time, pattern_id, inc_key, slack_link, 
                disaster_link, escalation_group, alerts, hosts, project_groups, info_systems, attributes, 
                master_incident, issue_history)
            VALUES (%(id)s, %(summary)s, %(severity)s, %(host_critical)s, %(duty_admin)s, %(description)s, 
                %(status)s, %(status_duration)s, %(create_time)s, %(last_alert_time)s, %(resolve_time)s, 
                %(pattern_id)s, %(inc_key)s, %(slack_link)s, %(disaster_link)s, %(escalation_group)s, 
                %(alerts)s, %(hosts)s, %(project_groups)s, %(info_systems)s, %(attributes)s, 
                %(master_incident)s, %(issue_history)s::history[])
            RETURNING *
        """
        
        # Используем словарь с преобразованными значениями вместо vars(issue)
        return self._insert(insert, issue_dict)

    def get_issue(self, issue_id, customers=None):
        select = """
            SELECT * FROM issues
            WHERE id = %s
        """
        return self._fetchone(select, (issue_id,))

    def get_issues(self, query=None, page=None, page_size=None):
        query = query or Query()
        select = """
            SELECT * FROM issues
            WHERE {where}
            ORDER BY {sort}
        """.format(
            where=query.where or 'true',
            sort=query.sort or 'create_time DESC'
        )
            
        return self._fetchall(select, query.vars, limit=page_size*5000, offset=0)

    def update_issue(self, issue_id, update, update_time=None, history=None):
        update_time = update_time or datetime.utcnow()
        if isinstance(update_time, datetime):
            update_time = DateTime.iso8601(update_time)
        
        # Подготавливаем значения для обновления
        update_value = dict()
        for k, v in update.items():
            if k in ['alerts', 'hosts', 'project_groups', 'info_systems']:
                # Убедимся, что эти поля всегда списки
                if isinstance(v, list):
                    update_value[k] = v
                else:
                    logging.error(f"Поле {k} должно быть списком, но получено {type(v)}")
                    # Преобразуем в список если это возможно
                    if hasattr(v, '__iter__') and not isinstance(v, (str, dict)):
                        update_value[k] = list(v)
                    else:
                        # Создаем пустой список, чтобы избежать ошибки
                        update_value[k] = []
            elif k == 'attributes' and isinstance(v, dict):
                update_value[k] = v
            elif isinstance(v, datetime):
                # Преобразуем datetime в строку
                update_value[k] = DateTime.iso8601(v)
            else:
                update_value[k] = v
        
        if history:
            # Преобразуем объект history
            history_dict = vars(history)
            update_value['history'] = history_dict
            
        # Формируем части SET запроса и параметры безопасно
        set_parts = []
        sql_params = []
        
        for k, v in update.items():
            if k == 'issue_history' and history:
                set_parts.append(f"{k}=array_append({k}, %s::history)")
                sql_params.append(history_dict)
            else:
                set_parts.append(f"{k}=%s")
                sql_params.append(update_value.get(k, v))
        
        # Добавляем параметр ID в конец списка
        sql_params.append(issue_id)
        
        # Формируем SQL запрос с безопасным подходом к параметрам
        update_query = """
            UPDATE issues
            SET {}
            WHERE id = %s
            RETURNING *
        """.format(", ".join(set_parts))
        
        logging.debug(f"Выполняется запрос обновления для Issue {issue_id}: {update_query}")
        logging.debug(f"Параметры: {sql_params}")
        
        return self._updateone(update_query, tuple(sql_params), returning=True)

    def delete_issue(self, issue_id):
        delete = """
            DELETE FROM issues
            WHERE id = %s
            RETURNING id
        """
        return bool(self._deleteone(delete, (issue_id,), returning=True))

    def update_issueid_for_alert(self, alert_id, issue_id):
        update = """
            UPDATE alerts
            SET issue_id = %s
            WHERE id = %s RETURNING *
        """
        
        logging.info(f"Обновление issue_id алерта {alert_id} на {issue_id}")
        return self._updateone(update, (issue_id, alert_id), returning=True)

    def update_issueid_for_alerts(self, alert_ids: List[str], new_issue_id: str = None) -> List[dict]:
        """
        Массовое обновление issue_id для списка алертов.
        
        :param alert_ids: Список ID алертов, которые нужно обновить
        :param new_issue_id: Новый ID задачи (None для отлинковки)
        :return: Список обновленных алертов
        """
        if not alert_ids:
            logging.warn('No alerts to update with new issue_id')
            return []
            
        # Используем list(set()) для обеспечения уникальности ID алертов
        alert_ids = list(set(alert_ids))
            
        # Преобразуем None в NULL для SQL запроса
        if new_issue_id:
            query = """
            UPDATE alerts SET issue_id = %s
            WHERE id = ANY(%s)
            RETURNING *
            """
            action = 'link'
            
            # Используем стандартный метод _updateall
            try:
                results = self._updateall(query, (new_issue_id, alert_ids), returning=True)
                if not results:
                    logging.warn(f'No alerts with ids {alert_ids} to link to issue {new_issue_id}')
                return results
            except Exception as e:
                logging.error(f'Error during mass update issue_id: {e}')
                raise e
        else:
            query = """
            UPDATE alerts SET issue_id = NULL
            WHERE id = ANY(%s)
            RETURNING *
            """
            action = 'unlink'
            
            # Используем стандартный метод _updateall
            try:
                results = self._updateall(query, (alert_ids,), returning=True)
                if not results:
                    logging.warn(f'No alerts with ids {alert_ids} to unlink from issue')
                return results
            except Exception as e:
                logging.error(f'Error during mass update issue_id: {e}')
                raise e

    def get_issue_aggregated_attributes(self, issue_id):
        """
        Получает все агрегированные атрибуты для issue_id за один запрос.
        
        :param issue_id: ID проблемы
        :return: Словарь с агрегированными атрибутами
        """
        try:
            # Используем CTE (Common Table Expression) для получения базового набора алертов
            sql = """
            WITH issue_alerts AS (
                SELECT *
                FROM alerts
                WHERE issue_id = %s AND status != 'expired'
            ),
            -- Вычисляем максимальное severity
            max_severity AS (
                SELECT 
                    CASE 
                        WHEN MAX(CASE
                            WHEN severity = 'critical' THEN 5
                            WHEN severity = 'high' THEN 4
                            WHEN severity = 'medium' THEN 3
                            ELSE 1
                        END) = 5 THEN 'critical'
                        WHEN MAX(CASE
                            WHEN severity = 'critical' THEN 5
                            WHEN severity = 'high' THEN 4
                            WHEN severity = 'medium' THEN 3
                            ELSE 1
                        END) = 4 THEN 'high'
                        WHEN MAX(CASE
                            WHEN severity = 'critical' THEN 5
                            WHEN severity = 'high' THEN 4
                            WHEN severity = 'medium' THEN 3
                            ELSE 1
                        END) = 3 THEN 'medium'
                        ELSE 'normal'
                    END AS severity
                FROM issue_alerts
            ),
            -- Проверяем наличие критичных хостов
            host_critical AS (
                SELECT 
                    CASE 
                        WHEN COUNT(*) > 0 THEN TRUE 
                        ELSE TRUE -- Меняем на TRUE по умолчанию
                    END AS is_critical
                FROM issue_alerts
                WHERE attributes->>'host_critical' = '1'
            ),
            -- Собираем уникальные events (хосты)
            unique_hosts AS (
                SELECT array_agg(DISTINCT event ORDER BY event) AS hosts
                FROM issue_alerts
            ),
            -- Собираем уникальные project_groups
            project_groups AS (
                SELECT array_agg(DISTINCT substring(t.tag_value FROM 14)) AS project_groups
                FROM issue_alerts a, 
                    LATERAL unnest(a.tags) t(tag_value)
                WHERE t.tag_value LIKE 'ProjectGroup:%%'
            ),
            -- Собираем уникальные info_systems
            info_systems AS (
                SELECT array_agg(DISTINCT substring(t.tag_value FROM 12)) AS info_systems
                FROM issue_alerts a, 
                    LATERAL unnest(a.tags) t(tag_value)
                WHERE t.tag_value LIKE 'InfoSystem:%%'
            ),
            -- Получаем last_alert_time (используем MAX - самое позднее)
            last_alert_time AS (
                SELECT MAX(create_time) AS last_time
                FROM issue_alerts
            ),
            -- Получаем минимальное значение create_time (самое раннее)
            min_create_time AS (
                SELECT MIN(create_time) AS earliest_time
                FROM issue_alerts
            )
            
            -- Собираем все вычисленные данные
            SELECT 
                (SELECT severity FROM max_severity) AS severity,
                (SELECT is_critical FROM host_critical) AS host_critical,
                (SELECT hosts FROM unique_hosts) AS hosts,
                (SELECT project_groups FROM project_groups) AS project_groups,
                (SELECT info_systems FROM info_systems) AS info_systems,
                (SELECT last_time FROM last_alert_time) AS last_alert_time,
                (SELECT earliest_time FROM min_create_time) AS earliest_create_time
            """
            cursor = self.get_db().cursor()
            
            # Правильно форматируем параметр для запроса
            params = (issue_id,)
            cursor.execute(sql, params)
            
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return {
                    'severity': 'normal',
                    'host_critical': True,  # Меняем на True по умолчанию
                    'hosts': [],
                    'project_groups': [],
                    'info_systems': [],
                    'last_alert_time': None,
                    'earliest_create_time': None
                }
            
            # Сформируем словарь с результатами
            keys = ['severity', 'host_critical', 'hosts', 'project_groups', 'info_systems', 'last_alert_time', 'earliest_create_time']
            result_dict = {k: v for k, v in zip(keys, result)}
            
            # Преобразуем пустые массивы из None в пустой список
            for array_key in ['hosts', 'project_groups', 'info_systems']:
                if result_dict[array_key] is None:
                    result_dict[array_key] = []
            
            return result_dict
        except Exception as e:
            logging.error(f"Ошибка при получении агрегированных атрибутов для issue {issue_id}: {str(e)}")
            logging.error(traceback.format_exc())
            # Возвращаем значения по умолчанию
            return {
                'severity': 'normal',
                'host_critical': True,  # Меняем на True по умолчанию
                'hosts': [],
                'project_groups': [],
                'info_systems': [],
                'last_alert_time': None,
                'earliest_create_time': None
            }
