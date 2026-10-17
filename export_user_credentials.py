"""Export credentials or reset every local Acom Task Manager account.

Usage: python export_user_credentials.py [path/to/database.db] [--reset-all]
Without --reset-all, only empty passwords are set to 12345678.
With --reset-all, every password is changed to 12345678 after a database backup.
"""

import argparse
import csv
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


DEFAULT_FOR_EMPTY = '12345678'


def excel_safe(value):
    value = str(value or '')
    return "'" + value if value.startswith(('=', '+', '-', '@')) else value


def main():
    parser = argparse.ArgumentParser(description='Export Acom Task Manager user credentials')
    parser.add_argument('database', nargs='?', default='database.db')
    parser.add_argument('--reset-all', action='store_true', help='Set every account password to 12345678')
    args = parser.parse_args()
    database = Path(args.database).expanduser().resolve()
    if not database.is_file():
        raise SystemExit(f'Database file not found: {database}')

    conn = sqlite3.connect(str(database), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        columns = {row['name'] for row in conn.execute('PRAGMA table_info(users)')}
        if not {'id', 'name', 'username', 'password'} <= columns:
            raise SystemExit('The database does not contain the Acom Task Manager users table.')
        users = conn.execute('SELECT id, name, username, password FROM users ORDER BY id').fetchall()
        empty_ids = [user['id'] for user in users if not str(user['password'] or '').strip()]
        if empty_ids or args.reset_all:
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            backup = database.with_name(f'{database.stem}.backup-{stamp}{database.suffix}')
            with sqlite3.connect(str(backup)) as backup_conn:
                conn.backup(backup_conn)
            conn.execute('BEGIN IMMEDIATE')
            if args.reset_all:
                for user in users:
                    conn.execute('UPDATE users SET password=? WHERE id=?',
                                 (generate_password_hash(DEFAULT_FOR_EMPTY), user['id']))
            else:
                for user_id in empty_ids:
                    conn.execute("UPDATE users SET password=? WHERE id=? AND (password IS NULL OR TRIM(password)='')",
                                 (generate_password_hash(DEFAULT_FOR_EMPTY), user_id))
            conn.commit()
            users = conn.execute('SELECT id, name, username, password FROM users ORDER BY id').fetchall()

        known = list(dict.fromkeys(filter(None, (
            DEFAULT_FOR_EMPTY, '123456', os.environ.get('SEED_PASSWORD'), 'ChangeMe123!'
        ))))
        output = database.with_name(f'user_credentials_{datetime.now():%Y%m%d_%H%M%S_%f}.csv')
        with output.open('x', encoding='utf-8-sig', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(['نام', 'نام کاربری', 'رمز عبور قابل تأیید', 'وضعیت'])
            for user in users:
                saved = user['password'] or ''
                matched = ''
                for candidate in known:
                    try:
                        if check_password_hash(saved, candidate):
                            matched = candidate
                            break
                    except (ValueError, TypeError):
                        break
                status = ('رمز همه حساب‌ها به 12345678 تغییر کرد' if args.reset_all else
                          'رمز خالی بود و 12345678 تنظیم شد' if user['id'] in empty_ids else
                          'رمز تأیید شد' if matched else 'رمز قبلی هش شده و قابل بازیابی نیست')
                writer.writerow([excel_safe(user['name']), excel_safe(user['username']),
                                 excel_safe(matched), status])
        print(f'Exported {len(users)} users to: {output}')
        if args.reset_all:
            print(f'Set 12345678 for all {len(users)} accounts. Backup: {backup}')
        elif empty_ids:
            print(f'Set 12345678 for {len(empty_ids)} empty-password accounts. Backup: {backup}')
    finally:
        conn.close()


if __name__ == '__main__':
    main()
