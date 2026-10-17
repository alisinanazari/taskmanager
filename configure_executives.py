"""One-time setup. Run from the taskmanager folder while the app is stopped."""
from pathlib import Path
from datetime import datetime
import uuid

import app


def configure(ceo_username, administrator_username, *, backup=True):
    ceo_username = ceo_username.strip()
    administrator_username = administrator_username.strip()
    if not ceo_username or not administrator_username or ceo_username == administrator_username:
        raise ValueError('دو نام کاربری متفاوت لازم است')
    app.init_db()
    conn = app.get_db()
    try:
        accounts = conn.execute('SELECT id, username FROM users WHERE username IN (?,?)',
                                (ceo_username, administrator_username)).fetchall()
        if len(accounts) != 2:
            raise ValueError('یک یا هر دو نام کاربری در database.db پیدا نشدند')
        if backup and Path('database.db').exists():
            backup_name = 'database.before_roles_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.db'
            snapshot = app.sqlite3.connect(backup_name)
            try:
                conn.backup(snapshot)
            finally:
                snapshot.close()
            print('Backup:', backup_name)
        conn.execute("UPDATE users SET role='employee', staff_admin=0 WHERE role IN ('admin','administrator')")
        conn.execute("UPDATE users SET role='admin', staff_admin=0 WHERE username=?", (ceo_username,))
        conn.execute("UPDATE users SET role='administrator', staff_admin=0 WHERE username=?", (administrator_username,))
        # Preserve previously assigned organizational titles as global login roles.
        titles = conn.execute('''SELECT DISTINCT j.name FROM job_roles j
                                 JOIN users u ON u.job_role_id=j.id
                                 WHERE u.role NOT IN ('admin','administrator','manager')''').fetchall()
        for title in titles:
            existing = conn.execute('SELECT key FROM role_catalog WHERE name=?', (title['name'],)).fetchone()
            key = existing['key'] if existing else 'custom_' + uuid.uuid4().hex
            if not existing:
                conn.execute('INSERT INTO role_catalog (key,name) VALUES (?,?)', (key, title['name']))
            conn.execute('''UPDATE users SET role=? WHERE role NOT IN ('admin','administrator','manager')
                            AND job_role_id IN (SELECT id FROM job_roles WHERE name=?)''', (key, title['name']))
        conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('executives_configured','1')")
        conn.commit()
        print('CEO:', ceo_username, '| Administrator:', administrator_username)
    finally:
        conn.close()


if __name__ == '__main__':
    app.init_db()
    connection = app.get_db()
    already_configured = app.executive_setup_done(connection)
    connection.close()
    if already_configured:
        print('Executive accounts have already been configured.')
    else:
        print('Enter two existing usernames. Passwords are unchanged.')
        ceo = input('CEO username: ')
        administrator = input('Administrator username: ')
        configure(ceo, administrator)
