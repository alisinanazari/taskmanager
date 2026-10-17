from flask import Flask, render_template, render_template_string, request, jsonify, send_from_directory, send_file, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import sqlite3
import json
import os
import uuid
import secrets
import time
from pathlib import Path
from io import BytesIO
from datetime import datetime, timedelta, date
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

app = Flask(__name__)

# محل نگهداری داده‌های دائمی (دیتابیس، فایل‌های آپلودی، کلید نشست).
# روی سرور داخلی خالی است و همه‌چیز مثل قبل کنار app.py می‌ماند.
# روی هاست‌های کانتینری (مثل لیارا) آن را مسیر دیسک دائمی بگذارید، مثلاً /usr/src/app/data
DATA_DIR = os.environ.get('TASKMANAGER_DATA_DIR', '').strip()
DATABASE_PATH = os.path.join(DATA_DIR, 'database.db') if DATA_DIR else 'database.db'


def _seed_data_dir():
    """اولین اجرا روی دیسک خالی: دیتابیس و فایل‌های همراه بسته را یک‌بار به دیسک منتقل می‌کند.
    اگر روی دیسک فایلی باشد، هرگز بازنویسی نمی‌شود."""
    if not DATA_DIR:
        return
    import shutil
    base = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(DATA_DIR, 'uploads'), exist_ok=True)
    # فایل -wal (تغییرات اخیر SQLite) باید قبل از خود دیتابیس کپی شود تا چیزی جا نماند.
    for name in ('database.db-wal', 'database.db', '.taskmanager-secret-key'):
        src, dst = os.path.join(base, name), os.path.join(DATA_DIR, name)
        if os.path.isfile(src) and not os.path.exists(dst):
            tmp = dst + '.seed-' + uuid.uuid4().hex
            shutil.copy2(src, tmp)
            try:
                os.link(tmp, dst)  # فقط اگر هنوز وجود ندارد (امن در برابر چند worker هم‌زمان)
            except FileExistsError:
                pass
            finally:
                os.remove(tmp)
    src_uploads = os.path.join(base, 'uploads')
    if os.path.isdir(src_uploads):
        for name in os.listdir(src_uploads):
            src, dst = os.path.join(src_uploads, name), os.path.join(DATA_DIR, 'uploads', name)
            if os.path.isfile(src) and not os.path.exists(dst):
                shutil.copy2(src, dst)


_seed_data_dir()

# در پروداکشن حتماً از متغیر محیطی بخونید، نه مقدار ثابت داخل کد.
def stable_secret_key():
    configured = os.environ.get('SECRET_KEY')
    if configured:
        return configured
    key_file = (Path(DATA_DIR) / '.taskmanager-secret-key' if DATA_DIR
                else Path(__file__).resolve().with_name('.taskmanager-secret-key'))
    try:
        existing = key_file.read_text(encoding='utf-8').strip()
        if existing:
            return existing
    except FileNotFoundError:
        pass
    generated = secrets.token_hex(32)
    try:
        with key_file.open('x', encoding='utf-8') as handle:
            handle.write(generated)
        return generated
    except FileExistsError:
        return key_file.read_text(encoding='utf-8').strip()


app.config['SECRET_KEY'] = stable_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER') or (
    os.path.join(DATA_DIR, 'uploads') if DATA_DIR else 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# محدودسازی نرخ درخواست برای جلوگیری از brute-force روی لاگین.
# storage پیش‌فرض حافظه‌ی داخلی است؛ برای اجرای چند-worker/چند-instance
# متغیر RATELIMIT_STORAGE_URI را روی یک Redis تنظیم کنید (مثلاً redis://localhost:6379).
limiter = Limiter(get_remote_address, app=app,
                   storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
                   default_limits=[])

DEFAULT_SEED_PASSWORD = os.environ.get('SEED_PASSWORD', 'ChangeMe123!')


def login_rate_key():
    """محدودیت ورود برای هر «آی‌پی + نام کاربری» جداگانه حساب می‌شود؛ وقتی همهٔ کارکنان از یک
    اینترنت اداری (یک آی‌پی) وارد می‌شوند، ورود هم‌زمان ۳۰ نفر به هم گیر نمی‌کند ولی حدس‌زدن رمز
    یک حساب همچنان محدود است."""
    username = str((request.get_json(silent=True) or {}).get('username') or '').strip().lower()
    return f'{get_remote_address()}|{username}'

EXECUTIVE_ROLES = {'admin', 'administrator'}
# مدیرعامل (admin) همان دسترسی کامل Administrator را دارد.
SUPER_ROLES = ('administrator', 'admin')


def is_super(user):
    return bool(user) and user['role'] in SUPER_ROLES


MANAGEMENT_ROLES = EXECUTIVE_ROLES | {'manager'}
TASK_EDITOR_ROLES = MANAGEMENT_ROLES | {'supervisor'}
MANAGER_STAFF_ROLES = {'supervisor', 'specialist', 'employee'}
SUPERVISOR_STAFF_ROLES = {'specialist', 'employee'}
SUPERVISOR_LOCKED = {'view_all_tasks', 'manage_brands', 'manage_departments', 'manage_roles'}
MANAGER_PERMISSIONS = (
    ('view_all_tasks', 'مشاهده همه تسک‌ها (مدیرعامل)'),
    ('view_brand_tasks', 'مشاهده تسک‌های محدوده خود'),
    ('view_staff', 'مشاهده کاربران و کارکنان'),
    ('view_analytics', 'تحلیل عملکرد'),
    ('create_users', 'افزودن کاربر'),
    ('edit_users', 'ویرایش کاربر، نقش، برند و بخش'),
    ('delete_users', 'حذف کاربر'),
    ('reset_passwords', 'بازنشانی رمز کاربران'),
    ('manage_brands', 'مدیریت برندها'),
    ('manage_departments', 'مدیریت بخش‌ها'),
    ('manage_roles', 'مدیریت نقش‌های سازمانی'),
    ('edit_own_tasks', 'ویرایش کامل تسک‌هایی که خودش ساخته'),
    ('edit_tasks', 'ویرایش تسک‌های دیگران در محدوده دسترسی'),
    ('delete_tasks', 'حذف تسک‌ها'),
    ('rate_tasks', 'امتیازدهی تسک'),
    ('approve_tasks', 'تأیید تسک تکمیل‌شده'),
    ('create_projects', 'ایجاد پروژه'),
    ('edit_own_projects', 'ویرایش پروژه‌ای که خودش ساخته'),
    ('edit_projects', 'ویرایش پروژه‌های دیگران (در محدوده دسترسی)'),
    ('delete_projects', 'حذف پروژه و تسک‌های آن'),
    ('export_data', 'خروجی Excel'),
)
PERMISSION_KEYS = {key for key, _ in MANAGER_PERMISSIONS}
LEVEL_ONE = {'view_all_tasks', 'view_brand_tasks', 'view_staff', 'view_analytics',
             'create_projects', 'export_data', 'edit_own_tasks'}
LEVEL_TWO = LEVEL_ONE | {'create_users', 'edit_users', 'edit_own_tasks', 'edit_tasks', 'rate_tasks',
                         'approve_tasks', 'edit_own_projects', 'edit_projects'}
LEVEL_THREE = LEVEL_TWO | {'delete_users', 'reset_passwords', 'manage_brands',
                           'manage_departments', 'manage_roles', 'delete_tasks', 'delete_projects'}
LEVEL_DEFAULTS = {1: LEVEL_ONE, 2: LEVEL_TWO, 3: LEVEL_THREE}
# نقش‌هایی که Administrator می‌تواند برایشان سطح و مجوز تعریف کند
ACCESS_ROLES = ('admin', 'manager', 'supervisor', 'specialist')
# کارشناس فقط این مجوزها را می‌تواند بگیرد؛ بقیه برای این نقش طراحی نشده‌اند و قفل می‌مانند.
SPECIALIST_ALLOWED = {'edit_own_tasks', 'create_projects', 'edit_own_projects', 'edit_projects', 'delete_projects'}
ROLE_LOCKED = {'manager': {'view_all_tasks'}, 'supervisor': SUPERVISOR_LOCKED,
               'specialist': PERMISSION_KEYS - SPECIALIST_ALLOWED}
BASE_ROLES = (
    ('admin', 'مدیرعامل'), ('manager', 'مدیر برند'),
    ('administrator', 'Administrator'), ('supervisor', 'سرپرست'),
    ('specialist', 'کارشناس'), ('employee', 'کارمند'),
)


def executive_setup_done(conn):
    return bool(conn.execute("SELECT 1 FROM app_settings WHERE key='executives_configured'").fetchone())


def strip_password(user_dict):
    """هرگز هش پسورد را در پاسخ API برنگردانید."""
    d = dict(user_dict)
    d.pop('password', None)
    d.pop('ethics_score', None)
    return d


def current_user():
    if 'user_id' not in session:
        return None
    return {'id': session['user_id'], 'role': session['role'],
            'brand_id': session.get('brand_id'), 'department_id': session.get('department_id'),
            'name': session.get('name')}


def refresh_session_user():
    if 'user_id' not in session:
        return False
    if session.get('expires_at', 0) <= time.time():
        session.clear()
        return False
    conn = get_db()
    if not executive_setup_done(conn):
        conn.close()
        session.clear()
        return False
    user = conn.execute('SELECT role, brand_id, department_id, name FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return False
    session['role'], session['brand_id'], session['department_id'], session['name'] = (
        user['role'], user['brand_id'], user['department_id'], user['name'])
    return True


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not refresh_session_user():
            return jsonify({'success': False, 'error': 'ابتدا وارد شوید'}), 401
        return f(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not refresh_session_user():
                return jsonify({'success': False, 'error': 'ابتدا وارد شوید'}), 401
            if session.get('role') not in roles:
                return jsonify({'success': False, 'error': 'دسترسی غیرمجاز'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def permissions_for(conn, user):
    role = user['role']
    if role in SUPER_ROLES:
        return 3, {key: True for key in PERMISSION_KEYS}
    if role not in ACCESS_ROLES:
        return None, {key: False for key in PERMISSION_KEYS}
    row = conn.execute('SELECT level FROM manager_access WHERE user_id=?', (user['id'],)).fetchone()
    if role == 'supervisor' and row is None:
        # سرپرستی که هنوز سطحی برایش تعیین نشده فقط تسک‌های خودش را ویرایش می‌کند.
        return 1, {key: key == 'edit_own_tasks' for key in PERMISSION_KEYS}
    if role == 'specialist' and row is None:
        # کارشناسی که Administrator هنوز برایش دسترسی تعریف نکرده هیچ مجوز اضافه‌ای ندارد.
        return None, {key: False for key in PERMISSION_KEYS}
    level = row['level'] if row else 1
    enabled = {r['permission_key'] for r in conn.execute(
        'SELECT permission_key FROM access_level_permissions WHERE level=? AND enabled=1', (level,))}
    permissions = {key: key in enabled for key in PERMISSION_KEYS}
    for override in conn.execute('SELECT permission_key,enabled FROM manager_permission_overrides WHERE user_id=?',
                                 (user['id'],)):
        if override['permission_key'] in permissions:
            permissions[override['permission_key']] = bool(override['enabled'])
    for key in ROLE_LOCKED.get(role, ()):
        permissions[key] = False
    return level, permissions


def has_permission(conn, user, key):
    if key not in PERMISSION_KEYS:
        return False
    return permissions_for(conn, user)[1][key]


def permission_required(key):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not refresh_session_user():
                return jsonify({'success': False, 'error': 'ابتدا وارد شوید'}), 401
            conn = get_db()
            allowed = has_permission(conn, current_user(), key)
            conn.close()
            if not allowed:
                return jsonify({'error': 'این دسترسی توسط Administrator برای شما فعال نشده است'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'zip',
                      'html', 'htm',
                      'rar', 'txt'}


HTML_EXTENSIONS = {'html', 'htm'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


# ---- جلوگیری از ثبت تکراری (دوبار کلیک یا ارسال دوباره به‌خاطر کندی شبکه) ----
DUPLICATE_WINDOW_MS = 20000


def lock_for_create(conn):
    """نوشتن‌ها را پشت سر هم می‌کند تا دو درخواست هم‌زمانِ یکسان هر دو از بررسی تکراری رد نشوند."""
    if not conn.in_transaction:
        conn.execute('BEGIN IMMEDIATE')


def recent_duplicate_task(conn, creator_id, title, description, project_id, assignee_ids):
    """اگر همین شخص در ۲۰ ثانیهٔ اخیر تسکی با همین عنوان، توضیحات، پروژه و مسئولان ساخته باشد، همان را برمی‌گرداند."""
    since = int(time.time() * 1000) - DUPLICATE_WINDOW_MS
    rows = conn.execute('''SELECT id, task_code FROM tasks WHERE creator_id=? AND title=?
        AND COALESCE(description,'')=? AND created_at>=? AND project_id IS ? ORDER BY id DESC''',
        (creator_id, title, description or '', since, project_id)).fetchall()
    wanted = set(assignee_ids)
    for row in rows:
        if {r['user_id'] for r in conn.execute('SELECT user_id FROM task_assignees WHERE task_id=?', (row['id'],))} == wanted:
            return row
    return None


def managed_brand_ids(conn, user_id):
    """Brands assigned to this brand manager, read live from the brands table."""
    return {r['id'] for r in conn.execute('SELECT id FROM brands WHERE manager_id=?', (user_id,))}


def manages_brand(conn, me, brand_id):
    return me['role'] == 'manager' and brand_id in managed_brand_ids(conn, me['id'])


# عضویت در برند: برند اصلی (users.brand_id) + برندهای اضافه‌ای که Administrator برای سرپرست/کارشناس تعیین می‌کند.
MULTI_BRAND_ROLES = ('supervisor', 'specialist')
# دسته‌بندی تسک‌های مستقل (کلید، عنوان، زیردسته‌ها)
TASK_CATEGORIES = (
    ('finance', 'مالی', (('payment_order', 'دستور پرداخت'), ('deposit', 'واریز'), ('tax', 'مالیات'), ('insurance', 'بیمه'))),
    ('sales', 'فروش', (('official_sale', 'فروش رسمی'), ('unofficial_sale', 'فروش غیر رسمی'))),
    ('warehouse', 'انبار', ()),
    ('admin', 'اداری', (('equipment_request', 'درخواست تجهیزات'),)),
    ('it', 'IT', ()),
    ('bi', 'BI', ()),
    ('courier', 'تحصیلدار', (('goods_transfer', 'جابه‌جایی کالا'), ('documents_transfer', 'جابه‌جایی اسناد'))),
    ('other', 'سایر', ()),
)


def validate_task_category(data):
    """(category, subcategory, error) — دسته الزامی است؛ اگر دسته زیردسته دارد، زیردسته هم الزامی است."""
    category = str(data.get('category') or '').strip()
    subcategory = str(data.get('subcategory') or '').strip() or None
    entry = next((c for c in TASK_CATEGORIES if c[0] == category), None)
    if not entry:
        return None, None, 'دسته‌بندی تسک را انتخاب کنید'
    subs = {k for k, _ in entry[2]}
    if subs and subcategory not in subs:
        return None, None, f'زیردستهٔ «{entry[1]}» را انتخاب کنید'
    if not subs:
        subcategory = None
    return category, subcategory, None


# نوع فروش (نقدی / اعتباری) برای زیردسته‌های «فروش رسمی» و «فروش غیر رسمی»
SALE_TERMS = {'cash': 'نقدی', 'credit': 'اعتباری'}


def clean_sale_term(category, data, current=None):
    """(sale_term, error) — برای دستهٔ فروش، نقدی یا اعتباری بودن الزامی است."""
    if category != 'sales':
        return None, None
    term = str(data.get('sale_term') or current or '').strip()
    if term not in SALE_TERMS:
        return None, 'نقدی یا اعتباری بودن فروش را انتخاب کنید'
    return term, None


# فرم دستور پرداخت (دسته «مالی» / زیردسته «دستور پرداخت»)؛ فعلاً هیچ فیلدی اجباری نیست.
PAYMENT_ORDER_KINDS = {'official': 'رسمی', 'unofficial': 'غیر رسمی'}
PAYMENT_METHODS = {'cash': 'پرداخت نقدی', 'online': 'پرداخت آنلاین', 'cheque': 'پرداخت چک', 'card': 'کارت به کارت'}
PAYMENT_ORDER_FIELDS = ('unit_name', 'recipient_company', 'subject', 'project_number', 'brand_name', 'notes',
                        'payer_company', 'amount', 'method', 'card_number', 'counterparty_detail', 'bank_name',
                        'statement_number')


def clean_payment_order(category, subcategory, raw):
    """(json_text_or_None, error). فقط برای مالی/دستور پرداخت ذخیره می‌شود."""
    if category != 'finance' or subcategory != 'payment_order' or raw in (None, ''):
        return None, None
    if not isinstance(raw, dict):
        return None, 'فرم دستور پرداخت نامعتبر است'
    kind = str(raw.get('kind') or '').strip()
    if kind and kind not in PAYMENT_ORDER_KINDS:
        return None, 'نوع دستور پرداخت نامعتبر است'
    form = {'kind': kind}
    for key in PAYMENT_ORDER_FIELDS:
        form[key] = str(raw.get(key) or '').strip()[:2000 if key in ('subject', 'notes', 'counterparty_detail') else 200]
    digits = str.maketrans('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789')
    form['amount'] = ''.join(ch for ch in form['amount'].translate(digits) if ch.isdigit())[:20]
    if form['method'] and form['method'] not in PAYMENT_METHODS:
        return None, 'نوع پرداخت نامعتبر است'
    form['card_number'] = (''.join(ch for ch in form['card_number'].translate(digits) if ch.isdigit())[:19]
                           if form['method'] == 'card' else '')
    return json.dumps(form, ensure_ascii=False), None
ARCHIVE_AFTER_DAYS = int(os.environ.get('TASK_ARCHIVE_DAYS', '5'))
BRAND_MEMBERSHIP = 'user_brand_membership'


def user_brand_ids(conn, user_id):
    return {r[0] for r in conn.execute(f'SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?', (user_id,))}


def member_of_brand_sql(alias, brand_sql='?'):
    """شرط SQL: کاربر alias عضو برند brand_sql است (اصلی یا اضافه)."""
    return f'EXISTS(SELECT 1 FROM {BRAND_MEMBERSHIP} bm WHERE bm.user_id={alias}.id AND bm.brand_id={brand_sql})'


def member_of_brands_sql(alias, brands_sql):
    """شرط SQL: کاربر alias عضو یکی از برندهای brands_sql (یک زیرکوئری یا لیست داخل پرانتز) است."""
    return f'EXISTS(SELECT 1 FROM {BRAND_MEMBERSHIP} bm WHERE bm.user_id={alias}.id AND bm.brand_id IN {brands_sql})'


def manages_user(conn, me, user):
    """مدیر برند، کارکنی را که دست‌کم در یکی از برندهای او عضو است مدیریت می‌کند."""
    return me['role'] == 'manager' and bool(user_brand_ids(conn, user['id']) & managed_brand_ids(conn, me['id']))


def supervisor_staff_scope(conn, me, user):
    if (me['role'] != 'supervisor' or me['department_id'] is None or
            user['department_id'] != me['department_id']):
        return False
    return bool(user_brand_ids(conn, me['id']) & user_brand_ids(conn, user['id']))


def supervisor_task_scope(conn, me, task):
    if me['role'] != 'supervisor' or me['department_id'] is None:
        return False
    if task['brand_id'] not in user_brand_ids(conn, me['id']):
        return False
    return bool(conn.execute(f'''SELECT 1 FROM users u WHERE u.id=?
        AND u.department_id=? AND {member_of_brand_sql('u')}
        UNION SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
        WHERE ta.task_id=? AND u.department_id=? AND {member_of_brand_sql('u')} LIMIT 1''',
        (task['creator_id'], me['department_id'], task['brand_id'], task['id'],
         me['department_id'], task['brand_id'])).fetchone())


def can_edit_own_task(conn, me, task):
    """Full edit of a task this leader created, granted by Administrator via 'edit_own_tasks'.
    Applies to every task the person created, old or new, while it is still open."""
    return (task['creator_id'] == me['id'] and me['role'] in TASK_EDITOR_ROLES | {'specialist'} and
            task['status'] not in ('done', 'rejected') and
            has_permission(conn, me, 'edit_own_tasks') and can_view_task(conn, task, me))


def can_fully_edit_task(conn, me, task):
    """Own tasks need 'edit_own_tasks'; edits to others require the scoped 'edit_tasks' grant."""
    if is_super(me):
        return True  # Administrator: ویرایش کامل همه تسک‌ها بدون محدودیت
    if is_task_observer(conn, task['id'], me['id']) or forwarded_by(conn, task['id'], me['id']):
        return False
    if task['project_id'] is None and task['creator_id'] == me['id'] and task['creator_edit_allowed']:
        return True
    if can_edit_own_task(conn, me, task):
        return True
    return (task['status'] not in ('done', 'rejected') and
            has_permission(conn, me, 'edit_tasks') and
            can_view_task(conn, task, me) and
            (me['role'] in EXECUTIVE_ROLES or
             manages_brand(conn, me, task['brand_id']) or
             supervisor_task_scope(conn, me, task)))


def sync_manager_primary_brand(conn, user_id):
    """Keep the legacy primary brand useful for older sessions and existing UI."""
    primary = conn.execute('SELECT MIN(id) FROM brands WHERE manager_id=?', (user_id,)).fetchone()[0]
    conn.execute('UPDATE users SET brand_id=? WHERE id=? AND role=?', (primary, user_id, 'manager'))


def public_user(conn, user, include_access=False):
    result = strip_password(user)
    result['managed_brand_ids'] = sorted(managed_brand_ids(conn, user['id'])) if user['role'] == 'manager' else []
    result['brand_ids'] = sorted(user_brand_ids(conn, user['id']))
    result['extra_brand_ids'] = sorted(set(result['brand_ids']) - {user['brand_id']})
    result.pop('ethics_score', None)
    if include_access:
        result['permission_level'], result['permissions'] = permissions_for(conn, user)
    return result


def _migrate_legacy_assignee_ids(conn, c):
    """اگر دیتابیس قدیمی با ستون assignee_ids (CSV) باشد، داده را به جدول
    task_assignees منتقل می‌کند و ستون قدیمی را (در صورت پشتیبانی SQLite) حذف می‌کند."""
    cols = [r[1] for r in c.execute("PRAGMA table_info(tasks)").fetchall()]
    if 'assignee_ids' not in cols:
        return
    for row in c.execute("SELECT id, assignee_ids FROM tasks").fetchall():
        for uid in (row['assignee_ids'] or '').split(','):
            uid = uid.strip()
            if uid.isdigit():
                c.execute('INSERT OR IGNORE INTO task_assignees (task_id, user_id) VALUES (?,?)',
                          (row['id'], int(uid)))
    try:
        c.execute('ALTER TABLE tasks DROP COLUMN assignee_ids')
    except sqlite3.OperationalError:
        pass  # SQLite قدیمی‌تر از 3.35 - ستون باقی می‌ماند ولی دیگر استفاده نمی‌شود
    conn.commit()


def get_task_assignees(conn, task_id):
    return [r['user_id'] for r in conn.execute(
        'SELECT user_id FROM task_assignees WHERE task_id=?', (task_id,)).fetchall()]


def get_task_observers(conn, task_id):
    return [r['user_id'] for r in conn.execute(
        'SELECT user_id FROM task_observers WHERE task_id=? ORDER BY user_id', (task_id,))]


def is_task_observer(conn, task_id, user_id):
    return bool(conn.execute('SELECT 1 FROM task_observers WHERE task_id=? AND user_id=?',
                             (task_id, user_id)).fetchone())


def validate_added_observers(conn, task, raw, assignee_ids, actor_id):
    """Return new observers or a validation response; existing observers cannot be removed."""
    if (not isinstance(raw, list) or any(type(uid) not in (int, str) or
            not str(uid).isdigit() for uid in raw)):
        return None, (jsonify({'error': 'ناظران تسک نامعتبرند'}), 400)
    ids = [int(uid) for uid in raw]
    if len(ids) != len(set(ids)) or any(uid <= 0 for uid in ids):
        return None, (jsonify({'error': 'ناظران تسک نامعتبرند'}), 400)
    current = set(get_task_observers(conn, task['id']))
    if not current.issubset(ids):
        return None, (jsonify({'error': 'ناظران قبلی قابل حذف نیستند؛ فقط فرد جدید اضافه کنید'}), 409)
    added = set(ids) - current
    if any(uid == task['creator_id'] or uid == actor_id or uid in assignee_ids or
           not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone() or
           forwarded_by(conn, task['id'], uid) for uid in added):
        return None, (jsonify({'error': 'ناظر جدید نمی‌تواند سازنده، مسئول، فورواردکننده یا ویرایشگر فعلی باشد'}), 400)
    return added, None


def add_task_observers(conn, task, actor, new_ids):
    for uid in sorted(new_ids):
        conn.execute('INSERT INTO task_observers (task_id,user_id) VALUES (?,?)', (task['id'], uid))
        if task['project_id'] is not None:
            conn.execute('INSERT OR IGNORE INTO project_members (project_id,user_id) VALUES (?,?)',
                         (task['project_id'], uid))
            conn.execute('INSERT OR IGNORE INTO task_participants (task_id,user_id) VALUES (?,?)',
                         (task['id'], uid))
        create_notification(uid, '👁️ ناظر تسک',
                            f'{actor["name"]} شما را ناظر تسک «{task["title"]}» کرد. می‌توانید روند آن را مشاهده کنید.',
                            'info', task['id'], conn=conn)
    if new_ids:
        task_event(conn, task['id'], actor['id'], 'observers_added',
                   f'{len(new_ids)} ناظر به تسک اضافه شد')


def shared_with(conn, task_id, user_id):
    return bool(conn.execute('SELECT 1 FROM task_shares WHERE task_id=? AND to_user_id=? LIMIT 1',
                             (task_id, user_id)).fetchone())


def forwarded_by(conn, task_id, user_id):
    return bool(conn.execute('SELECT 1 FROM task_forwards WHERE task_id=? AND from_user_id=?',
                             (task_id, user_id)).fetchone())


def task_is_mentioned(conn, task_id, user_id):
    return bool(conn.execute('''SELECT 1 FROM task_comment_mentions m
        JOIN task_comments c ON c.id=m.comment_id
        WHERE c.task_id=? AND m.user_id=? LIMIT 1''', (task_id, user_id)).fetchone())


def can_view_task(conn, task, me):
    direct = (is_super(me) or
              (me['role'] == 'admin' and has_permission(conn, me, 'view_all_tasks')) or
              task['creator_id'] == me['id'] or
              me['id'] in get_task_assignees(conn, task['id']) or
              is_task_observer(conn, task['id'], me['id']) or
              forwarded_by(conn, task['id'], me['id']) or
              shared_with(conn, task['id'], me['id']))
    if task['project_id'] is not None:
        return direct or task_is_mentioned(conn, task['id'], me['id']) or (
            manages_brand(conn, me, task['brand_id']) and
            has_permission(conn, me, 'view_brand_tasks') and
            bool(conn.execute(f'''SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
                WHERE ta.task_id=? AND {member_of_brand_sql('u')}
                AND u.role IN ('supervisor','specialist','employee') LIMIT 1''',
                (task['id'], task['brand_id'])).fetchone()))
    return direct or (has_permission(conn, me, 'view_brand_tasks') and (
        manages_brand(conn, me, task['brand_id']) or supervisor_task_scope(conn, me, task)))


def is_project_member(conn, project_id, user_id):
    return bool(conn.execute('SELECT 1 FROM project_members WHERE project_id=? AND user_id=?',
                             (project_id, user_id)).fetchone())


def project_event(conn, project_id, task_id, actor_id, action, detail):
    if project_id is not None:
        conn.execute('''INSERT INTO project_events (project_id, task_id, actor_id, action, detail, created_at)
                        VALUES (?,?,?,?,?,?)''',
                     (project_id, task_id, actor_id, action, detail, int(datetime.now().timestamp() * 1000)))


def task_event(conn, task_id, actor_id, action, detail):
    project_id = conn.execute('SELECT project_id FROM tasks WHERE id=?', (task_id,)).fetchone()['project_id']
    project_event(conn, project_id, task_id, actor_id, action, detail)


def repair_notification_text(value):
    """Recover legacy UTF-8 text decoded as Latin-1/Windows-1252, without changing healthy text."""
    if not value or not any(part in value for part in ('Ø', 'Ù', 'Û', 'ðŸ', 'â€', 'Ã')):
        return value
    for _ in range(2):
        candidates = []
        for codec in ('latin-1', 'cp1252'):
            try:
                decoded = value.encode(codec).decode('utf-8')
            except (UnicodeError, ValueError):
                continue
            if decoded != value and (sum('\u0600' <= ch <= '\u06ff' for ch in decoded) >
                                     sum('\u0600' <= ch <= '\u06ff' for ch in value) or
                                     any(ord(ch) > 0xffff for ch in decoded)):
                candidates.append(decoded)
        if not candidates:
            break
        value = max(candidates, key=lambda item: sum('\u0600' <= ch <= '\u06ff' for ch in item))
    return value


def notify_task_rating(conn, task_id):
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
    if not task:
        return
    if task['status'] != 'done':
        conn.execute('UPDATE tasks SET rating_notified_signature=NULL WHERE id=?', (task_id,))
        return
    scores = (task['task_score'], task['quality_score'])
    if any(value is None for value in scores):
        return
    assignees = sorted(get_task_assignees(conn, task_id))
    signature = f'v2:{scores[0]}:{scores[1]}:{",".join(map(str, assignees))}'
    if task['rating_notified_signature'] == signature:
        return
    total = sum(scores)
    label = 'عالی' if total >= 14 else 'خوب' if total >= 7 else 'نیاز به بازبینی بیشتر'
    for uid in assignees:
        create_notification(uid, '📊 نتیجه امتیازدهی تسک',
                            f'تسک «{task["title"]}»: امتیاز کمی {scores[0]}، کیفی {scores[1]}؛ مجموع {total} از ۲۰ — {label}.',
                            'success', task_id, conn=conn)
    conn.execute('UPDATE tasks SET rating_notified_signature=? WHERE id=?', (signature, task_id))


def set_task_assignees(conn, task_id, user_ids):
    wanted = {int(u) for u in user_ids if str(u).strip()}
    existing = set(get_task_assignees(conn, task_id))
    for uid in existing - wanted:
        conn.execute('DELETE FROM task_assignees WHERE task_id=? AND user_id=?', (task_id, uid))
    for uid in wanted - existing:
        conn.execute('INSERT OR IGNORE INTO task_assignees (task_id, user_id) VALUES (?,?)', (task_id, uid))


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, username TEXT UNIQUE, 
        password TEXT, role TEXT, brand_id INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS brands (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, manager_id INTEGER, 
        color TEXT DEFAULT '#3498db')""")
    new_departments = not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='departments'").fetchone()
    c.execute('CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)')
    c.execute('''CREATE TABLE IF NOT EXISTS job_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, brand_id INTEGER NOT NULL,
        name TEXT NOT NULL, UNIQUE(brand_id, name))''')
    c.execute('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    c.execute('''CREATE TABLE IF NOT EXISTS access_level_permissions (
        level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 3),
        permission_key TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        PRIMARY KEY(level,permission_key))''')
    c.execute('''CREATE TABLE IF NOT EXISTS manager_access (
        user_id INTEGER PRIMARY KEY, level INTEGER NOT NULL DEFAULT 1 CHECK(level BETWEEN 1 AND 3),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS manager_permission_overrides (
        user_id INTEGER NOT NULL, permission_key TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        PRIMARY KEY(user_id,permission_key),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER NOT NULL,
        target_type TEXT NOT NULL, target_id INTEGER NOT NULL,
        detail TEXT NOT NULL, created_at INTEGER NOT NULL)''')
    for level, defaults in LEVEL_DEFAULTS.items():
        c.executemany('INSERT OR IGNORE INTO access_level_permissions (level,permission_key,enabled) VALUES (?,?,?)',
                      [(level, key, int(key in defaults)) for key in PERMISSION_KEYS])
    # یک‌بار: مدیرعامل، مدیر برند و سرپرست فقط تسک‌های خودشان را ویرایش کنند؛
    # ویرایش تسک دیگران خاموش و ویرایش تسک خود برای همه سطوح روشن می‌شود.
    # بعد از این، Administrator می‌تواند از صفحه سطوح دسترسی دوباره تغییرش دهد.
    if not c.execute("SELECT 1 FROM app_settings WHERE key='task_edit_policy_v1'").fetchone():
        c.execute("UPDATE access_level_permissions SET enabled=0 WHERE permission_key='edit_tasks'")
        c.execute("UPDATE access_level_permissions SET enabled=1 WHERE permission_key='edit_own_tasks'")
        c.execute("DELETE FROM manager_permission_overrides WHERE permission_key IN ('edit_tasks','edit_own_tasks')")
        c.execute("INSERT INTO app_settings (key,value) VALUES ('task_edit_policy_v1','1')")
    # یک‌بار: «ویرایش پروژه خود» از «ویرایش پروژه» جدا شد. رفتار فعلی دقیقاً حفظ می‌شود:
    # هر کس قبلاً پروژهٔ خودش را ویرایش می‌کرد هنوز می‌تواند؛ مدیر برند و سرپرست پروژهٔ دیگران را نه؛
    # و سرپرست مثل قبل پروژه نمی‌سازد تا Administrator خودش فعال کند.
    if not c.execute("SELECT 1 FROM app_settings WHERE key='project_access_policy_v1'").fetchone():
        c.execute('''UPDATE access_level_permissions SET enabled=(SELECT p.enabled FROM access_level_permissions p
            WHERE p.level=access_level_permissions.level AND p.permission_key='edit_projects')
            WHERE permission_key='edit_own_projects' ''')
        people = c.execute("SELECT id, role FROM users WHERE role IN ('admin','manager','supervisor')").fetchall()
        for person in people:
            if person['role'] == 'supervisor' and not c.execute(
                    'SELECT 1 FROM manager_access WHERE user_id=?', (person['id'],)).fetchone():
                continue  # سرپرست بدون سطح اصلاً مجوز پروژه ندارد
            effective = permissions_for(conn, person)[1]
            changes = {}
            if effective['edit_own_projects'] != effective['edit_projects']:
                changes['edit_own_projects'] = effective['edit_projects']
            if person['role'] in ('manager', 'supervisor') and effective['edit_projects']:
                changes['edit_projects'] = False
            if person['role'] == 'supervisor' and effective['create_projects']:
                changes['create_projects'] = False
            for key, value in changes.items():
                c.execute('''INSERT INTO manager_permission_overrides (user_id,permission_key,enabled) VALUES (?,?,?)
                    ON CONFLICT(user_id,permission_key) DO UPDATE SET enabled=excluded.enabled''',
                          (person['id'], key, int(value)))
        c.execute("INSERT INTO app_settings (key,value) VALUES ('project_access_policy_v1','1')")
    c.execute('CREATE TABLE IF NOT EXISTS role_catalog (key TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, built_in INTEGER NOT NULL DEFAULT 0)')
    c.executemany('INSERT OR IGNORE INTO role_catalog (key, name, built_in) VALUES (?,?,1)', BASE_ROLES)
    if new_departments:
        c.executemany('INSERT INTO departments (name) VALUES (?)',
                      [(name,) for name in ('مالی', 'بازرگانی', 'R&D', 'فروش', 'BI', 'دیگر')])
    c.execute("""CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, 
        creator_id INTEGER, brand_id INTEGER, 
        status TEXT DEFAULT 'new', priority TEXT DEFAULT 'normal', 
        progress INTEGER DEFAULT 0, requirements TEXT, approval TEXT, 
        due_date TEXT, created_at INTEGER, completed_at INTEGER, 
        notified_overdue INTEGER DEFAULT 0)""")
    # جدول جدا برای تخصیص تسک به کاربران، به‌جای رشته CSV در ستون assignee_ids
    # (رشته‌ی CSV در کوئری‌ها با LIKE/INSTR شکننده و مستعد باگ بود؛ اینجا هر ردیف یک تخصیص است)
    c.execute("""CREATE TABLE IF NOT EXISTS task_assignees (
        task_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY (task_id, user_id),
        FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_task_assignees_task ON task_assignees(task_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_task_assignees_user ON task_assignees(user_id)")
    c.execute('''CREATE TABLE IF NOT EXISTS task_observers (
        task_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        PRIMARY KEY(task_id, user_id),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_task_observers_user ON task_observers(user_id,task_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS task_forwards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL,
        forwarded_at INTEGER NOT NULL,
        FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_task_forwards_sender ON task_forwards(from_user_id, task_id)')
    # چت و فایل‌های پروژه (جدا از تسک‌ها)
    c.execute('''CREATE TABLE IF NOT EXISTS project_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        text TEXT, created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS project_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL, message_id INTEGER,
        filename TEXT NOT NULL, original_name TEXT, file_size INTEGER, uploader_id INTEGER, created_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_project_messages ON project_messages(project_id, id)')
    # آخرین پیام دیده‌شده در صفحهٔ «پیام‌های پروژه‌ها» برای هر کاربر
    c.execute('CREATE TABLE IF NOT EXISTS project_chat_reads (user_id INTEGER PRIMARY KEY, last_seen_id INTEGER NOT NULL DEFAULT 0)')
    # فوروارد تسکِ تمام‌شده = اشتراک‌گذاری برای مشاهده (مسئولیت کسی جابه‌جا نمی‌شود)
    c.execute('''CREATE TABLE IF NOT EXISTS task_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, from_user_id INTEGER NOT NULL,
        to_user_id INTEGER NOT NULL, shared_at INTEGER NOT NULL)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_task_shares_to ON task_shares(to_user_id, task_id)')
    # تسک مستقل چندمرحله‌ای: هر ردیف یعنی تسک از مسئولان قبلی به مسئولان مرحلهٔ بعد رفت
    c.execute('''CREATE TABLE IF NOT EXISTS task_stages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, stage_no INTEGER NOT NULL,
        from_user_id INTEGER, prev_user_ids TEXT, to_user_ids TEXT, note TEXT, prev_status TEXT,
        prev_progress INTEGER, created_at INTEGER NOT NULL)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_task_stages_task ON task_stages(task_id, stage_no)')
    payment_init_tables(c)  # روند پرداخت (مالی / دستور پرداخت)
    sales_board_init_tables(c)  # تابلو اعلانات فروش (کالا، قیمت‌ها، مشتریان، پیشنهادهای فروش)
    if 'stage_no' not in {r[1] for r in c.execute('PRAGMA table_info(task_attachments)')}:
        c.execute('ALTER TABLE task_attachments ADD COLUMN stage_no INTEGER')  # فایل مربوط به کدام مرحلهٔ تسک چندمرحله‌ای
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT,
        creator_id INTEGER NOT NULL, created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS project_members (
        project_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        PRIMARY KEY(project_id, user_id), FOREIGN KEY(project_id) REFERENCES projects(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS project_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL,
        task_id INTEGER, actor_id INTEGER, action TEXT NOT NULL, detail TEXT,
        created_at INTEGER NOT NULL, FOREIGN KEY(project_id) REFERENCES projects(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS task_participants (
        task_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        PRIMARY KEY(task_id, user_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS task_comment_mentions (
        comment_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        PRIMARY KEY(comment_id, user_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS task_user_progress (
        task_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
        progress INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL,
        PRIMARY KEY(task_id, user_id),
        FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE)''')
    _migrate_legacy_assignee_ids(conn, c)
    assignee_columns = {r['name'] for r in c.execute('PRAGMA table_info(task_assignees)')}
    if 'acceptance_status' not in assignee_columns:
        c.execute("ALTER TABLE task_assignees ADD COLUMN acceptance_status TEXT DEFAULT 'pending'")
        c.execute('ALTER TABLE task_assignees ADD COLUMN accepted_at INTEGER')
        # تسک‌های موجود پیش از این نسخه نیازی به تایید مجدد ندارند.
        c.execute("""UPDATE task_assignees SET acceptance_status='accepted',
                     accepted_at=(SELECT created_at FROM tasks WHERE tasks.id=task_assignees.task_id)""")
    elif 'accepted_at' not in assignee_columns:
        c.execute('ALTER TABLE task_assignees ADD COLUMN accepted_at INTEGER')
    c.execute("""CREATE TABLE IF NOT EXISTS task_attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, filename TEXT, 
        original_name TEXT, file_type TEXT, file_size INTEGER, uploaded_at INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, 
        message TEXT, type TEXT DEFAULT 'info', task_id INTEGER, 
        is_read INTEGER DEFAULT 0, created_at INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS task_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER, user_id INTEGER, 
        comment TEXT, created_at INTEGER)""")

    # افزوده‌های سازگار با پایگاه داده نسخه‌های قبلی
    task_columns = {r['name'] for r in c.execute('PRAGMA table_info(tasks)')}
    for column, definition in (
        ('task_code', 'TEXT'), ('is_daily', 'INTEGER DEFAULT 0'),
        ('estimated_minutes', 'INTEGER'), ('task_score', 'INTEGER'),
        ('quality_score', 'INTEGER'), ('ethics_score', 'INTEGER'),
        ('rating_notified_signature', 'TEXT'), ('project_id', 'INTEGER'),
        ('creator_edit_allowed', 'INTEGER NOT NULL DEFAULT 0')):
        if column not in task_columns:
            c.execute(f'ALTER TABLE tasks ADD COLUMN {column} {definition}')
    c.execute('''INSERT OR IGNORE INTO task_user_progress (task_id,user_id,progress,updated_at)
        SELECT ta.task_id,ta.user_id,CASE WHEN t.status='done' THEN 100 ELSE COALESCE(t.progress,0) END,
               COALESCE(t.created_at,0) FROM task_assignees ta JOIN tasks t ON t.id=ta.task_id
        WHERE t.project_id IS NOT NULL''')
    c.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) SELECT id, creator_id FROM tasks')
    c.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) SELECT task_id, user_id FROM task_assignees')
    c.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) SELECT task_id, from_user_id FROM task_forwards')
    c.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) SELECT task_id, to_user_id FROM task_forwards')
    # کد پروژه (PRJ-000001) برای پروژه‌های قبلی و جدید
    project_columns = {r['name'] for r in c.execute('PRAGMA table_info(projects)')}
    if 'project_code' not in project_columns:
        c.execute('ALTER TABLE projects ADD COLUMN project_code TEXT')
    c.execute("UPDATE projects SET project_code='PRJ-' || substr('000000' || id, -6, 6) WHERE project_code IS NULL OR project_code=''")
    # دسته‌بندی پروژه: برند + زیرگروه (بازرگانی/تولیدی) یا «سایر پروژه‌ها»
    if 'brand_id' not in project_columns:
        c.execute('ALTER TABLE projects ADD COLUMN brand_id INTEGER')
    if 'category' not in project_columns:
        c.execute('ALTER TABLE projects ADD COLUMN category TEXT')
    # وضعیت روال بازرگانی: تعداد مراحل انجام‌شده + بیمه، خرید ارز، استاندارد اجباری
    for column, definition in (('trade_stage', 'INTEGER NOT NULL DEFAULT 0'),
                               ('insurance_done', 'INTEGER NOT NULL DEFAULT 0'),
                               ('fx_done', 'INTEGER NOT NULL DEFAULT 0'),
                               ('standard_required', 'INTEGER'),
                               ('standard_done', 'INTEGER NOT NULL DEFAULT 0'),
                               ('insurance_required', 'INTEGER'),
                               ('inspection_required', 'INTEGER'),
                               ('inspection_done', 'INTEGER NOT NULL DEFAULT 0'),
                               ('production_stage', 'INTEGER NOT NULL DEFAULT 0')):
        if column not in project_columns:
            c.execute(f'ALTER TABLE projects ADD COLUMN {column} {definition}')
            if column == 'insurance_required':
                # بیمه‌ای که قبلاً «انجام شد» ثبت شده یعنی پروژه بیمه دارد
                c.execute('UPDATE projects SET insurance_required=1 WHERE insurance_done=1')
    # یادآوری روزانهٔ نزدیک شدن مهلت
    task_columns = {r['name'] for r in c.execute('PRAGMA table_info(tasks)')}
    if 'reminder_sent_on' not in task_columns:
        c.execute('ALTER TABLE tasks ADD COLUMN reminder_sent_on TEXT')
    # سطل زباله: تسک حذف‌شده با همهٔ اطلاعات وابسته‌اش این‌جا نگه داشته می‌شود
    c.execute('''CREATE TABLE IF NOT EXISTS task_trash (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL, task_code TEXT, title TEXT,
        project_id INTEGER, project_name TEXT, brand_id INTEGER, creator_id INTEGER,
        deleted_by INTEGER, deleted_at INTEGER NOT NULL, snapshot TEXT NOT NULL)''')
    trash_columns = {r['name'] for r in c.execute('PRAGMA table_info(task_trash)')}
    if 'item_type' not in trash_columns:
        c.execute("ALTER TABLE task_trash ADD COLUMN item_type TEXT NOT NULL DEFAULT 'task'")
    if 'task_count' not in trash_columns:
        c.execute('ALTER TABLE task_trash ADD COLUMN task_count INTEGER')
    user_columns = {r['name'] for r in c.execute('PRAGMA table_info(users)')}
    for column in ('phone', 'bio'):
        if column not in user_columns:
            c.execute(f'ALTER TABLE users ADD COLUMN {column} TEXT')
    seed_staff_privileges = 'staff_admin' not in user_columns
    if seed_staff_privileges:
        c.execute('ALTER TABLE users ADD COLUMN staff_admin INTEGER DEFAULT 0')
    if 'department_id' not in user_columns:
        c.execute('ALTER TABLE users ADD COLUMN department_id INTEGER')
    if 'job_role_id' not in user_columns:
        c.execute('ALTER TABLE users ADD COLUMN job_role_id INTEGER')
    if 'ethics_score' not in user_columns:
        c.execute('ALTER TABLE users ADD COLUMN ethics_score INTEGER')
        c.execute("""UPDATE users SET ethics_score=(
            SELECT CAST(AVG(t.ethics_score) + 0.5 AS INTEGER)
            FROM task_assignees ta JOIN tasks t ON t.id=ta.task_id
            WHERE ta.user_id=users.id AND t.status='done' AND t.ethics_score IS NOT NULL
        )""")
        # Preserve old rating notifications: moving ethics to profiles must not resend results.
        for task in c.execute("SELECT id, task_score, quality_score FROM tasks WHERE rating_notified_signature IS NOT NULL").fetchall():
            assignees = sorted(get_task_assignees(conn, task['id']))
            if task['task_score'] is not None and task['quality_score'] is not None:
                signature = f'v2:{task["task_score"]}:{task["quality_score"]}:{",".join(map(str, assignees))}'
                c.execute('UPDATE tasks SET rating_notified_signature=? WHERE id=?', (signature, task['id']))
    promote_admins = 'admin_promotion_done' not in user_columns
    if promote_admins:
        c.execute('ALTER TABLE users ADD COLUMN admin_promotion_done INTEGER DEFAULT 0')
    c.execute("UPDATE tasks SET task_code = printf('TASK-%06d', id) WHERE task_code IS NULL OR task_code = ''")
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_code ON tasks(task_code)')

    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        brands_data = [
            ('گروه', '#3498db'), ('VTA', '#e74c3c'), ('XIMENT', '#27ae60'),
            ('PEXOl', '#f39c12'), ('RETRONA', '#9b59b6')
        ]
        for name, color in brands_data:
            c.execute("INSERT INTO brands (name, color) VALUES (?, ?)", (name, color))

        seed_hash = generate_password_hash(DEFAULT_SEED_PASSWORD)

        # احسان آشتیانی فقط به عنوان مدیر کل
        c.execute(
            "INSERT INTO users (name, username, password, role, brand_id) VALUES ('احسان آشتیانی', 'admin', ?, 'admin', 1)",
            (seed_hash,))

        # مدیران برند (بدون احسان آشتیانی)
        managers = [
            ('محسن عباسی', 'manager2', 2),
            ('حامد حواصلی آشتیانی', 'manager3', 3),
            ('محدثه پناهی', 'manager4', 4),
            ('ماهان جوادی', 'manager5', 5),
        ]
        for name, username, brand_id in managers:
            c.execute(
                "INSERT INTO users (name, username, password, role, brand_id) VALUES (?, ?, ?, 'manager', ?)",
                (name, username, seed_hash, brand_id))
            c.execute(
                "UPDATE brands SET manager_id = (SELECT id FROM users WHERE username=?) WHERE id = ?",
                (username, brand_id))

        # مدیر برند گروه = ادمین (احسان آشتیانی)
        c.execute("UPDATE brands SET manager_id = (SELECT id FROM users WHERE username='admin') WHERE id = 1")

        # کارمندان واقعی هر برند
        employees_by_brand = {
            1: [  # گروه
                'مسیح صیدی', 'فاطمه کیا', 'سمانه کرماجانی', 'سحر لطفی', 'حدیث قلی پور',
                'هادی حیات', 'مریم بکائی', 'حسن مرادیان', 'الهه ملکی', 'حامد یعقوب زاده',
                'حنانه کمالی', 'سینا نظری'
            ],
            2: [  # VTA
                'آرزو شریفی', 'مینا شرفی', 'مهدیه', 'محمد گودینی', 'بهار خسروی',
                'سولماز نعیمی', 'فاطمه احمدخانی', 'فاطمه همتی'
            ],
            3: [  # XIMENT (زیمنت)
            ],
            4: [  # PEXOl (پکسول)
                'عباس پارنج', 'محدثه جعفریان', 'زهرا منوچهری', 'الهام ترابی'
            ],
            5: [  # RETRONA
            ],
        }
        emp_counter = 1
        seen_names = set()
        for brand_id, names in employees_by_brand.items():
            for name in names:
                if name in seen_names:
                    continue
                seen_names.add(name)
                username = f'emp{emp_counter}'
                c.execute(
                    "INSERT INTO users (name, username, password, role, brand_id) VALUES (?, ?, ?, 'employee', ?)",
                    (name, username, seed_hash, brand_id))
                emp_counter += 1

    # Backfill managers created in older versions where only users.brand_id was set.
    c.execute('''UPDATE brands SET manager_id=(SELECT u.id FROM users u
                 WHERE u.role='manager' AND u.brand_id=brands.id ORDER BY u.id LIMIT 1)
                 WHERE manager_id IS NULL AND EXISTS(
                 SELECT 1 FROM users u WHERE u.role='manager' AND u.brand_id=brands.id)''')
    for manager in c.execute("SELECT id FROM users WHERE role='manager'").fetchall():
        sync_manager_primary_brand(conn, manager['id'])
    c.execute("INSERT OR IGNORE INTO manager_access (user_id,level) SELECT id,1 FROM users WHERE role IN ('admin','manager')")
    task_columns_now = {r['name'] for r in c.execute('PRAGMA table_info(tasks)')}
    for column in ('category', 'subcategory', 'payment_order', 'sale_term'):
        if column not in task_columns_now:
            c.execute(f'ALTER TABLE tasks ADD COLUMN {column} TEXT')
    # زیردستهٔ موقت «مالیات و بیمه» به «مالیات» تبدیل می‌شود (حالا مالیات و بیمه جدا هستند)
    c.execute("UPDATE tasks SET subcategory='tax' WHERE category='finance' AND subcategory='tax_insurance'")
    # برندهای اضافهٔ سرپرست/کارشناس (برند اصلی همان users.brand_id می‌ماند)
    c.execute('''CREATE TABLE IF NOT EXISTS user_brands (user_id INTEGER NOT NULL, brand_id INTEGER NOT NULL,
        PRIMARY KEY(user_id, brand_id))''')
    c.execute(f'''CREATE VIEW IF NOT EXISTS {BRAND_MEMBERSHIP} AS
        SELECT id AS user_id, brand_id FROM users WHERE brand_id IS NOT NULL
        UNION SELECT user_id, brand_id FROM user_brands''')
    # Executive accounts are selected explicitly by configure_executives.py.
    conn.commit()
    conn.close()


def create_notification(user_id, title, message, type_='info', task_id=None, conn=None):
    """اگر conn داده شود از همان اتصال استفاده می‌کند تا database is locked نشود"""
    close_after = False
    if conn is None:
        conn = get_db()
        close_after = True
    c = conn.cursor()
    if task_id is not None:
        task = c.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        recipient = c.execute('SELECT id,role,brand_id,name FROM users WHERE id=?', (user_id,)).fetchone()
        if task and task['project_id'] is not None and (not recipient or not can_view_task(conn, task, recipient)):
            if close_after:
                conn.close()
            return
    c.execute('INSERT INTO notifications (user_id, title, message, type, task_id, created_at) VALUES (?,?,?,?,?,?)',
              (user_id, title, message, type_, task_id, int(datetime.now().timestamp() * 1000)))
    if close_after:
        conn.commit()
        conn.close()


REMINDER_DAYS = int(os.environ.get('TASK_REMINDER_DAYS', '3'))


def check_due_reminders():
    """هر روز یک‌بار به مسئولان تسک‌های بازی که حداکثر REMINDER_DAYS روز تا مهلتشان مانده یادآوری می‌فرستد."""
    today = date.today()
    today_iso = today.isoformat()
    last_day = (today + timedelta(days=REMINDER_DAYS)).isoformat()
    conn = get_db()
    try:
        rows = conn.execute('''SELECT id, title, due_date FROM tasks
            WHERE due_date IS NOT NULL AND due_date != '' AND due_date >= ? AND due_date <= ?
            AND status NOT IN ('done','rejected') AND (reminder_sent_on IS NULL OR reminder_sent_on != ?)''',
            (today_iso, last_day, today_iso)).fetchall()
        for task in rows:
            try:
                left = (date.fromisoformat(task['due_date'][:10]) - today).days
            except ValueError:
                continue
            when = 'امروز آخرین مهلت آن است' if left == 0 else ('فردا مهلت آن تمام می‌شود' if left == 1
                                                               else f'{left} روز تا پایان مهلت آن مانده است')
            for uid in get_task_assignees(conn, task['id']):
                create_notification(uid, '⏰ یادآوری مهلت تسک', f'تسک «{task["title"]}»: {when}.',
                                    'warning', task['id'], conn=conn)
            conn.execute('UPDATE tasks SET reminder_sent_on=? WHERE id=?', (today_iso, task['id']))
        conn.commit()
    finally:
        conn.close()


def check_overdue_tasks():
    conn = get_db()
    c = conn.cursor()
    today = datetime.now().strftime('%Y-%m-%d')
    c.execute("""SELECT t.*, b.name as brand_name 
                 FROM tasks t LEFT JOIN brands b ON t.brand_id = b.id
                 WHERE t.due_date != '' AND t.due_date < ? 
                 AND t.status NOT IN ('done','rejected') AND t.notified_overdue = 0""", (today,))
    for task in c.fetchall():
        ids = set(get_task_assignees(conn, task['id']))
        for aid in ids:
            create_notification(aid, '⚠️ تسک با تاخیر مواجه شده',
                                f'تسک "{task["title"]}" از موعد مقرر گذشته است.', 'warning', task['id'], conn=conn)
        c.execute('SELECT manager_id FROM brands WHERE id = ?', (task['brand_id'],))
        brand = c.fetchone()
        if brand and brand['manager_id'] and brand['manager_id'] not in ids:
            create_notification(brand['manager_id'], '⚠️ تسک تاخیردار در برند شما',
                                f'تسک "{task["title"]}" در حال تاخیر است.', 'warning', task['id'], conn=conn)
        c.execute('UPDATE tasks SET notified_overdue = 1 WHERE id = ?', (task['id'],))
    conn.commit()
    conn.close()


@app.route('/api/profile/<int:user_id>')
@login_required
def get_profile(user_id):
    me = current_user()
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'کاربر پیدا نشد'}), 404
    if user_id != me['id'] and not (has_permission(conn, me, 'view_staff') or
                                    has_permission(conn, me, 'view_analytics')):
        conn.close()
        return jsonify({'error': 'دسترسی مشاهده پروفایل فعال نیست'}), 403
    if me['role'] not in EXECUTIVE_ROLES and user_id != me['id'] and not (
            manages_user(conn, me, user) or supervisor_staff_scope(conn, me, user)):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    profile_scope = 'AND t.brand_id IN (SELECT id FROM brands WHERE manager_id=?)' if me['role'] == 'manager' and user_id != me['id'] else ''
    if me['role'] == 'supervisor' and user_id != me['id']:
        profile_scope = f'AND t.brand_id IN (SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)'
    counts = dict(conn.execute(f'''SELECT COUNT(*) total,
        COALESCE(SUM(CASE WHEN t.status='done' THEN 1 ELSE 0 END), 0) done
        FROM task_assignees ta JOIN tasks t ON t.id=ta.task_id WHERE ta.user_id=? {profile_scope}''',
        (user_id, me['id']) if profile_scope else (user_id,)).fetchone())
    profile = strip_password(user)
    profile['managed_brand_ids'] = sorted(managed_brand_ids(conn, user_id)) if user['role'] == 'manager' else []
    conn.close()
    return jsonify({'user': profile, 'stats': counts})


@app.route('/api/profile/me', methods=['POST'])
@login_required
def save_profile():
    data = request.json or {}
    name = str(data.get('name') or '').strip()
    if not name or len(name) > 120:
        return jsonify({'error': 'نام معتبر وارد کنید'}), 400
    phone = str(data.get('phone') or '').strip()
    bio = str(data.get('bio') or '').strip()
    if len(phone) > 40 or len(bio) > 1000:
        return jsonify({'error': 'اطلاعات پروفایل بیش از حد طولانی است'}), 400
    conn = get_db()
    me = conn.execute('SELECT * FROM users WHERE id=?', (current_user()['id'],)).fetchone()
    password = data.get('new_password') or ''
    if password:
        if not check_password_hash(me['password'], data.get('current_password') or ''):
            conn.close()
            return jsonify({'error': 'رمز فعلی نادرست است'}), 400
        if len(password) < 8:
            conn.close()
            return jsonify({'error': 'رمز جدید باید دست‌کم ۸ کاراکتر باشد'}), 400
        conn.execute('UPDATE users SET name=?, phone=?, bio=?, password=? WHERE id=?',
                     (name, phone, bio, generate_password_hash(password), me['id']))
    else:
        conn.execute('UPDATE users SET name=?, phone=?, bio=? WHERE id=?',
                     (name, phone, bio, me['id']))
    conn.commit()
    conn.close()
    session['name'] = name
    return jsonify({'success': True})


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    conn = get_db()
    task = conn.execute('''SELECT t.*, a.original_name AS attachment_name FROM task_attachments a
                           JOIN tasks t ON t.id=a.task_id WHERE a.filename=?''', (filename,)).fetchone()
    permitted = task is not None and can_view_task(conn, task, current_user())
    conn.close()
    if not permitted:
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if filename.rsplit('.', 1)[-1].lower() in HTML_EXTENSIONS:
        # فایل HTML آپلودی هرگز داخل خود برنامه باز نمی‌شود (جلوگیری از اجرای اسکریپت با نشست کاربر)؛
        # فقط دانلود می‌شود و کاربر آن را روی کامپیوتر خودش باز می‌کند.
        response = send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True,
                                       download_name=task['attachment_name'] or filename,
                                       mimetype='application/octet-stream')
        response.headers['Content-Security-Policy'] = 'sandbox'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'error': 'تعداد تلاش‌های ورود بیش از حد مجاز است. کمی بعد دوباره امتحان کنید.'}), 429


@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute', key_func=login_rate_key)
@limiter.limit('200 per minute')
def login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    role = data.get('role', '')
    conn = get_db()
    c = conn.cursor()
    if not executive_setup_done(conn):
        conn.close()
        return jsonify({'error': 'ابتدا حساب‌های مدیرعامل و Administrator را با configure_executives.py تنظیم کنید'}), 503
    c.execute('SELECT * FROM users WHERE username=? AND role=?', (username, role))
    user = c.fetchone()
    if user and check_password_hash(user['password'], password):
        session.clear()
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['brand_id'] = user['brand_id']
        session['department_id'] = user['department_id']
        session['name'] = user['name']
        session.permanent = True
        session['expires_at'] = int(time.time()) + 2 * 60 * 60
        result = public_user(conn, user, include_access=True)
        conn.close()
        return jsonify({'success': True, 'user': result})
    conn.close()
    return jsonify({'success': False, 'error': 'اطلاعات نادرست'})


@app.route('/api/session')
@login_required
def session_info():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    result = public_user(conn, user, include_access=True)
    conn.close()
    return jsonify({'success': True, 'user': result})


def parse_permission_selection(data):
    if not isinstance(data, dict):
        return None
    values = data.get('permissions')
    if not isinstance(values, dict) or set(values) != PERMISSION_KEYS or any(
            type(value) is not bool for value in values.values()):
        return None
    return values


@app.route('/api/access')
@roles_required(*SUPER_ROLES)
def list_access():
    conn = get_db()
    templates = {}
    for level in (1, 2, 3):
        enabled = {row['permission_key']: bool(row['enabled']) for row in conn.execute(
            'SELECT permission_key, enabled FROM access_level_permissions WHERE level=?', (level,))}
        templates[str(level)] = {key: enabled.get(key, False) for key in PERMISSION_KEYS}
    managers = []
    configured = {r['user_id'] for r in conn.execute('SELECT user_id FROM manager_access')}
    for row in conn.execute(f'''SELECT u.id,u.name,u.username,u.role,u.brand_id,b.name AS brand_name,d.name AS department_name
            FROM users u LEFT JOIN brands b ON b.id=u.brand_id LEFT JOIN departments d ON d.id=u.department_id
            WHERE u.role IN ({','.join('?' for _ in ACCESS_ROLES)}) ORDER BY u.role,u.name''', ACCESS_ROLES):
        level, permissions = permissions_for(conn, row)
        brands = row['brand_name']
        if row['role'] == 'manager':
            brands = '، '.join(r['name'] for r in conn.execute('SELECT name FROM brands WHERE manager_id=? ORDER BY id', (row['id'],))) or None
        managers.append({'id': row['id'], 'name': row['name'], 'username': row['username'],
                         'role': row['role'], 'level': level, 'permissions': permissions,
                         'configured': row['id'] in configured, 'brand_name': brands,
                         'department_name': row['department_name']})
    conn.close()
    return jsonify({'catalog': [{'key': key, 'label': label} for key, label in MANAGER_PERMISSIONS],
                    'levels': templates, 'managers': managers, 'roles': list(ACCESS_ROLES),
                    'locked': {role: sorted(keys) for role, keys in ROLE_LOCKED.items()}})


def apply_person_access(conn, user_id, level, values):
    """سطح و مجوزهای یک نفر را ذخیره می‌کند؛ مجوزهای قفل نقش همیشه خاموش ذخیره می‌شوند."""
    target = conn.execute('SELECT id,role FROM users WHERE id=?', (user_id,)).fetchone()
    values = {key: value and key not in ROLE_LOCKED.get(target['role'], ()) for key, value in values.items()}
    conn.execute('INSERT INTO manager_access (user_id,level) VALUES (?,?) '
                 'ON CONFLICT(user_id) DO UPDATE SET level=excluded.level', (user_id, level))
    conn.execute('DELETE FROM manager_permission_overrides WHERE user_id=?', (user_id,))
    template = {r['permission_key']: bool(r['enabled']) for r in conn.execute(
        'SELECT permission_key,enabled FROM access_level_permissions WHERE level=?', (level,))}
    conn.executemany('INSERT INTO manager_permission_overrides (user_id,permission_key,enabled) VALUES (?,?,?)',
                     [(user_id, key, int(value)) for key, value in values.items() if value != template.get(key, False)])
    conn.execute('INSERT INTO access_audit (actor_id,target_type,target_id,detail,created_at) VALUES (?,?,?,?,?)',
                 (current_user()['id'], 'manager', user_id,
                  f'level={level}; enabled=' + ','.join(sorted(key for key, value in values.items() if value)),
                  int(time.time() * 1000)))


@app.route('/api/access/roles/<role>', methods=['PUT'])
@roles_required(*SUPER_ROLES)
def update_role_access(role):
    """یک سطح و مجموعه مجوز را یک‌جا برای همهٔ افراد یک نقش ثبت می‌کند."""
    data = request.get_json(silent=True) or {}
    values = parse_permission_selection(data)
    level = data.get('level') if isinstance(data, dict) else None
    if role not in ACCESS_ROLES or type(level) is not int or level not in LEVEL_DEFAULTS or values is None:
        return jsonify({'error': 'نقش، سطح یا فهرست مجوزها نامعتبر است'}), 400
    conn = get_db()
    ids = [r['id'] for r in conn.execute('SELECT id FROM users WHERE role=?', (role,))]
    for user_id in ids:
        apply_person_access(conn, user_id, level, values)
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'count': len(ids)})


@app.route('/api/access/levels/<int:level>', methods=['PUT'])
@roles_required(*SUPER_ROLES)
def update_access_level(level):
    values = parse_permission_selection(request.get_json(silent=True) or {})
    if level not in LEVEL_DEFAULTS or values is None:
        return jsonify({'error': 'سطح یا فهرست مجوزها نامعتبر است'}), 400
    conn = get_db()
    conn.executemany('''UPDATE access_level_permissions SET enabled=? WHERE level=? AND permission_key=?''',
                     [(int(value), level, key) for key, value in values.items()])
    conn.execute('INSERT INTO access_audit (actor_id,target_type,target_id,detail,created_at) VALUES (?,?,?,?,?)',
                 (current_user()['id'], 'level', level, ','.join(sorted(key for key, value in values.items() if value)),
                  int(time.time() * 1000)))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/access/managers/<int:user_id>', methods=['PUT'])
@roles_required(*SUPER_ROLES)
def update_manager_access(user_id):
    data = request.get_json(silent=True) or {}
    values = parse_permission_selection(data)
    level = data.get('level') if isinstance(data, dict) else None
    if type(level) is not int or level not in LEVEL_DEFAULTS or values is None:
        return jsonify({'error': 'سطح یا فهرست مجوزها نامعتبر است'}), 400
    conn = get_db()
    target = conn.execute('SELECT id,role FROM users WHERE id=?', (user_id,)).fetchone()
    if not target or target['role'] not in ACCESS_ROLES:
        conn.close()
        return jsonify({'error': 'فقط دسترسی مدیرعامل، مدیر برند، سرپرست و کارشناس قابل تنظیم است'}), 400
    if any(values[key] for key in ROLE_LOCKED.get(target['role'], ())):
        conn.close()
        return jsonify({'error': 'یک یا چند مجوز انتخاب‌شده برای این نقش قابل فعال‌سازی نیست'}), 400
    apply_person_access(conn, user_id, level, values)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/roles')
def list_roles():
    conn = get_db()
    roles = [dict(r) for r in conn.execute('SELECT key, name, built_in FROM role_catalog ORDER BY built_in DESC, rowid')]
    conn.close()
    return jsonify(roles)


@app.route('/api/roles', methods=['POST'])
@permission_required('manage_roles')
def create_role():
    name = str((request.json or {}).get('name') or '').strip()
    if not name or len(name) > 80:
        return jsonify({'error': 'عنوان نقش باید بین ۱ تا ۸۰ کاراکتر باشد'}), 400
    conn = get_db()
    try:
        key = 'custom_' + uuid.uuid4().hex
        conn.execute('INSERT INTO role_catalog (key, name) VALUES (?,?)', (key, name))
        conn.commit()
        return jsonify({'success': True, 'key': key})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'این نقش قبلاً ثبت شده است'}), 400
    finally:
        conn.close()


@app.route('/api/roles/<key>', methods=['DELETE'])
@permission_required('manage_roles')
def remove_role(key):
    conn = get_db()
    try:
        role = conn.execute('SELECT built_in FROM role_catalog WHERE key=?', (key,)).fetchone()
        if not role:
            return jsonify({'error': 'نقش پیدا نشد'}), 404
        if role['built_in']:
            return jsonify({'error': 'نقش‌های اصلی قابل حذف نیستند'}), 403
        if conn.execute('SELECT 1 FROM users WHERE role=? LIMIT 1', (key,)).fetchone():
            return jsonify({'error': 'ابتدا نقش کاربران مرتبط را تغییر دهید'}), 409
        conn.execute('DELETE FROM role_catalog WHERE key=?', (key,))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/users')
@login_required
def get_users():
    conn = get_db()
    me = current_user()
    if not has_permission(conn, me, 'view_staff'):
        rows = conn.execute('SELECT * FROM users WHERE id=?', (me['id'],)).fetchall()
    elif me['role'] == 'manager':
        brands = managed_brand_ids(conn, me['id'])
        rows = conn.execute(f'''SELECT * FROM users WHERE id=? OR
            {member_of_brands_sql('users', '(SELECT id FROM brands WHERE manager_id=?)')}''',
                            (me['id'], me['id'])).fetchall() if brands else conn.execute(
                                'SELECT * FROM users WHERE id=?', (me['id'],)).fetchall()
    elif me['role'] == 'supervisor':
        rows = conn.execute(f'''SELECT * FROM users WHERE id=? OR
            (department_id=? AND ? IS NOT NULL AND
             {member_of_brands_sql('users', f'(SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)')})''',
            (me['id'], me['department_id'], me['department_id'], me['id'])).fetchall()
    else:
        rows = conn.execute('SELECT * FROM users').fetchall()
    users = [public_user(conn, r) for r in rows]
    conn.close()
    return jsonify(users)


@app.route('/api/task-recipients')
@login_required
def task_recipients():
    """Minimal directory for cross-brand assignment; the staff tab uses /api/users."""
    conn = get_db()
    recipients = [dict(row) for row in conn.execute(
        'SELECT id, name, role, brand_id FROM users ORDER BY name').fetchall()]
    conn.close()
    return jsonify(recipients)


@app.route('/api/users', methods=['POST'])
@login_required
def save_user():
    data = request.json or {}
    conn = get_db()
    c = conn.cursor()
    try:
        me = current_user()
        permission = 'edit_users' if data.get('id') else 'create_users'
        if not has_permission(conn, me, permission):
            return jsonify({'error': 'این دسترسی توسط Administrator فعال نشده است'}), 403
        if not data.get('name') or not data.get('username') or not data.get('role'):
            return jsonify({'success': False, 'error': 'نام، نام‌کاربری و نقش الزامی است'}), 400
        role = data['role']
        allowed_roles = SUPERVISOR_STAFF_ROLES if me['role'] == 'supervisor' else MANAGER_STAFF_ROLES
        if not is_super(me) and role not in allowed_roles:
            return jsonify({'error': 'فقط Administrator می‌تواند نقش‌های مدیریتی را نسبت دهد'}), 403
        if not c.execute('SELECT 1 FROM role_catalog WHERE key=?', (role,)).fetchone():
            return jsonify({'error': 'نقش نامعتبر است'}), 400
        brand_id, department_id = None, None
        if data.get('brand_id') not in (None, ''):
            try:
                brand_id = int(data.get('brand_id'))
            except (TypeError, ValueError):
                return jsonify({'error': 'برند معتبر انتخاب کنید'}), 400
            if not c.execute('SELECT 1 FROM brands WHERE id=?', (brand_id,)).fetchone():
                return jsonify({'error': 'برند پیدا نشد'}), 400
        manager_brands = []
        if role == 'manager':
            raw = data.get('managed_brand_ids', [brand_id] if brand_id else [])
            if not isinstance(raw, list) or not raw:
                return jsonify({'error': 'حداقل یک برند برای مدیر برند انتخاب کنید'}), 400
            try:
                manager_brands = list(dict.fromkeys(int(v) for v in raw))
            except (TypeError, ValueError):
                return jsonify({'error': 'برندهای مدیر نامعتبرند'}), 400
            if any(v <= 0 or not c.execute('SELECT 1 FROM brands WHERE id=?', (v,)).fetchone()
                   for v in manager_brands):
                return jsonify({'error': 'یکی از برندهای مدیر پیدا نشد'}), 400
            brand_id = min(manager_brands)
        if data.get('department_id') not in (None, ''):
            try:
                department_id = int(data.get('department_id'))
            except (TypeError, ValueError):
                return jsonify({'error': 'بخش کارمند را انتخاب کنید'}), 400
            if not c.execute('SELECT 1 FROM departments WHERE id=?', (department_id,)).fetchone():
                return jsonify({'error': 'بخش پیدا نشد'}), 400
        job_role_id = None  # Old brand-specific title is no longer used.
        if role in EXECUTIVE_ROLES:
            holder = c.execute('SELECT id FROM users WHERE role=? AND id!=?',
                               (role, data.get('id') or -1)).fetchone()
            if holder:
                return jsonify({'error': 'این دسترسی ارشد قبلاً به یک حساب اختصاص داده شده است'}), 409
        if data.get('id'):
            old_user = c.execute('SELECT id,role,brand_id,department_id FROM users WHERE id=?', (data['id'],)).fetchone()
            if not old_user:
                return jsonify({'error': 'کاربر پیدا نشد'}), 404
            if old_user['role'] == 'administrator' and role != 'administrator':
                return jsonify({'error': 'نقش حساب Administrator قابل تغییر نیست'}), 403
            if old_user['role'] == 'administrator' and me['role'] != 'administrator':
                return jsonify({'error': 'حساب Administrator فقط توسط خود Administrator قابل تغییر است'}), 403
            if not is_super(me) and old_user['role'] not in MANAGER_STAFF_ROLES:
                return jsonify({'error': 'فقط Administrator می‌تواند حساب مدیران را تغییر دهد'}), 403
            if data.get('password') and not is_super(me) and not has_permission(conn, me, 'reset_passwords'):
                return jsonify({'error': 'بازنشانی رمز این کاربر مجاز نیست'}), 403
            if me['role'] == 'manager' and (not manager_staff_target_allowed(conn, me, old_user) or
                                           brand_id not in managed_brand_ids(conn, me['id'])):
                return jsonify({'error': 'فقط کارکنان برندهای خود را می‌توانید ویرایش کنید'}), 403
            if me['role'] == 'supervisor' and (not supervisor_staff_scope(conn, me, old_user) or
                    old_user['role'] not in SUPERVISOR_STAFF_ROLES or
                    brand_id not in user_brand_ids(conn, me['id']) or department_id != me['department_id']):
                return jsonify({'error': 'فقط کارکنان بخش و برند خود را می‌توانید ویرایش کنید'}), 403
            if data.get('password'):
                c.execute('UPDATE users SET name=?, username=?, password=?, role=?, brand_id=?, department_id=?, job_role_id=? WHERE id=?',
                          (data['name'], data['username'], generate_password_hash(data['password']),
                           role, brand_id, department_id, job_role_id, data['id']))
            else:
                c.execute('UPDATE users SET name=?, username=?, role=?, brand_id=?, department_id=?, job_role_id=? WHERE id=?',
                          (data['name'], data['username'], role, brand_id, department_id, job_role_id, data['id']))
        else:
            if me['role'] == 'manager' and brand_id not in managed_brand_ids(conn, me['id']):
                return jsonify({'error': 'فقط برای برندهای خود می‌توانید کاربر بسازید'}), 403
            if me['role'] == 'supervisor' and (brand_id not in user_brand_ids(conn, me['id']) or
                    department_id != me['department_id'] or brand_id is None or department_id is None):
                return jsonify({'error': 'فقط برای بخش و برند خود می‌توانید کاربر بسازید'}), 403
            if not data.get('password'):
                return jsonify({'success': False, 'error': 'رمز عبور الزامی است'}), 400
            new_row = c.execute('INSERT INTO users (name, username, password, role, brand_id, department_id, job_role_id) VALUES (?,?,?,?,?,?,?)',
                      (data['name'], data['username'], generate_password_hash(data['password']),
                       role, brand_id, department_id, job_role_id))
        user_id = int(data.get('id') or new_row.lastrowid)
        if data.get('id') and old_user['role'] != role:
            c.execute('DELETE FROM manager_permission_overrides WHERE user_id=?', (user_id,))
            c.execute('DELETE FROM manager_access WHERE user_id=?', (user_id,))
        displaced = {r['manager_id'] for r in c.execute(
            f"SELECT manager_id FROM brands WHERE id IN ({','.join('?' * len(manager_brands))}) AND manager_id IS NOT NULL",
            manager_brands).fetchall()} if manager_brands else set()
        c.execute('UPDATE brands SET manager_id=NULL WHERE manager_id=?', (user_id,))
        for selected_id in manager_brands:
            c.execute('UPDATE brands SET manager_id=? WHERE id=?', (user_id, selected_id))
        for previous_id in displaced | {user_id}:
            sync_manager_primary_brand(conn, previous_id)
        # برندهای اضافهٔ سرپرست/کارشناس فقط توسط Administrator تعیین می‌شود
        if role not in MULTI_BRAND_ROLES:
            c.execute('DELETE FROM user_brands WHERE user_id=?', (user_id,))
        elif is_super(me) and 'extra_brand_ids' in data:
            raw_extra = data.get('extra_brand_ids') or []
            try:
                extra = {int(v) for v in raw_extra} if isinstance(raw_extra, list) else None
            except (TypeError, ValueError):
                extra = None
            if extra is None or any(not c.execute('SELECT 1 FROM brands WHERE id=?', (v,)).fetchone() for v in extra):
                conn.rollback()
                return jsonify({'error': 'برندهای اضافه نامعتبرند'}), 400
            extra.discard(brand_id)
            c.execute('DELETE FROM user_brands WHERE user_id=?', (user_id,))
            c.executemany('INSERT INTO user_brands (user_id, brand_id) VALUES (?,?)', [(user_id, v) for v in sorted(extra)])
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'این نام‌کاربری قبلاً استفاده شده'}), 400
    finally:
        conn.close()
    return jsonify({'success': True})


@app.route('/api/users/<int:id>', methods=['DELETE'])
@permission_required('delete_users')
def delete_user(id):
    me = current_user()
    conn = get_db()
    if id == me['id']:
        conn.close()
        return jsonify({'error': 'حذف حساب خودتان مجاز نیست'}), 403
    target = conn.execute('SELECT id, role, brand_id, department_id FROM users WHERE id=?', (id,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error': 'کاربر پیدا نشد'}), 404
    if me['role'] == 'manager' and not manager_staff_target_allowed(conn, me, target):
        conn.close()
        return jsonify({'error': 'فقط اعضای برندهای خود با نقش سرپرست، کارشناس یا کارمند را می‌توانید حذف کنید'}), 403
    if me['role'] == 'supervisor' and (target['role'] not in SUPERVISOR_STAFF_ROLES or
            not supervisor_staff_scope(conn, me, target)):
        conn.close()
        return jsonify({'error': 'فقط کارکنان بخش و برند خود را می‌توانید حذف کنید'}), 403
    if target and target['role'] in MANAGEMENT_ROLES and not is_super(me):
        conn.close()
        return jsonify({'error': 'فقط Administrator می‌تواند حساب مدیران را حذف کند'}), 403
    if target and target['role'] == 'administrator':
        conn.close()
        return jsonify({'error': 'حذف حساب Administrator مجاز نیست'}), 403
    if has_project_responsibility(conn, id):
        conn.close()
        return jsonify({'error': 'این حساب سازنده پروژه یا مسئول یکی از تسک‌های پروژه است و حذف آن روند را ناقص می‌کند'}), 409
    conn.execute('UPDATE brands SET manager_id=NULL WHERE manager_id=?', (id,))
    conn.execute('DELETE FROM users WHERE id=?', (id,))
    conn.commit();
    conn.close()
    return jsonify({'success': True})


def staff_actor(conn):
    """دسترسی مدیریت کارکنان را از رکورد زنده، نه ادعای کلاینت، بخوان."""
    actor = conn.execute('SELECT id, role, brand_id, department_id, staff_admin FROM users WHERE id=?',
                         (current_user()['id'],)).fetchone()
    if actor and actor['role'] in MANAGEMENT_ROLES | {'supervisor'}:
        return actor
    return None


def manager_staff_target_allowed(conn, actor, target):
    return (actor['role'] == 'manager' and target['id'] != actor['id'] and
            target['role'] in MANAGER_STAFF_ROLES and manages_user(conn, actor, target))


def has_project_responsibility(conn, user_id):
    return bool(conn.execute('''SELECT 1 FROM projects WHERE creator_id=?
        UNION SELECT 1 FROM task_assignees ta JOIN tasks t ON t.id=ta.task_id
            WHERE t.project_id IS NOT NULL AND ta.user_id=? LIMIT 1''', (user_id, user_id)).fetchone())


def staff_target_allowed(conn, actor, target, password_reset=False):
    if is_super(actor):
        # مدیرعامل همه را مدیریت می‌کند به‌جز حساب Administrator
        return target['id'] != actor['id'] and (target['role'] != 'administrator' or actor['role'] == 'administrator')
    if actor['role'] == 'admin':
        return target['role'] not in MANAGEMENT_ROLES
    if actor['role'] == 'supervisor':
        return target['role'] in SUPERVISOR_STAFF_ROLES and supervisor_staff_scope(conn, actor, target)
    return target['role'] in MANAGER_STAFF_ROLES


@app.route('/api/staff')
@login_required
def list_staff():
    conn = get_db()
    actor = staff_actor(conn)
    if not actor or not has_permission(conn, actor, 'view_staff'):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if actor['role'] == 'manager':
        rows = conn.execute(f'''SELECT * FROM users WHERE id=? OR
            {member_of_brands_sql('users', '(SELECT id FROM brands WHERE manager_id=?)')} ORDER BY role, name''',
            (actor['id'], actor['id'])).fetchall()
    elif actor['role'] == 'supervisor':
        rows = conn.execute(f'''SELECT * FROM users WHERE id=? OR (department_id=? AND ? IS NOT NULL AND
            {member_of_brands_sql('users', f'(SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)')}) ORDER BY role,name''',
            (actor['id'], actor['department_id'], actor['department_id'], actor['id'])).fetchall()
    else:
        rows = conn.execute('SELECT * FROM users ORDER BY role, name').fetchall()
    users = [strip_password(row) for row in rows]
    conn.close()
    return jsonify({'users': users, 'can_reset_all': is_super(actor)})


@app.route('/api/staff', methods=['POST'])
@login_required
def create_staff():
    data = request.json or {}
    name, username = str(data.get('name') or '').strip(), str(data.get('username') or '').strip()
    conn = get_db()
    actor = staff_actor(conn)
    if not actor or not has_permission(conn, actor, 'create_users'):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if not name or not username or len(name) > 120 or len(username) > 80:
        conn.close()
        return jsonify({'error': 'نام و نام کاربری معتبر الزامی است'}), 400
    role = str(data.get('role') or 'employee')
    if not conn.execute('SELECT 1 FROM role_catalog WHERE key=?', (role,)).fetchone():
        conn.close()
        return jsonify({'error': 'نقش نامعتبر است'}), 400
    if actor['role'] == 'supervisor' and role not in SUPERVISOR_STAFF_ROLES:
        conn.close()
        return jsonify({'error': 'سرپرست فقط می‌تواند کارشناس یا کارمند اضافه کند'}), 403
    if actor['role'] == 'manager' and role not in MANAGER_STAFF_ROLES:
        conn.close()
        return jsonify({'error': 'مدیر برند فقط می‌تواند سرپرست، کارشناس یا کارمند اضافه کند'}), 403
    if not is_super(actor) and role not in MANAGER_STAFF_ROLES:
        conn.close()
        return jsonify({'error': 'فقط Administrator می‌تواند مدیر جدید بسازد'}), 403
    brand_id, department_id = None, None
    if data.get('brand_id') not in (None, ''):
        try:
            brand_id = int(data.get('brand_id'))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error': 'برند معتبر انتخاب کنید'}), 400
        if not conn.execute('SELECT 1 FROM brands WHERE id=?', (brand_id,)).fetchone():
            conn.close()
            return jsonify({'error': 'برند پیدا نشد'}), 400
    if actor['role'] == 'manager' and brand_id not in managed_brand_ids(conn, actor['id']):
        conn.close()
        return jsonify({'error': 'فقط یکی از برندهای تحت مدیریت خود را انتخاب کنید'}), 403
    if actor['role'] == 'supervisor' and (brand_id is None or brand_id not in user_brand_ids(conn, actor['id'])):
        conn.close()
        return jsonify({'error': 'فقط برند خود را انتخاب کنید'}), 403
    manager_brands = []
    if role == 'manager':
        raw = data.get('managed_brand_ids', [brand_id] if brand_id else [])
        if not isinstance(raw, list) or not raw:
            conn.close()
            return jsonify({'error': 'حداقل یک برند برای مدیر برند انتخاب کنید'}), 400
        try:
            manager_brands = list(dict.fromkeys(int(v) for v in raw))
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'error': 'برندهای مدیر نامعتبرند'}), 400
        if any(v <= 0 or not conn.execute('SELECT 1 FROM brands WHERE id=?', (v,)).fetchone()
               for v in manager_brands):
            conn.close()
            return jsonify({'error': 'یکی از برندهای مدیر پیدا نشد'}), 400
        brand_id = min(manager_brands)
    if data.get('department_id') not in (None, ''):
        try:
            department_id = int(data.get('department_id'))
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error': 'بخش کارمند را انتخاب کنید'}), 400
        if not conn.execute('SELECT 1 FROM departments WHERE id=?', (department_id,)).fetchone():
            conn.close()
            return jsonify({'error': 'بخش پیدا نشد'}), 400
    if actor['role'] == 'supervisor' and (department_id is None or department_id != actor['department_id']):
        conn.close()
        return jsonify({'error': 'فقط بخش خود را انتخاب کنید'}), 403
    job_role_id = None
    if role in EXECUTIVE_ROLES and conn.execute('SELECT 1 FROM users WHERE role=?', (role,)).fetchone():
        conn.close()
        return jsonify({'error': 'این دسترسی ارشد قبلاً به یک حساب اختصاص داده شده است'}), 409
    password = str(data.get('password') or '') or secrets.token_urlsafe(12)
    if len(password) < 8:
        conn.close()
        return jsonify({'error': 'رمز باید حداقل ۸ کاراکتر باشد'}), 400
    try:
        c = conn.execute('INSERT INTO users (name,username,password,role,brand_id,department_id,job_role_id) VALUES (?,?,?,?,?,?,?)',
                         (name, username, generate_password_hash(password), role, brand_id, department_id, job_role_id))
        user_id = c.lastrowid
        displaced = {r['manager_id'] for r in conn.execute(
            f"SELECT manager_id FROM brands WHERE id IN ({','.join('?' * len(manager_brands))}) AND manager_id IS NOT NULL",
            manager_brands).fetchall()} if manager_brands else set()
        for selected_id in manager_brands:
            conn.execute('UPDATE brands SET manager_id=? WHERE id=?', (user_id, selected_id))
        for previous_id in displaced | {user_id}:
            sync_manager_primary_brand(conn, previous_id)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'این نام کاربری قبلاً استفاده شده است'}), 400
    conn.close()
    response = jsonify({'success': True, 'user_id': user_id, 'new_password': password})
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/api/staff/<int:id>', methods=['DELETE'])
@login_required
def remove_staff(id):
    conn = get_db()
    actor = staff_actor(conn)
    target = conn.execute('SELECT id, role, brand_id, department_id, staff_admin FROM users WHERE id=?', (id,)).fetchone()
    if (not actor or not has_permission(conn, actor, 'delete_users') or not target or
            (target['role'] in MANAGEMENT_ROLES and not is_super(actor)) or
            target['role'] == 'administrator' or (
            actor['role'] == 'manager' and not manager_staff_target_allowed(conn, actor, target)) or
            (actor['role'] == 'supervisor' and not staff_target_allowed(conn, actor, target))):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز یا کاربر پیدا نشد'}), 403
    if id == actor['id']:
        conn.close()
        return jsonify({'error': 'حذف این حساب مجاز نیست'}), 403
    if has_project_responsibility(conn, id):
        conn.close()
        return jsonify({'error': 'این حساب سازنده پروژه یا مسئول یکی از تسک‌های پروژه است و حذف آن روند را ناقص می‌کند'}), 409
    conn.execute('UPDATE brands SET manager_id=NULL WHERE manager_id=?', (id,))
    conn.execute('DELETE FROM users WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/staff/<int:id>/password', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def reset_staff_password(id):
    conn = get_db()
    actor = staff_actor(conn)
    target = conn.execute('SELECT id, role, brand_id, department_id FROM users WHERE id=?', (id,)).fetchone()
    if not actor or not has_permission(conn, actor, 'reset_passwords') or not target or not staff_target_allowed(conn, actor, target, password_reset=True) or (
            actor['role'] == 'manager' and not manager_staff_target_allowed(conn, actor, target)):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز یا کاربر پیدا نشد'}), 403
    password = str((request.json or {}).get('password') or '') or secrets.token_urlsafe(12)
    if len(password) < 8:
        conn.close()
        return jsonify({'error': 'رمز باید حداقل ۸ کاراکتر باشد'}), 400
    conn.execute('UPDATE users SET password=? WHERE id=?', (generate_password_hash(password), id))
    conn.commit()
    conn.close()
    response = jsonify({'success': True, 'new_password': password})
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/api/brands')
@login_required
def get_brands():
    conn = get_db()
    brands = [dict(r) for r in conn.execute('SELECT * FROM brands').fetchall()]
    conn.close()
    return jsonify(brands)


@app.route('/api/brands', methods=['POST'])
@permission_required('manage_brands')
def save_brand():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'success': False, 'error': 'نام برند الزامی است'}), 400
    conn = get_db()
    c = conn.cursor()
    manager_id = data.get('manager_id') or None
    me = current_user()
    if me['role'] == 'manager':
        try:
            brand_id = int(data['id']) if data.get('id') else None
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'error': 'شناسه برند نامعتبر است'}), 400
        if brand_id and not manages_brand(conn, me, brand_id):
            conn.close()
            return jsonify({'error': 'فقط برندهای خود را می‌توانید تغییر دهید'}), 403
        manager_id = me['id']
    if manager_id is not None:
        manager = c.execute("SELECT id FROM users WHERE id=? AND role IN ('manager','admin','administrator')",
                            (manager_id,)).fetchone()
        if not manager:
            conn.close()
            return jsonify({'error': 'مدیر برند معتبر انتخاب کنید'}), 400
    previous = c.execute('SELECT manager_id FROM brands WHERE id=?', (data.get('id'),)).fetchone() if data.get('id') else None
    if data.get('id'):
        c.execute('UPDATE brands SET name=?, manager_id=?, color=? WHERE id=?',
                  (data['name'], manager_id, data.get('color', '#3498db'), data['id']))
    else:
        c.execute('INSERT INTO brands (name, manager_id, color) VALUES (?,?,?)',
                  (data['name'], manager_id, data.get('color', '#3498db')))
    for manager_id_to_sync in {manager_id, previous['manager_id'] if previous else None} - {None}:
        sync_manager_primary_brand(conn, manager_id_to_sync)
    conn.commit();
    conn.close()
    return jsonify({'success': True})


@app.route('/api/brands/<int:id>', methods=['DELETE'])
@permission_required('manage_brands')
def delete_brand(id):
    conn = get_db()
    me = current_user()
    if me['role'] == 'manager' and not manages_brand(conn, me, id):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if conn.execute('SELECT 1 FROM users WHERE brand_id=? LIMIT 1', (id,)).fetchone() or \
       conn.execute('SELECT 1 FROM tasks WHERE brand_id=? LIMIT 1', (id,)).fetchone() or \
       conn.execute('SELECT 1 FROM job_roles WHERE brand_id=? LIMIT 1', (id,)).fetchone():
        conn.close()
        return jsonify({'error': 'برای حذف برند، ابتدا کاربران، تسک‌ها و نقش‌های مرتبط را منتقل یا حذف کنید'}), 409
    conn.execute('DELETE FROM brands WHERE id=?', (id,))
    conn.commit();
    conn.close()
    return jsonify({'success': True})


@app.route('/api/departments')
@login_required
def get_departments():
    conn = get_db()
    departments = [dict(r) for r in conn.execute('SELECT * FROM departments ORDER BY id')]
    conn.close()
    return jsonify(departments)


@app.route('/api/departments', methods=['POST'])
@permission_required('manage_departments')
def create_department():
    name = str((request.json or {}).get('name') or '').strip()
    if not name or len(name) > 80:
        return jsonify({'error': 'نام بخش معتبر وارد کنید'}), 400
    conn = get_db()
    try:
        cursor = conn.execute('INSERT INTO departments (name) VALUES (?)', (name,))
        conn.commit()
        return jsonify({'success': True, 'id': cursor.lastrowid})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'این بخش قبلاً ثبت شده است'}), 400
    finally:
        conn.close()


@app.route('/api/departments/<int:id>', methods=['DELETE'])
@permission_required('manage_departments')
def delete_department(id):
    conn = get_db()
    if conn.execute('SELECT 1 FROM users WHERE department_id=? LIMIT 1', (id,)).fetchone():
        conn.close()
        return jsonify({'error': 'این بخش کارمند دارد؛ ابتدا بخش کارمندان را تغییر دهید'}), 409
    conn.execute('DELETE FROM departments WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


def visible_task_rows(conn, me):
    c = conn.cursor()
    if is_super(me) or (me['role'] == 'admin' and has_permission(conn, me, 'view_all_tasks')):
        return c.execute('SELECT t.* FROM tasks t ORDER BY t.created_at DESC').fetchall()
    return c.execute(f'''SELECT t.* FROM tasks t WHERE t.creator_id=? OR
        EXISTS(SELECT 1 FROM task_forwards tf WHERE tf.task_id=t.id AND tf.from_user_id=?) OR
        EXISTS(SELECT 1 FROM task_shares ts WHERE ts.task_id=t.id AND ts.to_user_id=?) OR
        EXISTS(SELECT 1 FROM task_assignees ta WHERE ta.task_id=t.id AND ta.user_id=?) OR
        EXISTS(SELECT 1 FROM task_observers ob WHERE ob.task_id=t.id AND ob.user_id=?) OR
        (t.project_id IS NOT NULL AND EXISTS(
            SELECT 1 FROM task_comment_mentions m JOIN task_comments tc ON tc.id=m.comment_id
            WHERE tc.task_id=t.id AND m.user_id=?)) OR
        (t.project_id IS NULL AND ?='manager' AND ?=1 AND t.brand_id IN
            (SELECT id FROM brands WHERE manager_id=?)) OR
        (?='manager' AND ?=1 AND t.project_id IS NOT NULL AND t.brand_id IN
            (SELECT id FROM brands WHERE manager_id=?) AND EXISTS (
                SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
                WHERE ta.task_id=t.id AND {member_of_brand_sql('u', 't.brand_id')}
                AND u.role IN ('supervisor','specialist','employee'))) OR
        (t.project_id IS NULL AND ?='supervisor' AND ?=1 AND ? IS NOT NULL
            AND t.brand_id IN (SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)
            AND (EXISTS(SELECT 1 FROM users u WHERE u.id=t.creator_id
                AND u.department_id=? AND {member_of_brand_sql('u', 't.brand_id')}) OR EXISTS(
                SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
                WHERE ta.task_id=t.id AND u.department_id=? AND {member_of_brand_sql('u', 't.brand_id')})))
        ORDER BY t.created_at DESC''',
        (me['id'], me['id'], me['id'], me['id'], me['id'], me['id'], me['role'],
         int(has_permission(conn, me, 'view_brand_tasks')), me['id'], me['role'],
         int(has_permission(conn, me, 'view_brand_tasks')), me['id'], me['role'],
         int(has_permission(conn, me, 'view_brand_tasks')), me['department_id'], me['id'],
         me['department_id'], me['department_id'])).fetchall()


def dashboard_scope(conn, me):
    """Return task and project IDs allowed on this manager's dashboard."""
    if me['role'] != 'manager':
        return None
    brands = managed_brand_ids(conn, me['id'])
    if not brands:
        return {'task_ids': [], 'project_ids': []}
    placeholders = ','.join('?' for _ in brands)
    brand_params = sorted(brands)
    subordinate = f'''({member_of_brands_sql('u', f'({placeholders})')} AND
        u.role IN ('supervisor','specialist','employee'))'''
    task_rows = conn.execute(f'''SELECT DISTINCT t.id, t.project_id FROM tasks t
        WHERE t.brand_id IN ({placeholders})
        AND (EXISTS (SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
                    WHERE ta.task_id=t.id AND (u.id=? OR {subordinate}))
             OR EXISTS (SELECT 1 FROM task_observers ob WHERE ob.task_id=t.id AND ob.user_id=?))''',
        brand_params + [me['id']] + brand_params + [me['id']]).fetchall()
    visible_ids = {row['id'] for row in visible_task_rows(conn, me)}
    task_ids = sorted(row['id'] for row in task_rows if row['id'] in visible_ids)
    scoped_task_ids = set(task_ids)
    project_ids = {row['project_id'] for row in task_rows
                   if row['id'] in scoped_task_ids and row['project_id'] is not None}
    # An empty project created by the manager belongs to the dashboard only
    # when its other members are staff in a managed brand.
    empty = conn.execute(f'''SELECT p.id FROM projects p WHERE p.creator_id=?
        AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.project_id=p.id)
        AND NOT EXISTS (SELECT 1 FROM project_members pm JOIN users u ON u.id=pm.user_id
                        WHERE pm.project_id=p.id AND u.id!=?
                        AND NOT {subordinate})''',
        [me['id'], me['id']] + brand_params).fetchall()
    project_ids.update(row['id'] for row in empty)
    return {'task_ids': task_ids, 'project_ids': sorted(project_ids)}


@app.route('/api/dashboard-scope')
@login_required
def get_dashboard_scope():
    conn = get_db()
    try:
        return jsonify(dashboard_scope(conn, current_user()))
    finally:
        conn.close()


# برندهایی که پروژه می‌گیرند و زیرگروه‌های مجاز هرکدام (نام برند بدون حساسیت به حروف بزرگ/کوچک)
PROJECT_BRAND_RULES = (
    ('vta', ('trade', 'importing', 'production', 'rnd')),
    ('leepica', ('trade', 'importing', 'production', 'rnd')),
    ('retrona', ('trade', 'importing', 'production', 'rnd')),
    ('ximent', ('trade', 'importing', 'rnd')),
    ('pexol', ('trade', 'importing', 'rnd')),
    ('eryxol', ('trade', 'importing', 'rnd')),
    ('xyland', ('trade', 'importing', 'rnd')),
)
PROJECT_CATEGORY_LABELS = {'trade': 'بازرگانی', 'importing': 'بازرگانی در حال واردات', 'production': 'تولیدی',
                           'rnd': 'تحقیق و توسعه', 'other': 'سایر پروژه‌ها'}
# روال پروژه‌های تولیدی VTA (به ترتیب)
PRODUCTION_STAGES = ('غذا و دارو', 'اداره تجهیزات', 'دانشگاه علوم پزشکی', 'آزمون‌های محصول', 'اداره استاندارد', 'ایزو')
PRODUCTION_FLOW_BRANDS = ('vta',)
# روال پروژه‌های بازرگانی (به ترتیب)
TRADE_STAGES = ('پیش‌پرداخت', 'بالانس', 'حمل', 'ترخیص کشتیرانی', 'ترخیص گمرک', 'رفع تعهد', 'بازبینی گمرک')
# موارد «دارد/ندارد» روال بازرگانی؛ اگر «دارد» باشد انجام شده/نشده هم ثبت می‌شود
TRADE_OPTIONAL_ITEMS = (('insurance', 'بیمه'), ('standard', 'استاندارد اجباری'), ('inspection', 'بازرسی'))


TRADE_WORKFLOW_CATEGORIES = ('trade', 'importing')


def trade_workflow_allowed(project):
    """روال بازرگانی برای زیرگروه‌های «بازرگانی» و «بازرگانی در حال واردات»."""
    return project['category'] in TRADE_WORKFLOW_CATEGORIES


# ساخت پروژه: Administrator همیشه؛ بقیهٔ نقش‌ها با مجوز «ایجاد پروژه» که Administrator می‌دهد.
PROJECT_CREATOR_ROLES = ('administrator',) + ACCESS_ROLES


def project_brand_options(conn, me):
    """برندهای قابل انتخاب برای پروژه به ترتیب ثابت، با زیرگروه‌های مجاز؛ مدیر برند فقط برندهای خودش."""
    brands = {r['name'].strip().lower(): r for r in conn.execute('SELECT id, name FROM brands')}
    if me['role'] == 'manager':
        own = managed_brand_ids(conn, me['id'])
    elif me['role'] in ('supervisor', 'specialist'):
        own = user_brand_ids(conn, me['id'])
    else:
        own = None
    options = []
    for key, categories in PROJECT_BRAND_RULES:
        row = brands.get(key)
        if row and (own is None or row['id'] in own):
            options.append({'brand_id': row['id'], 'name': row['name'], 'categories': list(categories)})
    return options


def can_create_project(conn, me):
    if is_super(me):
        return True
    return me['role'] in PROJECT_CREATOR_ROLES and has_permission(conn, me, 'create_projects')


def can_edit_project(conn, me, project):
    """پروژهٔ خود با «ویرایش پروژهٔ خود»؛ پروژهٔ دیگران با «ویرایش پروژه‌های دیگران» در محدودهٔ دسترسی."""
    if is_super(me):
        return True
    if project['creator_id'] == me['id']:
        return has_permission(conn, me, 'edit_own_projects')
    if not has_permission(conn, me, 'edit_projects'):
        return False
    if me['role'] == 'admin':
        return True
    return is_project_member(conn, project['id'], me['id']) or bool(
        project['brand_id'] and manages_brand(conn, me, project['brand_id']))


def can_delete_project(conn, me, project):
    if is_super(me):
        return True
    if not has_permission(conn, me, 'delete_projects'):
        return False
    return me['role'] == 'admin' or project['creator_id'] == me['id']


def validate_project_category(conn, me, data):
    """(brand_id, category, error) — category یکی از trade/production/other."""
    category = str(data.get('category') or '').strip()
    if category == 'other':
        return None, 'other', None
    try:
        brand_id = int(data.get('brand_id'))
    except (TypeError, ValueError):
        return None, None, 'برند پروژه را انتخاب کنید'
    viewer = me if not is_super(me) else {**me, 'role': 'admin'}
    option = next((o for o in project_brand_options(conn, viewer) if o['brand_id'] == brand_id), None)
    if not option:
        return None, None, 'این برند برای پروژه مجاز نیست یا تحت مدیریت شما نیست'
    if category not in option['categories']:
        return None, None, 'زیرگروه انتخاب‌شده برای این برند مجاز نیست'
    return brand_id, category, None


@app.route('/api/projects/<int:project_id>/trade-status', methods=['PUT'])
@login_required
def update_trade_status(project_id):
    """فقط سازندهٔ پروژه (و Administrator) مراحل روال بازرگانی را ثبت می‌کند."""
    data = request.get_json(silent=True) or {}
    me = current_user()
    conn = get_db()
    try:
        project = conn.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
        if not project:
            return jsonify({'error': 'پروژه پیدا نشد'}), 404
        if not trade_workflow_allowed(project):
            return jsonify({'error': 'روال بازرگانی فقط برای پروژه‌های بازرگانی و بازرگانی در حال واردات است'}), 400
        if not is_super(me) and project['creator_id'] != me['id']:
            return jsonify({'error': 'فقط سازندهٔ پروژه یا Administrator می‌تواند مراحل را ثبت کند'}), 403

        def flag(key, current, allow_none=False):
            if key not in data:
                return current
            value = data[key]
            if value is None and allow_none:
                return None
            if value in (True, False, 0, 1):
                return int(bool(value))
            raise ValueError(key)
        values = {}
        try:
            stage = project['trade_stage'] or 0
            if 'trade_stage' in data:
                stage = data['trade_stage']
                if isinstance(stage, bool) or not isinstance(stage, int) or not 0 <= stage <= len(TRADE_STAGES):
                    raise ValueError('trade_stage')
            values['trade_stage'] = stage
            values['fx_done'] = flag('fx_done', project['fx_done'] or 0)
            for key, _label in TRADE_OPTIONAL_ITEMS:
                required = flag(key + '_required', project[key + '_required'], allow_none=True)
                done = flag(key + '_done', project[key + '_done'] or 0)
                values[key + '_required'] = required
                values[key + '_done'] = done if required == 1 else 0
        except ValueError:
            return jsonify({'error': 'مقادیر روال بازرگانی نامعتبرند'}), 400
        changes = []
        if stage != (project['trade_stage'] or 0):
            changes.append('مرحله: ' + (TRADE_STAGES[stage - 1] + ' انجام شد' if stage else 'شروع نشده'))
        if values['fx_done'] != (project['fx_done'] or 0):
            changes.append('خرید ارز: ' + ('انجام شد' if values['fx_done'] else 'انجام نشده'))
        for key, label in TRADE_OPTIONAL_ITEMS:
            required, done = values[key + '_required'], values[key + '_done']
            if required != project[key + '_required'] or done != (project[key + '_done'] or 0):
                changes.append(f'{label}: ' + ('ندارد' if required == 0 else 'نامشخص' if required is None
                                                else ('انجام شد' if done else 'دارد، انجام نشده')))
        columns = list(values)
        conn.execute(f"UPDATE projects SET {', '.join(c + '=?' for c in columns)} WHERE id=?",
                     [values[c] for c in columns] + [project_id])
        if changes:
            project_event(conn, project_id, None, me['id'], 'trade_status', 'روال بازرگانی — ' + '، '.join(changes))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


def production_flow_brand_ids(conn):
    return [r['id'] for r in conn.execute('SELECT id, name FROM brands') if r['name'].strip().lower() in PRODUCTION_FLOW_BRANDS]


@app.route('/api/projects/<int:project_id>/production-status', methods=['PUT'])
@login_required
def update_production_status(project_id):
    """روال پروژه‌های تولیدی VTA؛ مثل روال بازرگانی، فقط سازندهٔ پروژه (و Administrator) ثبت می‌کند."""
    data = request.get_json(silent=True) or {}
    me = current_user()
    conn = get_db()
    try:
        project = conn.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
        if not project:
            return jsonify({'error': 'پروژه پیدا نشد'}), 404
        if project['category'] != 'production' or project['brand_id'] not in production_flow_brand_ids(conn):
            return jsonify({'error': 'روال تولید فقط برای پروژه‌های تولیدی VTA است'}), 400
        if not is_super(me) and project['creator_id'] != me['id']:
            return jsonify({'error': 'فقط سازندهٔ پروژه یا Administrator می‌تواند مراحل را ثبت کند'}), 403
        stage = data.get('production_stage')
        if isinstance(stage, bool) or not isinstance(stage, int) or not 0 <= stage <= len(PRODUCTION_STAGES):
            return jsonify({'error': 'مرحلهٔ نامعتبر است'}), 400
        if stage != (project['production_stage'] or 0):
            conn.execute('UPDATE projects SET production_stage=? WHERE id=?', (stage, project_id))
            project_event(conn, project_id, None, me['id'], 'production_status',
                          'روال تولید — ' + (PRODUCTION_STAGES[stage - 1] + ' انجام شد' if stage else 'شروع نشده'))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/project-options')
@login_required
def project_options():
    conn = get_db()
    me = current_user()
    viewer = me if not is_super(me) else {**me, 'role': 'admin'}
    result = {'can_create': can_create_project(conn, me), 'brands': project_brand_options(conn, viewer),
              'labels': PROJECT_CATEGORY_LABELS, 'trade_stages': list(TRADE_STAGES),
              'production_stages': list(PRODUCTION_STAGES), 'production_flow_brand_ids': production_flow_brand_ids(conn),
              'task_categories': [{'key': k, 'label': l, 'subs': [{'key': sk, 'label': sl} for sk, sl in subs]}
                                  for k, l, subs in TASK_CATEGORIES],
              'payment_order_kinds': PAYMENT_ORDER_KINDS, 'payment_methods': PAYMENT_METHODS, 'sale_terms': SALE_TERMS}
    conn.close()
    return jsonify(result)


@app.route('/api/projects', methods=['GET', 'POST'])
@login_required
def projects():
    me = current_user()
    conn = get_db()
    if request.method == 'POST':
        if not can_create_project(conn, me):
            conn.close()
            return jsonify({'error': 'مجوز ایجاد پروژه برای شما فعال نشده است'}), 403
        data = request.get_json(silent=True) or {}
        brand_id, category, error = validate_project_category(conn, me, data)
        if error:
            conn.close()
            return jsonify({'error': error}), 400
        name = str(data.get('name') or '').strip()
        description = str(data.get('description') or '').strip()
        raw = data.get('member_ids', [])
        if not name or len(name) > 120 or len(description) > 2000 or not isinstance(raw, list):
            conn.close()
            return jsonify({'error': 'عنوان یا اعضای پروژه نامعتبرند'}), 400
        try:
            members = {int(uid) for uid in raw} | {me['id']}
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'error': 'اعضای پروژه نامعتبرند'}), 400
        if any(uid <= 0 or not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone() for uid in members):
            conn.close()
            return jsonify({'error': 'یک یا چند عضو پیدا نشدند'}), 400
        now = int(datetime.now().timestamp() * 1000)
        lock_for_create(conn)
        duplicate = conn.execute('''SELECT id FROM projects WHERE creator_id=? AND name=? AND brand_id IS ?
            AND category IS ? AND created_at>=? ORDER BY id DESC''',
            (me['id'], name, brand_id, category, now - DUPLICATE_WINDOW_MS)).fetchone()
        if duplicate:
            conn.close()
            return jsonify({'success': True, 'project_id': duplicate['id'], 'duplicate': True})
        cursor = conn.execute('''INSERT INTO projects (name, description, creator_id, created_at, brand_id, category)
                              VALUES (?,?,?,?,?,?)''', (name, description, me['id'], now, brand_id, category))
        project_id = cursor.lastrowid
        conn.execute('UPDATE projects SET project_code=? WHERE id=?', (f'PRJ-{project_id:06d}', project_id))
        conn.executemany('INSERT INTO project_members (project_id, user_id) VALUES (?,?)',
                         [(project_id, uid) for uid in sorted(members)])
        project_event(conn, project_id, None, me['id'], 'created', 'پروژه ایجاد شد')
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'project_id': project_id})
    global_projects = is_super(me) or (me['role'] == 'admin' and
                      has_permission(conn, me, 'view_all_tasks'))
    scope = dashboard_scope(conn, me)
    if scope is not None:
        own_brands = managed_brand_ids(conn, me['id'])
        # مدیر برند علاوه بر پروژه‌های داشبوردش، پروژه‌هایی را که عضوشان است
        # و پروژه‌های برندهای خودش را هم می‌بیند؛ تسک‌های داخل پروژه همچنان طبق محدودهٔ او نمایش داده می‌شوند.
        ids = set(scope['project_ids'])
        ids.update(r['project_id'] for r in conn.execute(
            'SELECT project_id FROM project_members WHERE user_id=?', (me['id'],)))
        if own_brands:
            ids.update(r['id'] for r in conn.execute(
                f"SELECT id FROM projects WHERE brand_id IN ({','.join('?' for _ in own_brands)})", sorted(own_brands)))
        ids = sorted(ids)
        rows = conn.execute(f'''SELECT * FROM projects WHERE id IN ({','.join('?' for _ in ids)})
            ORDER BY created_at DESC, id DESC''', ids).fetchall() if ids else []
        visible_manager_tasks = set(scope['task_ids'])
    else:
        rows = conn.execute('''SELECT * FROM projects p WHERE ?=1
            OR EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_id=?)
            ORDER BY p.created_at DESC, p.id DESC''', (int(global_projects), me['id'])).fetchall()
    result = []
    for row in rows:
        project = dict(row)
        project['project_code'] = project.get('project_code') or f"PRJ-{row['id']:06d}"
        brand_row = conn.execute('SELECT name FROM brands WHERE id=?', (project.get('brand_id'),)).fetchone() \
            if project.get('brand_id') else None
        project['brand_name'] = brand_row['name'] if brand_row else None
        creator = conn.execute('SELECT name FROM users WHERE id=?', (row['creator_id'],)).fetchone()
        project['creator_name'] = creator['name'] if creator else None
        project['can_edit'] = can_edit_project(conn, me, row)
        project['can_chat'] = can_use_project_chat(conn, me, row)
        project['chat_count'] = conn.execute('SELECT COUNT(*) FROM project_messages WHERE project_id=?', (row['id'],)).fetchone()[0]
        project['can_delete'] = can_delete_project(conn, me, row)
        project['member_ids'] = [r['user_id'] for r in conn.execute(
            'SELECT user_id FROM project_members WHERE project_id=? ORDER BY user_id', (row['id'],))]
        if scope is not None and me['id'] not in project['member_ids']:
            project['member_ids'] = [uid for uid in project['member_ids'] if uid == me['id'] or
                (u := conn.execute('SELECT role,brand_id FROM users WHERE id=?', (uid,)).fetchone()) and
                u['brand_id'] in own_brands and u['role'] in MANAGER_STAFF_ROLES]
        visible_rows = [t for t in conn.execute('SELECT * FROM tasks WHERE project_id=? ORDER BY id',
                      (row['id'],)) if (t['id'] in visible_manager_tasks if scope is not None else can_view_task(conn, t, me))]
        visible_ids = {t['id'] for t in visible_rows}
        project['tasks'] = []
        for task in visible_rows:
            item = {key: task[key] for key in ('id', 'title', 'task_code', 'status', 'progress', 'created_at')}
            item['user_progress'] = {str(r['user_id']): r['progress'] for r in conn.execute(
                'SELECT user_id,progress FROM task_user_progress WHERE task_id=?', (task['id'],))}
            project['tasks'].append(item)
        project['member_progress'] = []
        for uid in project['member_ids']:
            personal = [t['user_progress'][str(uid)] for t in project['tasks'] if str(uid) in t['user_progress']]
            if uid == me['id'] or me['role'] in EXECUTIVE_ROLES or row['creator_id'] == me['id'] or personal:
                project['member_progress'].append({'user_id': uid,
                    'progress': round(sum(personal) / len(personal)) if personal else 0,
                    'task_count': len(personal)})
        project['events'] = [dict(r) for r in conn.execute('''SELECT pe.*, u.name AS actor_name,
            t.title AS task_title, t.task_code FROM project_events pe
            LEFT JOIN users u ON u.id=pe.actor_id LEFT JOIN tasks t ON t.id=pe.task_id
            WHERE pe.project_id=? ORDER BY pe.id''', (row['id'],))
            if r['task_id'] in visible_ids or (r['task_id'] is None and
                (scope is None or r['actor_id'] == me['id'] or r['actor_id'] in project['member_ids']))]
        result.append(project)
    conn.close()
    return jsonify(result)


@app.route('/api/projects/<int:project_id>', methods=['PUT'])
@login_required
def edit_project(project_id):
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    description = str(data.get('description') or '').strip()
    raw_members = data.get('member_ids', [])
    if not name or len(name) > 120 or len(description) > 2000 or not isinstance(raw_members, list):
        return jsonify({'error': 'عنوان یا توضیح پروژه نامعتبر است'}), 400
    try:
        if any(type(uid) not in (int, str) or not str(uid).isdigit() for uid in raw_members):
            raise ValueError
        requested = {int(uid) for uid in raw_members}
        if len(requested) != len(raw_members) or any(uid <= 0 for uid in requested):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'error': 'اعضای پروژه نامعتبرند'}), 400
    conn = get_db()
    project = conn.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
    me = current_user()
    if not project or not can_edit_project(conn, me, project):
        conn.close()
        return jsonify({'error': 'پروژه پیدا نشد یا مجوز ویرایش آن را ندارید'}), 404
    new_brand, new_category = project['brand_id'], project['category']
    category_changed = 'category' in data and (
        str(data.get('category') or '') != (project['category'] or '') or
        (data.get('category') != 'other' and str(data.get('brand_id') or '') != str(project['brand_id'] or '')))
    if category_changed:
        new_brand, new_category, error = validate_project_category(conn, me, data)
        if error:
            conn.close()
            return jsonify({'error': error}), 400
    existing = {r['user_id'] for r in conn.execute('SELECT user_id FROM project_members WHERE project_id=?', (project_id,))}
    added = requested - existing
    people = {r['id']: r['name'] for r in conn.execute(
        f"SELECT id,name FROM users WHERE id IN ({','.join('?' for _ in added)})", tuple(added))} if added else {}
    if len(people) != len(added):
        conn.close()
        return jsonify({'error': 'یک یا چند عضو جدید پیدا نشدند'}), 400
    conn.execute('UPDATE projects SET name=?,description=?,brand_id=?,category=? WHERE id=?',
                 (name, description, new_brand, new_category, project_id))
    if (new_brand, new_category) != (project['brand_id'], project['category']):
        project_event(conn, project_id, None, me['id'], 'project_category',
                      'دسته‌بندی پروژه تغییر کرد: ' + PROJECT_CATEGORY_LABELS.get(new_category, '-'))
    if name != project['name'] or description != (project['description'] or ''):
        project_event(conn, project_id, None, me['id'], 'project_edited', 'عنوان یا توضیح پروژه ویرایش شد')
    for uid in sorted(added):
        conn.execute('INSERT INTO project_members (project_id,user_id) VALUES (?,?)', (project_id, uid))
        create_notification(uid, '🗂️ عضویت در پروژه',
                            f'{me["name"]} شما را به پروژه «{name}» اضافه کرد.', 'info', conn=conn)
    if added:
        project_event(conn, project_id, None, me['id'], 'members_added',
                      'اعضای جدید اضافه شدند: ' + '، '.join(people[uid] for uid in sorted(added)))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'added_member_ids': sorted(added)})


def delete_task_data(conn, task_id):
    files = [r['filename'] for r in conn.execute('SELECT filename FROM task_attachments WHERE task_id=?', (task_id,))]
    conn.execute('DELETE FROM task_comment_mentions WHERE comment_id IN '
                 '(SELECT id FROM task_comments WHERE task_id=?)', (task_id,))
    for table in ('task_attachments', 'task_comments', 'task_participants', 'task_observers', 'task_forwards',
                  'task_user_progress', 'task_assignees', 'notifications', 'task_shares', 'task_stages',
                  'payment_processes'):
        conn.execute(f'DELETE FROM {table} WHERE task_id=?', (task_id,))
    conn.execute('DELETE FROM project_events WHERE task_id=?', (task_id,))
    conn.execute('DELETE FROM tasks WHERE id=?', (task_id,))
    return files


TRASH_TABLES = ('task_assignees', 'task_user_progress', 'task_observers', 'task_participants', 'task_forwards',
                'task_attachments', 'task_comments', 'notifications', 'project_events', 'task_shares', 'task_stages',
                'payment_processes')


def task_snapshot(conn, task):
    task_id = task['id']
    snapshot = {'tasks': [dict(task)]}
    for table in TRASH_TABLES:
        snapshot[table] = [dict(r) for r in conn.execute(f'SELECT * FROM {table} WHERE task_id=?', (task_id,))]
    snapshot['task_comment_mentions'] = [dict(r) for r in conn.execute(
        'SELECT * FROM task_comment_mentions WHERE comment_id IN (SELECT id FROM task_comments WHERE task_id=?)',
        (task_id,))]
    return snapshot


def move_task_to_trash(conn, task, actor_id):
    """تسک و همهٔ اطلاعات وابسته‌اش را در سطل زباله ذخیره و از جدول‌های اصلی حذف می‌کند؛ فایل‌ها روی دیسک می‌مانند."""
    task_id = task['id']
    snapshot = task_snapshot(conn, task)
    project = conn.execute('SELECT name FROM projects WHERE id=?', (task['project_id'],)).fetchone() \
        if task['project_id'] is not None else None
    conn.execute('''INSERT INTO task_trash (task_id, task_code, title, project_id, project_name, brand_id,
        creator_id, deleted_by, deleted_at, snapshot) VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (task_id, task['task_code'], task['title'], task['project_id'], project['name'] if project else None,
         task['brand_id'], task['creator_id'], actor_id, int(time.time() * 1000),
         json.dumps(snapshot, ensure_ascii=False)))
    delete_task_data(conn, task_id)


def _insert_rows(conn, table, rows):
    columns = {r['name'] for r in conn.execute(f'PRAGMA table_info({table})')}
    for row in rows:
        values = {k: v for k, v in row.items() if k in columns}
        if values:
            try:
                conn.execute(f'INSERT OR IGNORE INTO {table} ({",".join(values)}) '
                             f'VALUES ({",".join("?" for _ in values)})', tuple(values.values()))
            except sqlite3.IntegrityError:
                pass  # ردیفی که به کاربر حذف‌شده اشاره دارد


def restore_project_from_trash(conn, trash_row):
    """بازگرداندن پروژه با همان کد، اعضا، روند ثبت‌شده و همهٔ تسک‌هایش."""
    snapshot = json.loads(trash_row['snapshot'])
    project = snapshot['project']
    if conn.execute('SELECT 1 FROM projects WHERE id=?', (project['id'],)).fetchone():
        raise ValueError('پروژه‌ای با همین شناسه از قبل وجود دارد')
    _insert_rows(conn, 'projects', [project])
    _insert_rows(conn, 'project_members', snapshot.get('project_members', []))
    _insert_rows(conn, 'project_events', snapshot.get('project_events', []))
    for task_snap in snapshot.get('task_snapshots', []):
        if not conn.execute('SELECT 1 FROM tasks WHERE id=?', (task_snap['tasks'][0]['id'],)).fetchone():
            restore_task_snapshot(conn, task_snap)
    conn.execute('DELETE FROM task_trash WHERE id=?', (trash_row['id'],))
    return project['id']


def restore_task_from_trash(conn, trash_row):
    if (trash_row['item_type'] or 'task') == 'project':
        return restore_project_from_trash(conn, trash_row)
    task_id = restore_task_snapshot(conn, json.loads(trash_row['snapshot']))
    conn.execute('DELETE FROM task_trash WHERE id=?', (trash_row['id'],))
    return task_id


def restore_task_snapshot(conn, snapshot):
    """بازگرداندن تسک با همان شناسه، کد، گفت‌وگوها، فایل‌ها و مسئولان. ردیف‌هایی که به کاربر یا
    پروژهٔ حذف‌شده اشاره دارند نادیده گرفته می‌شوند."""
    task = snapshot['tasks'][0]
    if conn.execute('SELECT 1 FROM tasks WHERE id=?', (task['id'],)).fetchone():
        raise ValueError('تسکی با همین شناسه از قبل وجود دارد')
    if task.get('project_id') is not None and not conn.execute(
            'SELECT 1 FROM projects WHERE id=?', (task['project_id'],)).fetchone():
        task['project_id'] = None  # پروژه حذف شده؛ تسک به‌صورت مستقل برمی‌گردد
    order = ['tasks', 'task_assignees', 'task_user_progress', 'task_observers', 'task_participants',
             'task_forwards', 'task_attachments', 'task_comments', 'task_comment_mentions', 'notifications',
             'project_events', 'task_shares', 'task_stages', 'payment_processes']
    for table in order:
        columns = {r['name'] for r in conn.execute(f'PRAGMA table_info({table})')}
        for row in snapshot.get(table, []):
            if table == 'project_events' and task.get('project_id') is None:
                continue
            values = {k: v for k, v in row.items() if k in columns}
            if not values:
                continue
            names = ','.join(values)
            try:
                conn.execute(f'INSERT OR IGNORE INTO {table} ({names}) VALUES ({",".join("?" for _ in values)})',
                             tuple(values.values()))
            except sqlite3.IntegrityError:
                if table == 'tasks':
                    raise
    return task['id']


def remove_stored_files(filenames):
    for filename in filenames:
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(path):
            os.remove(path)


def can_use_project_chat(conn, me, project):
    """چت پروژه برای اعضای پروژه، مدیرعامل و Administrator."""
    return (me['role'] in EXECUTIVE_ROLES or project['creator_id'] == me['id'] or
            is_project_member(conn, project['id'], me['id']))


def project_chat_scope_sql(me):
    """شرط SQL پروژه‌هایی که چتشان برای این کاربر در دسترس است (همان قاعدهٔ can_use_project_chat)."""
    if me['role'] in EXECUTIVE_ROLES:
        return '1=1', ()
    return ('(p.creator_id=? OR EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_id=?))',
            (me['id'], me['id']))


@app.route('/api/project-chat-feed')
@login_required
def project_chat_feed():
    """همهٔ پیام‌های چت پروژه‌هایی که کاربر عضو آن‌هاست، جدیدترین اول، همراه نام پروژه."""
    me = current_user()
    conn = get_db()
    try:
        try:
            limit = max(1, min(int(request.args.get('limit', 300)), 1000))
        except (TypeError, ValueError):
            limit = 300
        where, params = project_chat_scope_sql(me)
        rows = [dict(r) for r in conn.execute(f'''SELECT m.id, m.project_id, m.user_id, m.text, m.created_at,
                u.name AS user_name, p.name AS project_name, p.project_code, p.category, b.name AS brand_name
                FROM project_messages m JOIN projects p ON p.id=m.project_id
                LEFT JOIN users u ON u.id=m.user_id LEFT JOIN brands b ON b.id=p.brand_id
                WHERE {where} ORDER BY m.id DESC LIMIT ?''', (*params, limit))]
        files = {}
        if rows:
            ids = [r['id'] for r in rows]
            for f in conn.execute(f"SELECT id, message_id, original_name, file_size FROM project_files WHERE message_id IN ({','.join('?' for _ in ids)}) ORDER BY id", ids):
                files.setdefault(f['message_id'], []).append(dict(f))
        for r in rows:
            r['files'] = files.get(r['id'], [])
            r['project_code'] = r['project_code'] or f"PRJ-{r['project_id']:06d}"
        seen = conn.execute('SELECT last_seen_id FROM project_chat_reads WHERE user_id=?', (me['id'],)).fetchone()
        last_seen = seen['last_seen_id'] if seen else 0
        unread = conn.execute(f'''SELECT COUNT(*) FROM project_messages m JOIN projects p ON p.id=m.project_id
                WHERE {where} AND m.id>? AND m.user_id!=?''', (*params, last_seen, me['id'])).fetchone()[0]
        return jsonify({'messages': rows, 'last_seen_id': last_seen, 'unread': unread})
    finally:
        conn.close()


@app.route('/api/project-chat-feed/seen', methods=['POST'])
@login_required
def project_chat_feed_seen():
    me = current_user()
    conn = get_db()
    try:
        where, params = project_chat_scope_sql(me)
        latest = conn.execute(f'''SELECT MAX(m.id) FROM project_messages m JOIN projects p ON p.id=m.project_id
                WHERE {where}''', params).fetchone()[0] or 0
        conn.execute('INSERT OR IGNORE INTO project_chat_reads (user_id, last_seen_id) VALUES (?,0)', (me['id'],))
        conn.execute('UPDATE project_chat_reads SET last_seen_id=MAX(last_seen_id, ?) WHERE user_id=?', (latest, me['id']))
        conn.commit()
        return jsonify({'success': True, 'last_seen_id': latest})
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>/chat', methods=['GET', 'POST'])
@login_required
def project_chat(project_id):
    me = current_user()
    conn = get_db()
    try:
        project = conn.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
        if not project or not can_use_project_chat(conn, me, project):
            return jsonify({'error': 'فقط اعضای پروژه به چت پروژه دسترسی دارند'}), 403
        if request.method == 'POST':
            text = str(request.form.get('text') or '').strip()[:5000]
            files = [f for f in request.files.getlist('files') if f and f.filename]
            if not text and not files:
                return jsonify({'error': 'پیام یا فایلی برای ارسال وجود ندارد'}), 400
            if any(not allowed_file(f.filename) for f in files):
                return jsonify({'error': 'نوع یکی از فایل‌ها مجاز نیست'}), 400
            stamp = int(time.time() * 1000)
            message_id = conn.execute('INSERT INTO project_messages (project_id,user_id,text,created_at) VALUES (?,?,?,?)',
                                      (project_id, me['id'], text, stamp)).lastrowid
            for f in files:
                ext = f.filename.rsplit('.', 1)[-1].lower()
                stored = f'prj_{uuid.uuid4().hex}.{ext}'
                path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
                f.save(path)
                conn.execute('''INSERT INTO project_files (project_id,message_id,filename,original_name,file_size,uploader_id,created_at)
                    VALUES (?,?,?,?,?,?,?)''', (project_id, message_id, stored, f.filename, os.path.getsize(path), me['id'], stamp))
            preview = text[:120] if text else f'{len(files)} فایل'
            for row in conn.execute('SELECT user_id FROM project_members WHERE project_id=? AND user_id!=?', (project_id, me['id'])).fetchall():
                conn.execute('INSERT INTO notifications (user_id,title,message,type,task_id,created_at) VALUES (?,?,?,?,?,?)',
                             (row['user_id'], f'💬 پیام جدید در پروژه «{project["name"]}»', f'{me["name"]}: {preview}', 'info', None, stamp))
            conn.commit()
            return jsonify({'success': True})
        messages = []
        files_by_message = {}
        for f in conn.execute('''SELECT f.id,f.message_id,f.original_name,f.file_size,f.created_at,u.name AS uploader_name
                FROM project_files f LEFT JOIN users u ON u.id=f.uploader_id WHERE f.project_id=? ORDER BY f.id''', (project_id,)):
            files_by_message.setdefault(f['message_id'], []).append(dict(f))
        for m in conn.execute('''SELECT m.id,m.user_id,m.text,m.created_at,u.name AS user_name,u.role AS user_role
                FROM project_messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY m.id''', (project_id,)):
            item = dict(m)
            item['files'] = files_by_message.get(m['id'], [])
            messages.append(item)
        all_files = [f for group in files_by_message.values() for f in group]
        return jsonify({'messages': messages, 'files': all_files, 'project_name': project['name']})
    finally:
        conn.close()


@app.route('/api/project-files/<int:file_id>')
@login_required
def project_file(file_id):
    me = current_user()
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM project_files WHERE id=?', (file_id,)).fetchone()
        project = conn.execute('SELECT * FROM projects WHERE id=?', (row['project_id'],)).fetchone() if row else None
        if not row or not project or not can_use_project_chat(conn, me, project):
            return jsonify({'error': 'فایل پیدا نشد یا دسترسی ندارید'}), 404
        response = send_from_directory(app.config['UPLOAD_FOLDER'], row['filename'], as_attachment=True,
                                       download_name=row['original_name'] or row['filename'])
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    finally:
        conn.close()


@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
@permission_required('delete_projects')
def delete_project(project_id):
    conn = get_db()
    project = conn.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
    me = current_user()
    if not project or not can_delete_project(conn, me, project):
        conn.close()
        return jsonify({'error': 'پروژه پیدا نشد یا دسترسی ندارید'}), 404
    if conn.execute('''SELECT 1 FROM task_observers ob JOIN tasks t ON t.id=ob.task_id
        WHERE t.project_id=? AND ob.user_id=? LIMIT 1''', (project_id, me['id'])).fetchone():
        conn.close()
        return jsonify({'error': 'ناظر نمی‌تواند پروژهٔ حاوی تسک تحت نظارتش را حذف کند'}), 403
    # پروژه با همهٔ تسک‌ها، اعضا و روندش به سطل زباله می‌رود؛ فایل‌ها روی دیسک می‌مانند.
    tasks = conn.execute('SELECT * FROM tasks WHERE project_id=? ORDER BY id', (project_id,)).fetchall()
    snapshot = {'project': dict(project),
                'project_members': [dict(r) for r in conn.execute(
                    'SELECT * FROM project_members WHERE project_id=?', (project_id,))],
                'project_events': [dict(r) for r in conn.execute(
                    'SELECT * FROM project_events WHERE project_id=? AND task_id IS NULL', (project_id,))],
                'task_snapshots': [task_snapshot(conn, t) for t in tasks]}
    code = project['project_code'] if 'project_code' in project.keys() and project['project_code'] else f'PRJ-{project_id:06d}'
    conn.execute('''INSERT INTO task_trash (task_id, task_code, title, project_id, project_name, brand_id,
        creator_id, deleted_by, deleted_at, snapshot, item_type, task_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (project_id, code, project['name'], project_id, project['name'], None, project['creator_id'],
         me['id'], int(time.time() * 1000), json.dumps(snapshot, ensure_ascii=False), 'project', len(tasks)))
    for task in tasks:
        delete_task_data(conn, task['id'])
    conn.execute('DELETE FROM project_events WHERE project_id=?', (project_id,))
    conn.execute('DELETE FROM project_members WHERE project_id=?', (project_id,))
    conn.execute('DELETE FROM projects WHERE id=?', (project_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'trashed': True})


@app.route('/api/tasks')
@login_required
def get_tasks():
    check_overdue_tasks()
    check_due_reminders()
    conn = get_db()
    c = conn.cursor()
    me = current_user()
    rows = visible_task_rows(conn, me)
    tasks = [dict(r) for r in rows]
    delete_perm = has_permission(conn, me, 'delete_tasks')
    for task in tasks:
        if task['status'] != 'done':
            task['task_score'] = None
            task['quality_score'] = None
        elif me['role'] not in MANAGEMENT_ROLES and any(task[key] is None for key in ('task_score', 'quality_score')):
            task['quality_score'] = None
        task.pop('ethics_score', None)
        task.pop('rating_notified_signature', None)
        creator_row = c.execute('SELECT name FROM users WHERE id=?', (task['creator_id'],)).fetchone()
        task['creator_name'] = creator_row['name'] if creator_row else None
        task['attachments'] = [dict(a) for a in
                               c.execute('SELECT * FROM task_attachments WHERE task_id=?', (task['id'],)).fetchall()]
        task['comments'] = [dict(c2) for c2 in c.execute(
            'SELECT tc.*, u.name as user_name, u.role as user_role FROM task_comments tc LEFT JOIN users u ON tc.user_id = u.id WHERE tc.task_id=? ORDER BY tc.created_at ASC, tc.id ASC',
            (task['id'],)).fetchall()]
        for comment in task['comments']:
            comment['mention_ids'] = [r['user_id'] for r in c.execute(
                'SELECT user_id FROM task_comment_mentions WHERE comment_id=?', (comment['id'],))]
        task['participant_ids'] = [r['user_id'] for r in c.execute(
            'SELECT user_id FROM task_participants WHERE task_id=?', (task['id'],))]
        # تخصیص‌ها اکنون از جدول task_assignees خوانده می‌شود
        task['assignee_ids'] = get_task_assignees(conn, task['id'])
        task['observer_ids'] = get_task_observers(conn, task['id'])
        task['observer_read_only'] = me['id'] in task['observer_ids']
        task['user_progress'] = {str(r['user_id']): r['progress'] for r in c.execute(
            'SELECT user_id,progress FROM task_user_progress WHERE task_id=?', (task['id'],))}
        task['my_progress'] = task['user_progress'].get(str(me['id']), 0) if task['project_id'] is not None else task['progress']
        task['assignee_acceptance'] = {str(r['user_id']): r['acceptance_status'] for r in
            c.execute('SELECT user_id, acceptance_status FROM task_assignees WHERE task_id=?', (task['id'],))}
        task['forwarded_read_only'] = forwarded_by(conn, task['id'], me['id'])
        task['shared_read_only'] = (shared_with(conn, task['id'], me['id']) and task['creator_id'] != me['id'] and
                                    me['id'] not in task['assignee_ids'] and not task['observer_read_only'] and
                                    not task['forwarded_read_only'])
        # تسک انجام‌شده ۵ روز بعد از اتمام به «آرشیو انجام‌شده‌ها» می‌رود
        finished_at = task['completed_at'] or task['created_at'] or 0
        task['archived'] = task['status'] == 'done' and finished_at <= int(time.time() * 1000) - ARCHIVE_AFTER_DAYS * 86400000
        task['shared_ids'] = [r['to_user_id'] for r in c.execute(
            'SELECT to_user_id FROM task_shares WHERE task_id=? ORDER BY id', (task['id'],))]
        task['creator_edit_allowed'] = bool(task['creator_edit_allowed']) if is_super(me) or task['creator_id'] == me['id'] else False
        task['supervisor_scope'] = supervisor_task_scope(conn, me, task) if me['role'] == 'supervisor' else False
        task['can_delete'] = can_delete_task(conn, me, task, delete_perm)
        task['stages'] = task_stage_history(conn, task['id']) if task['project_id'] is None else []
        pay = conn.execute('SELECT id FROM payment_processes WHERE task_id=?', (task['id'],)).fetchone()
        task['payment_process_id'] = pay['id'] if pay else None
        task['forward_history'] = [dict(r) for r in c.execute(
            '''SELECT tf.from_user_id, tf.to_user_id, tf.forwarded_at,
               sender.name AS from_name, recipient.name AS to_name
               FROM task_forwards tf LEFT JOIN users sender ON sender.id=tf.from_user_id
               LEFT JOIN users recipient ON recipient.id=tf.to_user_id
               WHERE tf.task_id=? ORDER BY tf.id''', (task['id'],))]
    conn.close()
    return jsonify(tasks)


@app.route('/api/tasks/<int:id>/creator-edit', methods=['POST'])
@roles_required(*SUPER_ROLES)
def set_creator_edit_permission(id):
    payload = request.get_json(silent=True) or {}
    if type(payload.get('allowed')) is not bool:
        return jsonify({'error': 'مقدار مجوز نامعتبر است'}), 400
    conn = get_db()
    task = conn.execute('SELECT id,title,creator_id,project_id FROM tasks WHERE id=?', (id,)).fetchone()
    if not task or task['project_id'] is not None:
        conn.close()
        return jsonify({'error': 'تسک مستقل پیدا نشد'}), 404
    if is_task_observer(conn, id, current_user()['id']):
        conn.close()
        return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
    allowed = payload['allowed']
    conn.execute('UPDATE tasks SET creator_edit_allowed=? WHERE id=?', (int(allowed), id))
    conn.execute('INSERT INTO access_audit (actor_id,target_type,target_id,detail,created_at) VALUES (?,?,?,?,?)',
                 (current_user()['id'], 'standalone_task', id,
                  f'creator_edit={int(allowed)}; creator_id={task["creator_id"]}', int(time.time() * 1000)))
    create_notification(task['creator_id'], 'مجوز ویرایش تسک مستقل',
                        f'Administrator مجوز ویرایش مشخصات تسک «{task["title"]}» را ' +
                        ('فعال کرد.' if allowed else 'لغو کرد.'), 'info', id, conn=conn)
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'allowed': allowed})


@app.route('/api/tasks/<int:id>/accept', methods=['POST'])
@login_required
def accept_task(id):
    me = current_user()
    conn = get_db()
    if is_task_observer(conn, id, me['id']):
        conn.close()
        return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
    task = conn.execute('SELECT id, title, creator_id, brand_id, status FROM tasks WHERE id=?', (id,)).fetchone()
    assignment = conn.execute('SELECT acceptance_status FROM task_assignees WHERE task_id=? AND user_id=?',
                              (id, me['id'])).fetchone()
    if not task or not assignment:
        conn.close()
        return jsonify({'error': 'این تسک به شما محول نشده است'}), 403
    if forwarded_by(conn, id, me['id']):
        conn.close()
        return jsonify({'error': 'پس از فوروارد، تسک فقط برای پیگیری قابل مشاهده است'}), 403
    if assignment['acceptance_status'] == 'accepted':
        conn.close()
        return jsonify({'success': True})
    if task['status'] in ('done', 'rejected'):
        conn.close()
        return jsonify({'error': 'تسک بسته‌شده قابل تأیید نیست'}), 400
    conn.execute("""UPDATE task_assignees SET acceptance_status='accepted', accepted_at=?
                 WHERE task_id=? AND user_id=?""", (int(datetime.now().timestamp() * 1000), id, me['id']))
    brand = conn.execute('SELECT manager_id FROM brands WHERE id=?', (task['brand_id'],)).fetchone()
    recipients = {task['creator_id'], brand['manager_id'] if brand else None} - {None, me['id']}
    for uid in recipients:
        create_notification(uid, '✅ تأیید دریافت تسک',
                            f'{me["name"]} تسک «{task["title"]}» را پذیرفت.', 'success', id, conn=conn)
    task_event(conn, id, me['id'], 'accepted', 'دریافت تسک تأیید شد')
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/tasks/<int:id>/forward', methods=['POST'])
@login_required
def forward_task(id):
    me = current_user()
    try:
        recipient_id = int((request.get_json(silent=True) or {}).get('to_user_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'کاربر مقصد را انتخاب کنید'}), 400
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone()
    recipient = conn.execute('SELECT id, name FROM users WHERE id=?', (recipient_id,)).fetchone()
    if not task or not can_view_task(conn, task, me):
        conn.close()
        return jsonify({'error': 'تسک پیدا نشد'}), 404
    if task['status'] in ('done', 'rejected'):
        # بعد از اتمام تسک، هر کسی که تسک را می‌بیند می‌تواند آن را برای دیگران فوروارد کند (فقط مشاهده)
        if not recipient or recipient_id == me['id']:
            conn.close()
            return jsonify({'error': 'گیرنده نامعتبر است'}), 400
        if is_task_observer(conn, id, recipient_id):
            # ناظر همین الان تسک را می‌بیند؛ فوروارد فقط به او اطلاع می‌دهد
            task_event(conn, id, me['id'], 'forwarded', f'تسک تمام‌شده برای ناظر ({recipient["name"]}) فوروارد شد')
            create_notification(recipient_id, '↪️ تسک برای شما فوروارد شد',
                                f'{me["name"]} تسک تمام‌شدهٔ «{task["title"]}» را برای شما فوروارد کرد.',
                                'info', id, conn=conn)
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'shared': True})
        already = (recipient_id == task['creator_id'] or recipient_id in get_task_assignees(conn, id) or
                   forwarded_by(conn, id, recipient_id) or shared_with(conn, id, recipient_id))
        if already:
            conn.close()
            return jsonify({'error': 'این شخص همین الان به تسک دسترسی دارد'}), 400
        conn.execute('INSERT INTO task_shares (task_id, from_user_id, to_user_id, shared_at) VALUES (?,?,?,?)',
                     (id, me['id'], recipient_id, int(time.time() * 1000)))
        conn.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)', (id, recipient_id))
        task_event(conn, id, me['id'], 'forwarded', f'تسک تمام‌شده برای {recipient["name"]} فوروارد شد (مشاهده)')
        create_notification(recipient_id, '↪️ تسک برای شما فوروارد شد',
                            f'{me["name"]} تسک تمام‌شدهٔ «{task["title"]}» را برای مشاهده به شما فوروارد کرد.',
                            'info', id, conn=conn)
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'shared': True})
    locked = payment_locked_response(conn, id)
    if locked:
        conn.close()
        return locked
    if is_task_observer(conn, id, me['id']):
        conn.close()
        return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
    if (forwarded_by(conn, id, me['id']) or
            (me['id'] != task['creator_id'] and me['id'] not in get_task_assignees(conn, id))):
        conn.close()
        return jsonify({'error': 'این تسک قابل فوروارد نیست'}), 403
    if (not recipient or recipient_id == me['id'] or recipient_id in get_task_assignees(conn, id) or
            forwarded_by(conn, id, recipient_id)):
        conn.close()
        return jsonify({'error': 'مقصد نامعتبر است یا قبلاً این تسک را دریافت کرده است'}), 400
    if is_task_observer(conn, id, recipient_id):
        # فوروارد به ناظر فقط برای اطلاع اوست: ناظر همچنان ناظر می‌ماند و مسئولیت تسک جابه‌جا نمی‌شود
        task_event(conn, id, me['id'], 'forwarded', f'تسک برای اطلاع ناظر ({recipient["name"]}) فوروارد شد')
        create_notification(recipient_id, '↪️ تسک برای شما (ناظر) فوروارد شد',
                            f'{me["name"]} تسک «{task["title"]}» را برای اطلاع و بررسی به شما فوروارد کرد.',
                            'info', id, conn=conn)
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'observer': True})
    conn.execute('DELETE FROM task_assignees WHERE task_id=? AND user_id=?', (id, me['id']))
    conn.execute('INSERT INTO task_assignees (task_id, user_id) VALUES (?,?)', (id, recipient_id))
    if task['project_id'] is not None:
        conn.execute('INSERT OR IGNORE INTO task_user_progress (task_id,user_id,progress,updated_at) VALUES (?,?,0,?)',
                     (id, recipient_id, int(time.time() * 1000)))
    conn.execute('INSERT INTO task_forwards (task_id, from_user_id, to_user_id, forwarded_at) VALUES (?,?,?,?)',
                 (id, me['id'], recipient_id, int(datetime.now().timestamp() * 1000)))
    conn.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)', (id, recipient_id))
    if task['project_id'] is not None:
        conn.execute('INSERT OR IGNORE INTO project_members (project_id, user_id) VALUES (?,?)',
                     (task['project_id'], recipient_id))
        conn.execute('''INSERT OR IGNORE INTO task_participants (task_id, user_id)
            SELECT id, ? FROM tasks WHERE project_id=?''', (recipient_id, task['project_id']))
    task_event(conn, id, me['id'], 'forwarded', f'تسک به {recipient["name"]} فوروارد شد')
    create_notification(recipient_id, '↪️ تسک برای شما فوروارد شد',
                        f'{me["name"]} تسک «{task["title"]}» را به شما فوروارد کرد. لطفاً دریافت را تأیید کنید.',
                        'info', id, conn=conn)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


def task_stage_history(conn, task_id):
    rows = conn.execute('''SELECT s.*, u.name AS from_name FROM task_stages s
        LEFT JOIN users u ON u.id=s.from_user_id WHERE s.task_id=? ORDER BY s.stage_no''', (task_id,)).fetchall()
    if not rows:
        return []

    def id_list(text):
        return [int(x) for x in (text or '').split(',') if x.strip().isdigit()]

    ids = set()
    for r in rows:
        ids |= set(id_list(r['prev_user_ids'])) | set(id_list(r['to_user_ids']))
    names = {u['id']: u['name'] for u in conn.execute(
        f"SELECT id,name FROM users WHERE id IN ({','.join('?' for _ in ids)})", tuple(ids))} if ids else {}
    return [{'stage_no': r['stage_no'], 'from_user_id': r['from_user_id'], 'from_name': r['from_name'],
             'prev_names': [names.get(uid, 'کاربر حذف‌شده') for uid in id_list(r['prev_user_ids'])],
             'to_names': [names.get(uid, 'کاربر حذف‌شده') for uid in id_list(r['to_user_ids'])],
             'to_user_ids': id_list(r['to_user_ids']), 'note': r['note'], 'prev_status': r['prev_status'],
             'prev_progress': r['prev_progress'], 'created_at': r['created_at']} for r in rows]


@app.route('/api/tasks/<int:id>/next-stage', methods=['POST'])
@login_required
def task_next_stage(id):
    """تسک مستقل چندمرحله‌ای: مسئول فعلی (یا سازنده) تسک را به شخص/اشخاص مرحلهٔ بعد می‌سپارد.
    مسئولان قبلی تسک را تا پایان می‌بینند و می‌توانند پیام بگذارند، ولی دیگر مسئول نیستند."""
    data = request.get_json(silent=True) or {}
    me = current_user()
    conn = get_db()
    try:
        task = conn.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone()
        if not task or not can_view_task(conn, task, me):
            return jsonify({'error': 'تسک پیدا نشد'}), 404
        if task['project_id'] is not None:
            return jsonify({'error': 'مرحله‌بندی فقط برای تسک‌های مستقل است'}), 400
        locked = payment_locked_response(conn, id)
        if locked:
            return locked
        if task['status'] == 'rejected':
            return jsonify({'error': 'تسک ردشده را نمی‌توان به مرحلهٔ بعد فرستاد'}), 409
        assignees = get_task_assignees(conn, id)
        if not (me['id'] in assignees or me['id'] == task['creator_id'] or is_super(me)):
            return jsonify({'error': 'فقط مسئول فعلی یا سازندهٔ تسک می‌تواند آن را به مرحلهٔ بعد بفرستد'}), 403
        targets = _parse_id_list(data.get('to_user_ids'))
        if not targets:
            return jsonify({'error': 'شخص یا اشخاص مرحلهٔ بعد را انتخاب کنید'}), 400
        if me['id'] in targets:
            return jsonify({'error': 'مرحلهٔ بعد را به شخص دیگری بسپارید'}), 400
        people = {r['id']: r['name'] for r in conn.execute(
            f"SELECT id,name FROM users WHERE id IN ({','.join('?' for _ in targets)})", tuple(targets))}
        if len(people) != len(targets):
            return jsonify({'error': 'کاربر انتخاب‌شده پیدا نشد'}), 400
        note = str(data.get('note') or '').strip()[:2000]
        due_date = str(data.get('due_date') or '').strip() or task['due_date']
        stamp = int(time.time() * 1000)
        stage_no = (conn.execute('SELECT MAX(stage_no) FROM task_stages WHERE task_id=?', (id,)).fetchone()[0] or 1) + 1
        conn.execute('''INSERT INTO task_stages (task_id, stage_no, from_user_id, prev_user_ids, to_user_ids, note,
            prev_status, prev_progress, created_at) VALUES (?,?,?,?,?,?,?,?,?)''',
                     (id, stage_no, me['id'], ','.join(map(str, assignees)), ','.join(map(str, targets)), note,
                      task['status'], task['progress'], stamp))
        for uid in assignees:
            if uid in targets:
                continue
            conn.execute('DELETE FROM task_assignees WHERE task_id=? AND user_id=?', (id, uid))
            if uid != task['creator_id'] and not shared_with(conn, id, uid):
                # مسئول مرحلهٔ قبل: فقط مشاهده و پیام تا پایان تسک
                conn.execute('INSERT INTO task_shares (task_id, from_user_id, to_user_id, shared_at) VALUES (?,?,?,?)',
                             (id, me['id'], uid, stamp))
            conn.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)', (id, uid))
        for uid in targets:
            conn.execute('DELETE FROM task_observers WHERE task_id=? AND user_id=?', (id, uid))
            if uid in assignees:
                conn.execute("UPDATE task_assignees SET acceptance_status='pending' WHERE task_id=? AND user_id=?",
                             (id, uid))
            else:
                conn.execute('INSERT INTO task_assignees (task_id, user_id) VALUES (?,?)', (id, uid))
            conn.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)', (id, uid))
        conn.execute('''UPDATE tasks SET status='new', progress=0, approval=NULL, completed_at=NULL,
            notified_overdue=0, due_date=? WHERE id=?''', (due_date, id))
        names = '، '.join(people[uid] for uid in targets)
        task_event(conn, id, me['id'], 'stage', f'مرحلهٔ {stage_no}: تسک به {names} سپرده شد' + (f' — {note}' if note else ''))
        for uid in targets:
            create_notification(uid, f'➡️ مرحلهٔ {stage_no} تسک به شما رسید',
                                f'{me["name"]} ادامهٔ تسک «{task["title"]}» را به شما سپرد' +
                                (f': {note[:120]}' if note else '') + '. لطفاً دریافت را تأیید کنید.',
                                'info', id, conn=conn)
        if task['creator_id'] not in targets and task['creator_id'] != me['id']:
            create_notification(task['creator_id'], f'➡️ تسک «{task["title"][:30]}» به مرحلهٔ {stage_no} رفت',
                                f'{me["name"]} تسک را به {names} سپرد.', 'info', id, conn=conn)
        conn.commit()
        return jsonify({'success': True, 'stage_no': stage_no})
    finally:
        conn.close()


def update_standalone_task(conn, task, me, data):
    """Only workflow fields may change after an independent task is created."""
    try:
        task_id = task['id']
        if not can_view_task(conn, task, me):
            return jsonify({'error': 'تسک پیدا نشد'}), 404
        if is_task_observer(conn, task_id, me['id']):
            return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
        if forwarded_by(conn, task_id, me['id']):
            return jsonify({'error': 'تسک فورواردشده فقط برای پیگیری قابل مشاهده است'}), 403

        text_fields = ('title', 'description', 'priority', 'requirements', 'due_date')
        for key in text_fields:
            if key in data and str(data[key] or '') != str(task[key] or ''):
                return jsonify({'error': 'مشخصات تسک مستقل پس از ایجاد قابل ویرایش نیست'}), 409
        for key in ('brand_id', 'creator_id'):
            if key in data:
                try:
                    supplied = int(data[key])
                except (TypeError, ValueError):
                    supplied = None
                if supplied != task[key]:
                    return jsonify({'error': 'مشخصات تسک مستقل پس از ایجاد قابل ویرایش نیست'}), 409
        if (data.get('project_id') not in (None, '') or
                'task_code' in data and data['task_code'] != task['task_code'] or
                'is_daily' in data and bool(data['is_daily']) != bool(task['is_daily'])):
            return jsonify({'error': 'مشخصات تسک مستقل پس از ایجاد قابل ویرایش نیست'}), 409
        if 'estimated_minutes' in data:
            try:
                supplied_minutes = int(data['estimated_minutes']) if data['estimated_minutes'] not in (None, '') else None
            except (TypeError, ValueError):
                supplied_minutes = -1
            if supplied_minutes != task['estimated_minutes']:
                return jsonify({'error': 'مشخصات تسک مستقل پس از ایجاد قابل ویرایش نیست'}), 409
        if 'assignee_ids' in data:
            raw_ids = data['assignee_ids']
            if isinstance(raw_ids, str):
                raw_ids = raw_ids.split(',')
            try:
                requested_ids = [int(uid) for uid in raw_ids]
            except (TypeError, ValueError):
                return jsonify({'error': 'مسئولان تسک مستقل پس از ایجاد قابل تغییر نیستند'}), 409
            if len(requested_ids) != len(set(requested_ids)) or set(requested_ids) != set(get_task_assignees(conn, task_id)):
                return jsonify({'error': 'مسئولان تسک مستقل پس از ایجاد قابل تغییر نیستند'}), 409

        assignment = conn.execute('SELECT acceptance_status FROM task_assignees WHERE task_id=? AND user_id=?',
                                  (task_id, me['id'])).fetchone()
        accepted = assignment is not None and assignment['acceptance_status'] == 'accepted'
        status = data.get('status', task['status'])
        if status not in ('new', 'progress', 'done', 'rejected'):
            return jsonify({'error': 'وضعیت تسک نامعتبر است'}), 400
        approval = data.get('approval', task['approval'])
        approval_changed = approval != task['approval']
        if approval_changed:
            can_approve = (task['status'] == 'done' and has_permission(conn, me, 'approve_tasks') and
                (me['role'] in ('admin', 'administrator') or manages_brand(conn, me, task['brand_id']) or
                 supervisor_task_scope(conn, me, task)))
            if not can_approve or status not in ('done', 'rejected'):
                return jsonify({'error': 'مجوز تأیید یا رد تسک را ندارید'}), 403

        progress = task['progress']
        if 'progress' in data:
            value = data['progress']
            if isinstance(value, bool) or not str(value).isdigit() or not 0 <= int(value) <= 100:
                return jsonify({'error': 'درصد پیشرفت باید بین ۰ تا ۱۰۰ باشد'}), 400
            requested_progress = int(value)
            if requested_progress != progress:
                if not accepted or task['status'] in ('done', 'rejected'):
                    return jsonify({'error': 'ثبت پیشرفت فقط برای مسئول تأییدکننده تسک باز مجاز است'}), 403
                progress = requested_progress
        if progress == 100 and task['status'] not in ('done', 'rejected'):
            status = 'done'
        status_changed = status != task['status']
        if status_changed and not accepted and not approval_changed:
            return jsonify({'error': 'فقط مسئول تأییدکننده می‌تواند وضعیت انجام را ثبت کند'}), 403
        if status_changed and task['status'] in ('done', 'rejected') and not approval_changed:
            return jsonify({'error': 'وضعیت تسک بسته‌شده قابل بازگشت نیست'}), 409
        if status == 'done' and task['status'] != 'done':
            if not accepted:
                return jsonify({'error': 'انجام تسک باید توسط مسئول تأییدکننده ثبت شود'}), 403
            progress = 100
        if status in ('progress', 'done'):
            accepted_ids = {row['user_id'] for row in conn.execute(
                "SELECT user_id FROM task_assignees WHERE task_id=? AND acceptance_status='accepted'", (task_id,))}
            assignees = set(get_task_assignees(conn, task_id))
            if status == 'done' and not assignees.issubset(accepted_ids):
                return jsonify({'error': 'ابتدا همه مسئولان باید دریافت تسک را تأیید کنند'}), 400
            if status == 'progress' and not accepted_ids:
                return jsonify({'error': 'ابتدا یکی از مسئولان باید دریافت تسک را تأیید کند'}), 400
        if not (status_changed or progress != task['progress'] or approval_changed):
            return jsonify({'error': 'مشخصات تسک مستقل قابل ویرایش نیست'}), 403

        completed_at = (task['completed_at'] or int(time.time() * 1000)) if status == 'done' else None
        conn.execute('''UPDATE tasks SET status=?, progress=?, approval=?, completed_at=?, notified_overdue=?
            WHERE id=?''', (status, progress, approval, completed_at,
            0 if task['status'] == 'done' and status != 'done' else task['notified_overdue'], task_id))
        if status == 'done' and task['status'] != 'done':
            brand = conn.execute('SELECT manager_id FROM brands WHERE id=?', (task['brand_id'],)).fetchone()
            recipients = {task['creator_id'], brand['manager_id'] if brand else None} - {None, me['id']}
            for uid in recipients:
                create_notification(uid, '✅ تسک انجام شد؛ آماده امتیازدهی',
                    f'{me["name"]} تسک «{task["title"]}» را با پیشرفت {progress}٪ تکمیل کرد. اکنون می‌توانید امتیاز بدهید.',
                    'success', task_id, conn=conn)
        notify_task_rating(conn, task_id)
        conn.commit()
        return jsonify({'success': True, 'task_id': task_id})
    finally:
        conn.close()


def _parse_id_list(raw):
    if isinstance(raw, str):
        raw = raw.split(',')
    if not isinstance(raw, list):
        return None
    try:
        ids = [int(x) for x in raw if str(x).strip() != '']
    except (TypeError, ValueError):
        return None
    if any(uid <= 0 for uid in ids):
        return None
    return list(dict.fromkeys(ids))


def apply_task_category_edit(conn, task, data):
    """در ویرایش کامل تسک مستقل، دسته/زیردسته را (اگر فرستاده شده) ثبت می‌کند؛ پیام خطا یا None."""
    if task['project_id'] is not None or 'category' not in data:
        return None
    category, subcategory, error = validate_task_category(data)
    if error:
        return error
    if 'payment_order' in data:
        payment_order, error = clean_payment_order(category, subcategory, data.get('payment_order'))
        if error:
            return error
    elif category == 'finance' and subcategory == 'payment_order':
        payment_order = task['payment_order'] if 'payment_order' in task.keys() else None  # فرم قبلی دست‌نخورده می‌ماند
    else:
        payment_order = None
    sale_term, error = clean_sale_term(category, data, task['sale_term'] if 'sale_term' in task.keys() else None)
    if error:
        return error
    conn.execute('UPDATE tasks SET category=?, subcategory=?, payment_order=?, sale_term=? WHERE id=?',
                 (category, subcategory, payment_order, sale_term, task['id']))
    return None


def administrator_update_task(conn, task, me, data):
    """Administrator: ویرایش کامل هر تسک (مستقل یا پروژه، باز یا بسته) بدون محدودیت گردش‌کار."""
    try:
        task_id = task['id']
        title = str(data.get('title', task['title']) or '').strip()
        if not title:
            return jsonify({'success': False, 'error': 'عنوان الزامی است'}), 400
        category_error = apply_task_category_edit(conn, task, data)
        if category_error:
            return jsonify({'error': category_error}), 400
        description = data.get('description', task['description'])
        requirements = data.get('requirements', task['requirements'])
        due_date = data.get('due_date', task['due_date']) or ''
        priority = data.get('priority', task['priority']) or 'normal'
        if priority not in ('low', 'normal', 'high', 'urgent'):
            return jsonify({'error': 'اولویت نامعتبر است'}), 400
        status = data.get('status', task['status'])
        if status not in ('new', 'progress', 'done', 'rejected'):
            return jsonify({'error': 'وضعیت تسک نامعتبر است'}), 400
        try:
            brand_id = int(data.get('brand_id', task['brand_id']))
        except (TypeError, ValueError):
            return jsonify({'error': 'برند نامعتبر است'}), 400
        if not conn.execute('SELECT 1 FROM brands WHERE id=?', (brand_id,)).fetchone():
            return jsonify({'error': 'برند پیدا نشد'}), 400
        if task['project_id'] is not None and data.get('project_id') not in (None, '') and \
                str(data.get('project_id')) != str(task['project_id']):
            return jsonify({'error': 'تسک پروژه را نمی‌توان به پروژه دیگری منتقل کرد'}), 409
        if task['project_id'] is None and data.get('project_id') not in (None, ''):
            return jsonify({'error': 'تسک مستقل را نمی‌توان به پروژه منتقل کرد'}), 409

        is_daily = 1 if data.get('is_daily', task['is_daily']) else 0
        minutes = None
        if is_daily:
            try:
                minutes = int(data.get('estimated_minutes', task['estimated_minutes']))
            except (TypeError, ValueError):
                minutes = -1
            if not 1 <= minutes <= 1440:
                return jsonify({'success': False, 'error': 'مدت کار روزانه باید بین ۱ تا ۱۴۴۰ دقیقه باشد'}), 400

        current_assignees = set(get_task_assignees(conn, task_id))
        assignees = (_parse_id_list(data['assignee_ids']) if 'assignee_ids' in data
                     else sorted(current_assignees))
        if assignees is None:
            return jsonify({'success': False, 'error': 'شناسه‌های تخصیص نامعتبر است'}), 400
        if not assignees:
            return jsonify({'success': False, 'error': 'حداقل یک مسئول انتخاب کنید'}), 400
        if any(not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone() for uid in assignees):
            return jsonify({'success': False, 'error': 'یکی از مسئولان انتخاب‌شده وجود ندارد'}), 400
        added = set(assignees) - current_assignees
        removed = current_assignees - set(assignees)
        if any(forwarded_by(conn, task_id, uid) for uid in added):
            return jsonify({'error': 'فردی که این تسک را فوروارد کرده نمی‌تواند دوباره مسئول شود'}), 400

        current_observers = set(get_task_observers(conn, task_id))
        observers = (_parse_id_list(data['observer_ids']) if 'observer_ids' in data
                     else sorted(current_observers))
        if observers is None:
            return jsonify({'error': 'ناظران تسک نامعتبرند'}), 400
        if set(observers) & set(assignees):
            return jsonify({'error': 'ناظر نمی‌تواند هم‌زمان مسئول همین تسک باشد'}), 400
        if any(not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone() for uid in observers):
            return jsonify({'error': 'یکی از ناظران انتخاب‌شده وجود ندارد'}), 400
        added_observers = set(observers) - current_observers
        removed_observers = current_observers - set(observers)

        now_ms = int(time.time() * 1000)
        progress = task['progress'] or 0
        if 'progress' in data and task['project_id'] is None:
            value = data['progress']
            if isinstance(value, bool) or not str(value).isdigit() or not 0 <= int(value) <= 100:
                return jsonify({'error': 'درصد پیشرفت باید بین ۰ تا ۱۰۰ باشد'}), 400
            progress = int(value)
        if status == 'done':
            progress = 100
        elif task['status'] == 'done' and progress == 100:
            progress = 99 if task['project_id'] is None else progress
        approval = data.get('approval', task['approval'])
        if status != 'done':
            approval = None if task['status'] == 'done' else approval
        completed_at = (task['completed_at'] or now_ms) if status == 'done' else None
        notified_overdue = (0 if due_date != (task['due_date'] or '') or status != task['status']
                            else task['notified_overdue'])

        changes = []
        for key, value, label in (('title', title, 'عنوان'), ('description', description, 'توضیحات'),
                                  ('requirements', requirements, 'نیازمندی‌ها'), ('due_date', due_date, 'مهلت'),
                                  ('priority', priority, 'اولویت'), ('status', status, 'وضعیت'),
                                  ('brand_id', brand_id, 'برند')):
            if str(value or '') != str(task[key] or ''):
                changes.append(label)
        if is_daily != (task['is_daily'] or 0) or minutes != task['estimated_minutes']:
            changes.append('کار روزانه')
        if added or removed:
            changes.append('مسئولان')
        if added_observers or removed_observers:
            changes.append('ناظران')

        conn.execute("""UPDATE tasks SET title=?, description=?, brand_id=?, status=?, priority=?, progress=?,
            requirements=?, approval=?, due_date=?, completed_at=?, is_daily=?, estimated_minutes=?,
            notified_overdue=? WHERE id=?""",
            (title, description, brand_id, status, priority, progress, requirements, approval, due_date,
             completed_at, is_daily, minutes, notified_overdue, task_id))
        set_task_assignees(conn, task_id, assignees)
        for uid in removed_observers:
            conn.execute('DELETE FROM task_observers WHERE task_id=? AND user_id=?', (task_id, uid))
        if task['project_id'] is not None:
            for uid in removed:
                conn.execute('DELETE FROM task_user_progress WHERE task_id=? AND user_id=?', (task_id, uid))
            for uid in added:
                conn.execute('INSERT OR IGNORE INTO task_user_progress (task_id,user_id,progress,updated_at) VALUES (?,?,0,?)',
                             (task_id, uid, now_ms))
                conn.execute('INSERT OR IGNORE INTO project_members (project_id,user_id) VALUES (?,?)',
                             (task['project_id'], uid))
            if status == 'done':
                conn.execute('UPDATE task_user_progress SET progress=100, updated_at=? WHERE task_id=?', (now_ms, task_id))
            else:
                rows = [r['progress'] for r in conn.execute(
                    'SELECT progress FROM task_user_progress WHERE task_id=?', (task_id,))]
                avg = round(sum(rows) / len(rows)) if rows else 0
                conn.execute('UPDATE tasks SET progress=? WHERE id=?', (min(avg, 99) if avg == 100 else avg, task_id))
        for uid in sorted(added):
            conn.execute('INSERT OR IGNORE INTO task_participants (task_id,user_id) VALUES (?,?)', (task_id, uid))
            create_notification(uid, '📌 تسک به شما واگذار شد',
                                f'Administrator تسک «{title}» را به شما واگذار کرد. لطفاً دریافت را تأیید کنید.',
                                'info', task_id, conn=conn)
        updated = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        add_task_observers(conn, updated, me, added_observers)
        if changes:
            task_event(conn, task_id, me['id'], 'admin_edited', 'ویرایش توسط Administrator: ' + '، '.join(changes))
            if task['creator_id'] and task['creator_id'] != me['id']:
                create_notification(task['creator_id'], '✏️ ویرایش تسک توسط Administrator',
                                    f'تسک «{title}» ویرایش شد: ' + '، '.join(changes), 'info', task_id, conn=conn)
        if status == 'done':
            notify_task_rating(conn, task_id)
        conn.commit()
        return jsonify({'success': True, 'task_id': task_id})
    finally:
        conn.close()


@app.route('/api/tasks/<int:task_id>/details', methods=['PATCH'])
@login_required
def edit_standalone_details(task_id):
    """Scoped metadata edits and additive assignments; never reset workflow progress."""
    data = request.get_json(silent=True)
    allowed_fields = {'brand_id', 'assignee_ids', 'priority', 'requirements', 'observer_ids'}
    if not isinstance(data, dict) or not data or set(data) - allowed_fields:
        return jsonify({'error': 'فقط برند، مسئولان جدید، ناظران جدید، اولویت و نیازمندی‌ها قابل ویرایش‌اند'}), 400
    conn = get_db()
    try:
        me = current_user()
        task = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
        if not task or task['project_id'] is not None or not can_view_task(conn, task, me):
            return jsonify({'error': 'تسک مستقل پیدا نشد'}), 404
        locked = payment_locked_response(conn, task_id)
        if locked:
            return locked
        if is_task_observer(conn, task_id, me['id']):
            return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
        if forwarded_by(conn, task_id, me['id']):
            return jsonify({'error': 'پس از فوروارد، تسک فقط برای پیگیری قابل مشاهده است'}), 403
        specialist_own = me['role'] == 'specialist' and can_edit_own_task(conn, me, task)
        if (me['role'] not in TASK_EDITOR_ROLES and not specialist_own) or not can_fully_edit_task(conn, me, task):
            return jsonify({'error': 'مجوز ویرایش مشخصات این تسک را ندارید'}), 403
        if task['status'] in ('done', 'rejected'):
            return jsonify({'error': 'مشخصات تسک بسته‌شده قابل ویرایش نیست'}), 409

        brand_id = task['brand_id']
        if 'brand_id' in data:
            if type(data['brand_id']) not in (int, str) or not str(data['brand_id']).isdigit():
                return jsonify({'error': 'برند نامعتبر است'}), 400
            brand_id = int(data['brand_id'])
            if not conn.execute('SELECT 1 FROM brands WHERE id=?', (brand_id,)).fetchone():
                return jsonify({'error': 'برند پیدا نشد'}), 400
            if me['role'] == 'manager' and not manages_brand(conn, me, brand_id):
                return jsonify({'error': 'فقط برندهای تحت مدیریت خود را می‌توانید انتخاب کنید'}), 403
            if me['role'] == 'supervisor' and brand_id not in user_brand_ids(conn, me['id']):
                return jsonify({'error': 'تغییر برند به خارج از محدوده سرپرستی مجاز نیست'}), 403

        priority = data.get('priority', task['priority'])
        if priority not in ('low', 'normal', 'high', 'urgent'):
            return jsonify({'error': 'اولویت نامعتبر است'}), 400
        requirements = (str(data['requirements'] or '').strip() if 'requirements' in data
                        else task['requirements'])
        if requirements is not None and len(requirements) > 5000:
            return jsonify({'error': 'نیازمندی‌ها بیش از حد طولانی است'}), 400
        current = set(get_task_assignees(conn, task_id))
        wanted = current
        if 'assignee_ids' in data:
            raw = data['assignee_ids']
            if not isinstance(raw, list) or any(type(uid) not in (int, str) or
                    not str(uid).isdigit() for uid in raw):
                return jsonify({'error': 'مسئولان تسک نامعتبرند'}), 400
            ids = [int(uid) for uid in raw]
            if len(ids) != len(set(ids)) or not ids or any(uid <= 0 for uid in ids):
                return jsonify({'error': 'مسئولان تسک نامعتبرند'}), 400
            wanted = set(ids)
            if not current <= wanted:
                return jsonify({'error': 'مسئولان قبلی قابل حذف نیستند؛ فقط فرد جدید اضافه کنید'}), 409
        added = wanted - current
        if any(not conn.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone() or
               forwarded_by(conn, task_id, uid) or is_task_observer(conn, task_id, uid) for uid in added):
            return jsonify({'error': 'مسئول جدید نامعتبر است یا قبلاً این تسک را فوروارد کرده است'}), 400
        added_observers, error = validate_added_observers(
            conn, task, data.get('observer_ids', get_task_observers(conn, task_id)), wanted, me['id'])
        if error:
            return error

        changes = []
        if brand_id != task['brand_id']:
            changes.append('برند')
        if priority != task['priority']:
            changes.append('اولویت')
        if requirements != task['requirements']:
            changes.append('نیازمندی‌ها')
        if added:
            changes.append(f'{len(added)} مسئول جدید')
        if added_observers:
            changes.append(f'{len(added_observers)} ناظر جدید')
        if changes:
            conn.execute('UPDATE tasks SET brand_id=?,priority=?,requirements=? WHERE id=?',
                         (brand_id, priority, requirements, task_id))
            for uid in sorted(added):
                conn.execute('INSERT INTO task_assignees (task_id,user_id) VALUES (?,?)', (task_id, uid))
                conn.execute('INSERT OR IGNORE INTO task_participants (task_id,user_id) VALUES (?,?)', (task_id, uid))
                create_notification(uid, '📌 مسئول جدید تسک',
                                    f'{me["name"]} تسک «{task["title"]}» را به شما واگذار کرد. لطفاً دریافت را تأیید کنید.',
                                    'info', task_id, conn=conn)
            add_task_observers(conn, task, me, added_observers)
            task_event(conn, task_id, me['id'], 'details_edited', 'ویرایش مشخصات: ' + '، '.join(changes))
            conn.commit()
        return jsonify({'success': True, 'added_assignee_ids': sorted(added),
                        'added_observer_ids': sorted(added_observers)})
    finally:
        conn.close()


@app.route('/api/tasks', methods=['POST'])
@login_required
def save_task():
    try:
        data = request.json
        if not data:
            return jsonify({'success': False, 'error': 'داده ارسال نشده'}), 400

        me = current_user()
        conn = get_db()
        c = conn.cursor()
        is_new = not data.get('id')
        project_id = None
        if is_new and data.get('project_id') not in (None, ''):
            try:
                project_id = int(data['project_id'])
            except (TypeError, ValueError):
                conn.close()
                return jsonify({'error': 'پروژه نامعتبر است'}), 400
            if not conn.execute('SELECT 1 FROM projects WHERE id=?', (project_id,)).fetchone() or not (
                    is_super(me) or is_project_member(conn, project_id, me['id'])):
                conn.close()
                return jsonify({'error': 'عضو این پروژه نیستید'}), 403
        if not is_new:
            existing = c.execute('SELECT * FROM tasks WHERE id=?', (data['id'],)).fetchone()
            if not existing:
                conn.close()
                return jsonify({'success': False, 'error': 'تسک پیدا نشد'}), 404
            locked = payment_locked_response(conn, existing['id'])
            if locked:
                conn.close()
                return locked
            if is_super(me):
                return administrator_update_task(conn, existing, me, data)
            if is_task_observer(conn, existing['id'], me['id']):
                conn.close()
                return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
            if existing['project_id'] is None and not can_fully_edit_task(conn, me, existing):
                if 'observer_ids' in data:
                    candidate, error = validate_added_observers(
                        conn, existing, data['observer_ids'],
                        set(get_task_assignees(conn, existing['id'])), me['id'])
                    if error:
                        conn.close()
                        return error
                    if candidate:
                        conn.close()
                        return jsonify({'error': 'افزودن ناظر نیازمند مجوز ویرایش تسک است'}), 403
                return update_standalone_task(conn, existing, me, data)
            if existing['project_id'] is None and data.get('project_id') not in (None, ''):
                conn.close()
                return jsonify({'error': 'تسک مستقل را نمی‌توان به پروژه منتقل کرد'}), 409
            if not can_view_task(conn, existing, me):
                conn.close()
                return jsonify({'error': 'تسک پیدا نشد'}), 404
            if forwarded_by(conn, existing['id'], me['id']):
                conn.close()
                return jsonify({'error': 'پس از فوروارد، تسک فقط برای پیگیری قابل مشاهده است'}), 403
            existing_assignees = get_task_assignees(conn, existing['id'])
            is_assignee = me['id'] in existing_assignees
            accepted = c.execute('SELECT acceptance_status FROM task_assignees WHERE task_id=? AND user_id=?',
                                 (existing['id'], me['id'])).fetchone() if is_assignee else None
            progress = existing['progress']
            personal_progress = None
            previous_personal_progress = (c.execute(
                'SELECT progress FROM task_user_progress WHERE task_id=? AND user_id=?',
                (existing['id'], me['id'])).fetchone() if existing['project_id'] is not None else None)
            previous_personal_progress = previous_personal_progress['progress'] if previous_personal_progress else 0
            if is_assignee and 'progress' in data:
                value = data['progress']
                if isinstance(value, bool) or not str(value).isdigit() or not 0 <= int(value) <= 100:
                    conn.close()
                    return jsonify({'error': 'درصد پیشرفت باید بین ۰ تا ۱۰۰ باشد'}), 400
                baseline = previous_personal_progress if existing['project_id'] is not None else progress
                if int(value) != baseline and (accepted['acceptance_status'] != 'accepted' or
                                                existing['status'] in ('done', 'rejected')):
                    conn.close()
                    return jsonify({'error': 'ثبت پیشرفت پس از تأیید و پیش از بسته‌شدن تسک مجاز است'}), 403
                if accepted['acceptance_status'] == 'accepted' and existing['status'] not in ('done', 'rejected'):
                    if existing['project_id'] is not None:
                        personal_progress = int(value)
                    else:
                        progress = int(value)
                    if int(value) == 100 and existing['project_id'] is None:
                        data['status'] = 'done'
            can_manage_task = can_fully_edit_task(conn, me, existing)
            if not can_manage_task and is_assignee:
                # مسئول تسک می‌تواند وضعیت و پیشرفت را تغییر دهد.
                data['title'] = existing['title']
                data['description'] = existing['description']
                data['assignee_ids'] = existing_assignees
                data['brand_id'] = existing['brand_id']
                data['priority'] = existing['priority']
                data['requirements'] = existing['requirements']
                data['approval'] = existing['approval']
                data['due_date'] = existing['due_date']
            elif not can_manage_task:
                conn.close()
                return jsonify({'success': False, 'error': 'دسترسی غیرمجاز'}), 403
            if is_assignee and not can_manage_task and accepted['acceptance_status'] != 'accepted' and \
               data.get('status') != existing['status']:
                conn.close()
                return jsonify({'error': 'ابتدا دریافت تسک را تأیید کنید'}), 403
            data.setdefault('approval', existing['approval'])
            if me['role'] not in MANAGEMENT_ROLES | {'supervisor'}:
                data['approval'] = existing['approval']
            elif data.get('approval') != existing['approval'] and not has_permission(conn, me, 'approve_tasks'):
                conn.close()
                return jsonify({'error': 'مجوز تأیید تسک برای شما فعال نشده است'}), 403
            if (data.get('status') == 'rejected' and existing['status'] != 'rejected' and
                    me['role'] in ('admin', 'manager', 'supervisor') and not has_permission(conn, me, 'approve_tasks')):
                conn.close()
                return jsonify({'error': 'مجوز رد تسک برای شما فعال نشده است'}), 403
            task_score = existing['task_score']
            quality_score = existing['quality_score']
            ethics_score = existing['ethics_score']
        else:
            task_score = quality_score = ethics_score = None
            data['status'] = 'new'

        if not data.get('title'):
            conn.close()
            return jsonify({'success': False, 'error': 'عنوان الزامی است'}), 400

        if not is_new and not can_manage_task:
            data['is_daily'] = existing['is_daily']
            data['estimated_minutes'] = existing['estimated_minutes']
        # The server owns the code. Client-provided task_code is ignored on create and edit.
        code = None if is_new else existing['task_code']
        is_daily = 1 if data.get('is_daily') else 0
        try:
            minutes = int(data.get('estimated_minutes')) if is_daily and data.get('estimated_minutes') not in (None, '') else None
        except (TypeError, ValueError):
            minutes = -1
        if is_daily and (minutes is None or not 1 <= minutes <= 1440):
            conn.close()
            return jsonify({'success': False, 'error': 'مدت کار روزانه باید بین ۱ تا ۱۴۴۰ دقیقه باشد'}), 400
        if not is_daily:
            minutes = None

        assignee_ids_raw = data.get('assignee_ids', [])
        if isinstance(assignee_ids_raw, str):
            assignee_ids_raw = assignee_ids_raw.split(',')
        try:
            assignee_ids_list = [int(x) for x in assignee_ids_raw if str(x).strip() != '']
        except (TypeError, ValueError):
            conn.close()
            return jsonify({'success': False, 'error': 'شناسه‌های تخصیص نامعتبر است'}), 400

        assignee_ids_list = list(dict.fromkeys(assignee_ids_list))
        if is_new:
            raw_observers = data.get('observer_ids', [])
            if not isinstance(raw_observers, list) or any(type(uid) not in (int, str) or
                    not str(uid).isdigit() for uid in raw_observers):
                conn.close()
                return jsonify({'error': 'ناظر تسک نامعتبر است'}), 400
            observer_ids = [int(uid) for uid in raw_observers]
            if (len(observer_ids) != len(set(observer_ids)) or any(uid <= 0 or uid == me['id'] or
                    not c.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone()
                    for uid in observer_ids) or set(observer_ids) & set(assignee_ids_list)):
                conn.close()
                return jsonify({'error': 'ناظر نباید سازنده یا مسئول همین تسک باشد'}), 400
        else:
            added_observers, error = validate_added_observers(
                conn, existing, data.get('observer_ids', get_task_observers(conn, existing['id'])),
                set(assignee_ids_list), me['id'])
            if error:
                conn.close()
                return error
            if added_observers and not can_manage_task:
                conn.close()
                return jsonify({'error': 'افزودن ناظر نیازمند مجوز ویرایش تسک است'}), 403
            if set(get_task_observers(conn, existing['id'])) & set(assignee_ids_list):
                conn.close()
                return jsonify({'error': 'ناظر نمی‌تواند مسئول این تسک شود'}), 400
        if not is_new and existing['project_id'] is not None:
            if data.get('project_id', existing['project_id']) != existing['project_id']:
                conn.close()
                return jsonify({'error': 'تسک پروژه را نمی‌توان از پروژه جدا کرد'}), 409
            # An existing project assignment is history. Editors can change the form
            # and add people, but cannot undo somebody's acceptance or progress.
            removed = set(existing_assignees) - set(assignee_ids_list)
            if removed and (not can_manage_task or any(c.execute('''SELECT 1 FROM task_assignees
                    WHERE task_id=? AND user_id=? AND acceptance_status='accepted' ''',
                    (existing['id'], uid)).fetchone() or
                    c.execute('''SELECT COALESCE((SELECT progress FROM task_user_progress
                        WHERE task_id=? AND user_id=?),0) AS progress''',
                        (existing['id'], uid)).fetchone()['progress'] > 0 or
                    c.execute('''SELECT 1 FROM project_events WHERE task_id=? AND actor_id=?''',
                              (existing['id'], uid)).fetchone()
                    for uid in removed)):
                conn.close()
                return jsonify({'error': 'مسئولی که در پروژه اقدامی ثبت کرده است قابل حذف نیست'}), 409
            if (personal_progress is not None and personal_progress < previous_personal_progress) or (
                    existing['status'] in ('done', 'rejected') and data['status'] != existing['status']) or (
                    existing['status'] == 'progress' and data['status'] == 'new'):
                conn.close()
                return jsonify({'error': 'برگشت وضعیت یا کاهش پیشرفت در پروژه مجاز نیست'}), 409
            if existing['approval'] and data.get('approval') != existing['approval']:
                conn.close()
                return jsonify({'error': 'تأیید ثبت‌شده در پروژه قابل بازگرداندن نیست'}), 409
        if not is_new and any(forwarded_by(conn, existing['id'], uid) for uid in assignee_ids_list):
            conn.close()
            return jsonify({'error': 'فورواردکننده فقط دسترسی مشاهده دارد و نمی‌تواند دوباره مسئول شود'}), 400
        if not assignee_ids_list:
            conn.close()
            return jsonify({'success': False, 'error': 'حداقل یک مسئول انتخاب کنید'}), 400
        if any(not c.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone()
               for uid in assignee_ids_list):
            conn.close()
            return jsonify({'success': False, 'error': 'یکی از مسئولان انتخاب‌شده وجود ندارد'}), 400
        if data.get('status') not in ('new', 'progress', 'done', 'rejected'):
            conn.close()
            return jsonify({'error': 'وضعیت تسک نامعتبر است'}), 400
        if not is_new and data['status'] == 'done' and existing['status'] != 'done' and \
           (not is_assignee or accepted['acceptance_status'] != 'accepted'):
            conn.close()
            return jsonify({'error': 'انجام تسک باید توسط مسئول تأییدکننده ثبت شود'}), 403
        if not is_new and data['status'] == 'done' and existing['status'] != 'done':
            if existing['project_id'] is None:
                progress = 100
        if not is_new and existing['project_id'] is not None:
            per_user = {r['user_id']: r['progress'] for r in c.execute(
                'SELECT user_id,progress FROM task_user_progress WHERE task_id=?', (existing['id'],))}
            if personal_progress is not None:
                per_user[me['id']] = personal_progress
            all_finished = bool(assignee_ids_list) and all(per_user.get(uid, 0) == 100 for uid in assignee_ids_list)
            if data['status'] == 'done' and not all_finished:
                conn.close()
                return jsonify({'error': 'ابتدا پیشرفت همه مسئولان باید به ۱۰۰٪ برسد'}), 409
            if all_finished and data['status'] != 'rejected':
                data['status'] = 'done'
            elif personal_progress is not None and personal_progress > 0 and data['status'] == 'new':
                data['status'] = 'progress'
            average = round(sum(per_user.get(uid, 0) for uid in assignee_ids_list) / len(assignee_ids_list)) if assignee_ids_list else 0
            progress = max(existing['progress'], average)
            if all_finished:
                progress = 100
        if not is_new and data['status'] in ('progress', 'done'):
            accepted_ids = {r['user_id'] for r in c.execute(
                "SELECT user_id FROM task_assignees WHERE task_id=? AND acceptance_status='accepted'", (existing['id'],))}
            if data['status'] == 'done' and not set(assignee_ids_list).issubset(accepted_ids):
                conn.close()
                return jsonify({'error': 'ابتدا همه مسئولان باید دریافت تسک را تأیید کنند'}), 400
            if data['status'] == 'progress' and not set(assignee_ids_list).intersection(accepted_ids):
                conn.close()
                return jsonify({'error': 'ابتدا یکی از مسئولان باید دریافت تسک را تأیید کند'}), 400

        if is_new:
            if me['role'] == 'manager':
                try:
                    selected_brand = int(data.get('brand_id'))
                except (TypeError, ValueError):
                    conn.close()
                    return jsonify({'error': 'یکی از برندهای خود را انتخاب کنید'}), 400
                if not manages_brand(conn, me, selected_brand):
                    conn.close()
                    return jsonify({'error': 'این برند تحت مدیریت شما نیست'}), 403
                data['brand_id'] = selected_brand
            elif me['role'] not in EXECUTIVE_ROLES:
                # کارکنانی که در چند برند هستند یکی از برندهای خودشان را انتخاب می‌کنند
                try:
                    selected_brand = int(data.get('brand_id'))
                except (TypeError, ValueError):
                    selected_brand = None
                data['brand_id'] = selected_brand if selected_brand in user_brand_ids(conn, me['id']) else me['brand_id']
        else:
            if me['role'] == 'manager' and can_manage_task:
                try:
                    selected_brand = int(data.get('brand_id'))
                except (TypeError, ValueError):
                    conn.close()
                    return jsonify({'error': 'برند نامعتبر است'}), 400
                if selected_brand != existing['brand_id'] and not manages_brand(conn, me, selected_brand):
                    conn.close()
                    return jsonify({'error': 'فقط برندهای تحت مدیریت خود را می‌توانید انتخاب کنید'}), 403
                data['brand_id'] = selected_brand
            elif me['role'] not in EXECUTIVE_ROLES:
                data['brand_id'] = existing['brand_id']
            elif not c.execute('SELECT 1 FROM brands WHERE id=?', (data.get('brand_id'),)).fetchone():
                conn.close()
                return jsonify({'error': 'برند پیدا نشد'}), 400
        if is_new:
            creator_id = me['id']
            task_category, task_subcategory, payment_order, sale_term = None, None, None, None
            if project_id is None:
                task_category, task_subcategory, category_error = validate_task_category(data)
                if not category_error and task_category == 'finance' and task_subcategory == 'payment_order':
                    category_error = 'دستور پرداخت از طریق فرم «روند پرداخت» ساخته می‌شود'
                if not category_error:
                    payment_order, category_error = clean_payment_order(task_category, task_subcategory, data.get('payment_order'))
                if not category_error:
                    sale_term, category_error = clean_sale_term(task_category, data)
                if category_error:
                    conn.close()
                    return jsonify({'error': category_error}), 400
            lock_for_create(conn)
            duplicate = recent_duplicate_task(conn, creator_id, data['title'], data.get('description'),
                                              project_id, assignee_ids_list)
            if duplicate:
                conn.close()
                return jsonify({'success': True, 'task_id': duplicate['id'], 'duplicate': True})
            c.execute("""INSERT INTO tasks (title, description, creator_id, brand_id, 
                         status, priority, progress, requirements, approval, due_date, created_at,
                         task_code, is_daily, estimated_minutes, task_score, quality_score, ethics_score, project_id,
                         category, subcategory, payment_order)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (data['title'], data.get('description'), creator_id,
                       data.get('brand_id'), data.get('status', 'new'),
                       data.get('priority', 'normal'), 0,
                       data.get('requirements'), None,
                       data.get('due_date'), int(datetime.now().timestamp() * 1000),
                       None, is_daily, minutes, task_score, quality_score, ethics_score, project_id,
                       task_category, task_subcategory, payment_order))
            task_id = c.lastrowid
            if sale_term:
                c.execute('UPDATE tasks SET sale_term=? WHERE id=?', (sale_term, task_id))
            generated = f'TASK-{task_id:06d}'
            if c.execute('SELECT 1 FROM tasks WHERE task_code=? AND id!=?', (generated, task_id)).fetchone():
                generated = f'TASK-{task_id:06d}-{secrets.token_hex(3).upper()}'
            c.execute('UPDATE tasks SET task_code=? WHERE id=?', (generated, task_id))
            set_task_assignees(conn, task_id, assignee_ids_list)
            conn.executemany('INSERT INTO task_observers (task_id,user_id) VALUES (?,?)',
                             [(task_id, uid) for uid in observer_ids])
            conn.executemany('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)',
                             [(task_id, uid) for uid in set(assignee_ids_list) | {me['id']}])
            if project_id is not None:
                conn.executemany('INSERT INTO task_user_progress (task_id,user_id,progress,updated_at) VALUES (?,?,0,?)',
                                 [(task_id, uid, int(time.time() * 1000)) for uid in assignee_ids_list])
                conn.executemany('INSERT OR IGNORE INTO project_members (project_id, user_id) VALUES (?,?)',
                                 [(project_id, uid) for uid in set(assignee_ids_list) | set(observer_ids)])
                conn.execute('''INSERT OR IGNORE INTO task_participants (task_id, user_id)
                    SELECT ?, user_id FROM project_members WHERE project_id=?''', (task_id, project_id))
                task_event(conn, task_id, me['id'], 'task_created', 'تسک به پروژه اضافه شد')

            creator_name = me['name'] or 'سیستم'
            for aid in assignee_ids_list:
                create_notification(aid, '📌 تسک جدید به شما واگذار شد',
                                    f'تسک "{data["title"]}" توسط {creator_name} به شما واگذار شد.',
                                    'info', task_id, conn=conn)
            for uid in observer_ids:
                create_notification(uid, '👁️ ناظر تسک جدید',
                                    f'شما ناظر تسک «{data["title"]}» هستید و می‌توانید روند آن را مشاهده کنید.',
                                    'info', task_id, conn=conn)
        else:
            old = existing
            category_error = apply_task_category_edit(conn, existing, data)
            if category_error:
                conn.close()
                return jsonify({'error': category_error}), 400
            was_done = old and old['status'] == 'done'
            is_done_now = data.get('status') == 'done'
            completed_at = (old['completed_at'] or int(datetime.now().timestamp() * 1000)) if is_done_now else None
            c.execute("""UPDATE tasks SET title=?, description=?, brand_id=?, 
                         status=?, priority=?, progress=?, requirements=?, approval=?, due_date=?, completed_at=?,
                         task_code=?, is_daily=?, estimated_minutes=?, notified_overdue=?,
                         task_score=?, quality_score=?, ethics_score=? WHERE id=?""",
                      (data['title'], data.get('description'), data.get('brand_id'),
                       data.get('status'), data.get('priority', 'normal'), progress,
                       data.get('requirements'), data.get('approval'), data.get('due_date'),
                       completed_at, code or existing['task_code'], is_daily, minutes,
                       0 if data.get('due_date') != existing['due_date'] or (was_done and not is_done_now) else existing['notified_overdue'],
                       task_score, quality_score, ethics_score,
                       data['id']))
            task_id = data['id']
            if existing['project_id'] is not None and personal_progress is not None:
                c.execute('''INSERT INTO task_user_progress (task_id,user_id,progress,updated_at)
                    VALUES (?,?,?,?) ON CONFLICT(task_id,user_id) DO UPDATE SET
                    progress=excluded.progress,updated_at=excluded.updated_at''',
                    (task_id, me['id'], personal_progress, int(time.time() * 1000)))
            set_task_assignees(conn, task_id, assignee_ids_list)
            conn.executemany('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)',
                             [(task_id, uid) for uid in assignee_ids_list])
            if existing['project_id'] is not None and can_manage_task:
                new_ids = set(assignee_ids_list) - set(existing_assignees)
                removed_ids = set(existing_assignees) - set(assignee_ids_list)
                conn.executemany('''INSERT OR IGNORE INTO task_user_progress
                    (task_id,user_id,progress,updated_at) VALUES (?,?,0,?)''',
                    [(task_id, uid, int(time.time() * 1000)) for uid in new_ids])
                conn.executemany('INSERT OR IGNORE INTO project_members (project_id,user_id) VALUES (?,?)',
                                 [(existing['project_id'], uid) for uid in new_ids])
                for uid in removed_ids:
                    conn.execute('DELETE FROM task_user_progress WHERE task_id=? AND user_id=?', (task_id, uid))
                changed = [label for label, before, after in (
                    ('عنوان', old['title'], data['title']),
                    ('توضیحات', old['description'] or '', data.get('description') or ''),
                    ('برند', old['brand_id'], data['brand_id']),
                    ('اولویت', old['priority'], data.get('priority', 'normal')),
                    ('مهلت', old['due_date'] or '', data.get('due_date') or ''),
                    ('کار روزانه', bool(old['is_daily']), bool(is_daily)),
                    ('مدت روزانه', old['estimated_minutes'], minutes),
                    ('نیازمندی‌ها', old['requirements'] or '', data.get('requirements') or ''),
                ) if before != after]
                if new_ids:
                    changed.append(f'{len(new_ids)} مسئول جدید')
                if removed_ids:
                    changed.append(f'{len(removed_ids)} مسئولِ بدون اقدام حذف شد')
                if added_observers:
                    changed.append(f'{len(added_observers)} ناظر جدید')
                if changed:
                    task_event(conn, task_id, me['id'], 'details_edited',
                               'ویرایش مشخصات: ' + '، '.join(changed))
            if existing['project_id'] is not None and (progress != old['progress'] or data['status'] != old['status'] or
                                                       personal_progress is not None and personal_progress != previous_personal_progress):
                task_event(conn, task_id, me['id'], 'progress',
                           f'وضعیت: {data["status"]}، پیشرفت {me["name"]}: {personal_progress if personal_progress is not None else previous_personal_progress}٪، کل تسک: {progress}٪')
            if existing['project_id'] is not None and data.get('approval') != old['approval']:
                task_event(conn, task_id, me['id'], 'approved', f'بررسی تسک: {data["approval"]}')
            for aid in set(assignee_ids_list) - set(existing_assignees):
                create_notification(aid, '📌 تسک جدید به شما واگذار شد',
                                    f'تسک "{data["title"]}" توسط {me["name"] or "سیستم"} به شما واگذار شد.',
                                    'info', task_id, conn=conn)
            add_task_observers(conn, existing, me, added_observers)
            if is_done_now and not was_done:
                task = c.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
                brand = c.execute('SELECT manager_id FROM brands WHERE id=?', (task['brand_id'],)).fetchone()
                recipients = {task['creator_id'], brand['manager_id'] if brand else None} - {None, me['id']}
                for uid in recipients:
                    create_notification(uid, '✅ تسک انجام شد؛ آماده امتیازدهی',
                                        f'{me["name"]} تسک «{task["title"]}» را با پیشرفت {progress}٪ تکمیل کرد. اکنون می‌توانید امتیاز بدهید.',
                                        'success', task_id, conn=conn)
        notify_task_rating(conn, task_id)
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'task_id': task_id})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'خطای داخلی سرور'}), 500


@app.route('/api/tasks/<int:id>/rating', methods=['POST'])
@permission_required('rate_tasks')
def rate_task(id):
    data = request.json or {}
    values = (data.get('task_score'), data.get('quality_score'))
    if any(isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= 10
           for value in values):
        return jsonify({'error': 'امتیاز کمی و کیفی باید بین ۱ تا ۱۰ باشد'}), 400
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone()
    if not task:
        conn.close()
        return jsonify({'error': 'تسک پیدا نشد'}), 404
    if task['status'] != 'done':
        conn.close()
        return jsonify({'error': 'امتیاز تسک پس از انجام آن ثبت می‌شود'}), 400
    me = current_user()
    if not can_view_task(conn, task, me):
        conn.close()
        return jsonify({'error': 'تسک پیدا نشد'}), 404
    if is_task_observer(conn, id, me['id']):
        conn.close()
        return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
    if forwarded_by(conn, id, me['id']):
        conn.close()
        return jsonify({'error': 'این تسک پس از فوروارد فقط خواندنی است'}), 403
    if me['role'] == 'manager' and not manages_brand(conn, me, task['brand_id']):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if me['role'] == 'supervisor' and not supervisor_task_scope(conn, me, task):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if task['project_id'] is not None and (task['task_score'] is not None or task['quality_score'] is not None):
        conn.close()
        return jsonify({'error': 'امتیاز ثبت‌شده در پروژه قابل برگشت یا تغییر نیست'}), 409
    conn.execute('UPDATE tasks SET task_score=?, quality_score=? WHERE id=?',
                 (int(values[0]), int(values[1]), id))
    task_event(conn, id, me['id'], 'rated', f'امتیاز کمی {values[0]}، کیفی {values[1]} ثبت شد')
    notify_task_rating(conn, id)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


def manager_owns_task_creator(conn, me, task):
    """تسک خود مدیر برند یا تسکی که یکی از کاربران (کارکنان) برندهای او ساخته است."""
    if task['creator_id'] == me['id']:
        return True
    creator = conn.execute('SELECT id, role FROM users WHERE id=?', (task['creator_id'],)).fetchone()
    return bool(creator) and creator['role'] in MANAGER_STAFF_ROLES and manages_user(conn, me, creator)


def can_delete_task(conn, me, task, delete_perm=None):
    if is_task_observer(conn, task['id'], me['id']) or forwarded_by(conn, task['id'], me['id']):
        return False
    if is_super(me):
        return True
    if delete_perm is None:
        delete_perm = has_permission(conn, me, 'delete_tasks')
    if me['role'] == 'manager':
        # مدیر برند تسک‌های کاربران خود را بدون نیاز به مجوز جداگانه حذف می‌کند
        if manager_owns_task_creator(conn, me, task):
            return True
        return delete_perm and manages_brand(conn, me, task['brand_id']) and can_view_task(conn, task, me)
    if not delete_perm:
        return False
    if me['role'] == 'supervisor':
        return supervisor_task_scope(conn, me, task) and can_view_task(conn, task, me)
    return can_view_task(conn, task, me)


@app.route('/api/tasks/<int:id>', methods=['DELETE'])
@login_required
def delete_task(id):
    me = current_user()
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (id,)).fetchone()
    if not task:
        conn.close()
        return jsonify({'success': False, 'error': 'تسک پیدا نشد'}), 404
    if not can_delete_task(conn, me, task):
        conn.close()
        return jsonify({'success': False, 'error': 'دسترسی غیرمجاز'}), 403
    move_task_to_trash(conn, task, me['id'])
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'trashed': True})


@app.route('/api/trash')
@roles_required(*SUPER_ROLES)
def list_trash():
    conn = get_db()
    rows = [dict(r) for r in conn.execute('''SELECT tr.id, tr.item_type, tr.task_count, tr.task_id, tr.task_code, tr.title, tr.project_id,
        tr.project_name, tr.brand_id, tr.creator_id, tr.deleted_by, tr.deleted_at,
        cu.name AS creator_name, du.name AS deleted_by_name, b.name AS brand_name
        FROM task_trash tr LEFT JOIN users cu ON cu.id=tr.creator_id LEFT JOIN users du ON du.id=tr.deleted_by
        LEFT JOIN brands b ON b.id=tr.brand_id ORDER BY tr.deleted_at DESC, tr.id DESC''')]
    conn.close()
    return jsonify(rows)


@app.route('/api/trash/<int:trash_id>/restore', methods=['POST'])
@roles_required(*SUPER_ROLES)
def restore_trash(trash_id):
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM task_trash WHERE id=?', (trash_id,)).fetchone()
        if not row:
            return jsonify({'error': 'مورد در سطل زباله پیدا نشد'}), 404
        try:
            task_id = restore_task_from_trash(conn, row)
        except (ValueError, sqlite3.IntegrityError) as exc:
            conn.rollback()
            return jsonify({'error': f'بازگردانی ممکن نشد: {exc}'}), 409
        conn.commit()
        return jsonify({'success': True, 'restored_id': task_id, 'item_type': row['item_type'] or 'task'})
    finally:
        conn.close()


def _trash_files(row):
    try:
        snapshot = json.loads(row['snapshot'])
    except (ValueError, TypeError):
        return []
    snaps = snapshot.get('task_snapshots', []) if 'project' in snapshot else [snapshot]
    return [a['filename'] for snap in snaps for a in snap.get('task_attachments', [])]


@app.route('/api/trash/<int:trash_id>', methods=['DELETE'])
@roles_required(*SUPER_ROLES)
def purge_trash(trash_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM task_trash WHERE id=?', (trash_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'مورد در سطل زباله پیدا نشد'}), 404
    files = _trash_files(row)
    conn.execute('DELETE FROM task_trash WHERE id=?', (trash_id,))
    conn.commit()
    conn.close()
    remove_stored_files(files)
    return jsonify({'success': True})


@app.route('/api/trash', methods=['DELETE'])
@roles_required(*SUPER_ROLES)
def empty_trash():
    conn = get_db()
    rows = conn.execute('SELECT * FROM task_trash').fetchall()
    files = [f for r in rows for f in _trash_files(r)]
    conn.execute('DELETE FROM task_trash')
    conn.commit()
    conn.close()
    remove_stored_files(files)
    return jsonify({'success': True, 'count': len(rows)})


@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    task_id = request.form.get('task_id')
    try:
        task_id = int(task_id)
    except (ValueError, TypeError):
        return jsonify({'error': 'شناسه تسک نامعتبر است'}), 400
    conn = get_db()
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
    me = current_user()
    allowed = task and is_super(me) or task and can_view_task(conn, task, me) and (
        task['status'] not in ('done', 'rejected') or forwarded_by(conn, task_id, me['id'])) and not is_task_observer(conn, task_id, me['id'])
    conn.close()
    if not allowed:
        return jsonify({'error': 'دسترسی تغییر این تسک را ندارید'}), 403
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'فایلی ارسال نشده'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'success': False, 'error': 'نوع فایل مجاز نیست'}), 400
    original_name = file.filename
    ext = original_name.rsplit('.', 1)[-1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    conn = get_db()
    c = conn.cursor()
    # در تسک چندمرحله‌ای، فایل به مرحلهٔ فعلی نسبت داده می‌شود
    stage_no = c.execute('SELECT MAX(stage_no) FROM task_stages WHERE task_id=?', (task_id,)).fetchone()[0]
    c.execute(
        'INSERT INTO task_attachments (task_id, filename, original_name, file_type, file_size, uploaded_at, stage_no) '
        'VALUES (?,?,?,?,?,?,?)',
        (task_id, filename, original_name, file.content_type or 'application/octet-stream',
         os.path.getsize(filepath), int(datetime.now().timestamp() * 1000), stage_no))
    aid = c.lastrowid
    task_event(conn, task_id, me['id'], 'uploaded', f'فایل «{original_name}» اضافه شد')
    conn.commit();
    conn.close()
    return jsonify({'success': True, 'attachment': {'id': aid, 'filename': filename, 'original_name': original_name,
                                                    'file_type': file.content_type,
                                                    'file_size': os.path.getsize(filepath)}})


@app.route('/api/attachments/<int:id>', methods=['DELETE'])
@login_required
def delete_attachment(id):
    conn = get_db()
    c = conn.cursor()
    att = c.execute('SELECT filename, task_id FROM task_attachments WHERE id=?', (id,)).fetchone()
    if not att:
        conn.close()
        return jsonify({'error': 'فایل پیدا نشد'}), 404
    task = c.execute('SELECT * FROM tasks WHERE id=?', (att['task_id'],)).fetchone()
    me = current_user()
    if not task:
        conn.close()
        return jsonify({'error': 'تسک پیدا نشد'}), 404
    if is_super(me):
        pass  # Administrator: حذف فایل هر تسک بدون محدودیت
    elif not can_view_task(conn, task, me) or forwarded_by(conn, task['id'], me['id']) or is_task_observer(conn, task['id'], me['id']):
        conn.close()
        return jsonify({'error': 'دسترسی تغییر این تسک را ندارید'}), 403
    elif task['project_id'] is not None:
        conn.close()
        return jsonify({'error': 'فایل ثبت‌شده در پروژه قابل حذف نیست'}), 409
    elif me['id'] != task['creator_id'] or not task['creator_edit_allowed']:
        conn.close()
        return jsonify({'error': 'حذف فایل تسک مستقل نیازمند مجوز Administrator برای سازنده است'}), 403
    fp = os.path.join(app.config['UPLOAD_FOLDER'], att['filename'])
    if os.path.exists(fp): os.remove(fp)
    c.execute('DELETE FROM task_attachments WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/comments', methods=['POST'])
@login_required
def add_comment():
    data = request.json or {}
    comment = str(data.get('comment') or '').strip()
    mentions = data.get('mention_ids', [])
    if not isinstance(mentions, list):
        return jsonify({'error': 'گیرندگان پیام نامعتبرند'}), 400
    try:
        mention_ids = {int(uid) for uid in mentions}
    except (TypeError, ValueError):
        return jsonify({'error': 'گیرندگان پیام نامعتبرند'}), 400
    try:
        task_id = int(data.get('task_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'شناسه تسک نامعتبر است'}), 400
    if not comment or len(comment) > 5000:
        return jsonify({'error': 'متن گفت‌وگو باید بین ۱ تا ۵۰۰۰ نویسه باشد'}), 400
    me = current_user()
    conn = get_db()
    c = conn.cursor()
    task = c.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
    if not task:
        conn.close()
        return jsonify({'error': 'تسک پیدا نشد'}), 404
    assignees = set(get_task_assignees(conn, task_id))
    if not can_view_task(conn, task, me):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if is_task_observer(conn, task_id, me['id']):
        conn.close()
        return jsonify({'error': 'ناظر فقط می‌تواند تسک را مشاهده کند'}), 403
    participants = {r['user_id'] for r in c.execute(
        'SELECT user_id FROM task_participants WHERE task_id=?', (task_id,))}
    if not mention_ids.issubset(participants):
        conn.close()
        return jsonify({'error': 'فقط افراد حاضر در روند تسک را می‌توان خطاب قرار داد'}), 400
    if task['status'] in ('done', 'rejected') and not forwarded_by(conn, task_id, me['id']):
        conn.close()
        return jsonify({'error': 'گفت‌وگوی تسک تکمیل‌شده بسته شده است'}), 409
    comment_id = c.execute('INSERT INTO task_comments (task_id, user_id, comment, created_at) VALUES (?,?,?,?)',
                           (task_id, me['id'], comment, int(datetime.now().timestamp() * 1000))).lastrowid
    c.executemany('INSERT INTO task_comment_mentions (comment_id, user_id) VALUES (?,?)',
                  [(comment_id, uid) for uid in sorted(mention_ids)])
    task_event(conn, task_id, me['id'], 'commented',
               f'پیام برای {", ".join(r["name"] for r in c.execute("SELECT name FROM users WHERE id IN (" + ",".join("?" * len(mention_ids)) + ")", tuple(mention_ids))) if mention_ids else "همه اعضای گفت‌وگو"}: {comment[:100]}')
    brand = c.execute('SELECT manager_id FROM brands WHERE id=?', (task['brand_id'],)).fetchone()
    recipients = mention_ids if mention_ids else assignees | participants | {task['creator_id'], brand['manager_id'] if brand else None}
    if task['project_id'] is not None:
        recipients = {uid for uid in recipients if uid is not None and (person := c.execute(
            'SELECT id,role,brand_id,name FROM users WHERE id=?', (uid,)).fetchone()) and
            can_view_task(conn, task, person)}
    for uid in recipients - {None, me['id']}:
        create_notification(uid, f'💬 پیام جدید در «{task["title"][:30]}»',
                            f'{me["name"]}: {comment[:80]}', 'info', task_id, conn=conn)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications')
@login_required
def get_notifications():
    user_id = current_user()['id']  # نوتیفیکیشن هر کاربر فقط برای خودش قابل مشاهده است
    check_overdue_tasks()
    check_due_reminders()
    conn = get_db()
    me = current_user()
    notifs = []
    for row in conn.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT 200',
                            (user_id,)):
        if row['task_id']:
            task = conn.execute('SELECT * FROM tasks WHERE id=?', (row['task_id'],)).fetchone()
            if task and not can_view_task(conn, task, me):
                continue
        notifs.append(dict(row))
    for notice in notifs:
        notice['title'] = repair_notification_text(notice['title'])
        notice['message'] = repair_notification_text(notice['message'])
    conn.close()
    return jsonify(notifs)


@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_one_read(notification_id):
    conn = get_db()
    cursor = conn.execute('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?',
                          (notification_id, current_user()['id']))
    if not cursor.rowcount:
        conn.close()
        return jsonify({'error': 'اعلان پیدا نشد'}), 404
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/read', methods=['POST'])
@login_required
def mark_read():
    user_id = current_user()['id']
    conn = get_db()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id=?', (user_id,))
    conn.commit();
    conn.close()
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def get_stats():
    me = current_user()
    user_id, role = me['id'], me['role']
    conn = get_db()
    c = conn.cursor()
    can_analyze = has_permission(conn, me, 'view_analytics')
    where, params = [], []
    if role == 'manager' and can_analyze:
        where.append('t.brand_id IN (SELECT id FROM brands WHERE manager_id=?)')
        params.append(user_id)
    elif role == 'supervisor' and can_analyze:
        where.append(f'''t.brand_id IN (SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?) AND ? IS NOT NULL AND
            (EXISTS(SELECT 1 FROM users u WHERE u.id=t.creator_id AND u.department_id=? AND {member_of_brand_sql('u', 't.brand_id')})
             OR EXISTS(SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
                WHERE ta.task_id=t.id AND u.department_id=? AND {member_of_brand_sql('u', 't.brand_id')}))''')
        params.extend([me['id'], me['department_id'], me['department_id'], me['department_id']])
    elif role not in MANAGEMENT_ROLES or (role in ('admin', 'manager') and not can_analyze):
        where.append("(EXISTS(SELECT 1 FROM task_assignees ta WHERE ta.task_id = t.id AND ta.user_id = ?) OR t.creator_id = ?)")
        params.extend([user_id, user_id])
    ws = ' AND '.join(where) if where else '1=1'

    c.execute(f'SELECT status, COUNT(*) as count FROM tasks t WHERE {ws} GROUP BY status', params)
    status_dist = {r['status']: r['count'] for r in c.fetchall()}

    brand_perf, emp_perf = [], []
    if role in MANAGEMENT_ROLES | {'supervisor'} and can_analyze:
        brand_filter = ('WHERE b.manager_id=?' if role == 'manager' else
                        f'WHERE b.id IN (SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)' if role == 'supervisor' else '')
        join_scope = f'''AND (EXISTS(SELECT 1 FROM users u WHERE u.id=t.creator_id
            AND u.department_id=? AND {member_of_brand_sql('u', 'b.id')}) OR EXISTS(
            SELECT 1 FROM task_assignees ta JOIN users u ON u.id=ta.user_id
            WHERE ta.task_id=t.id AND u.department_id=? AND {member_of_brand_sql('u', 'b.id')}))''' if role == 'supervisor' else ''
        c.execute(f"""SELECT b.id, b.name, b.color, COUNT(t.id) as total,
                     SUM(CASE WHEN t.status='done' THEN 1 ELSE 0 END) as done,
                     AVG(CASE WHEN t.status='done' THEN t.task_score END) as avg_task_score
                     FROM brands b LEFT JOIN tasks t ON b.id = t.brand_id {join_scope}
                     {brand_filter} GROUP BY b.id""", ([me['department_id'], me['department_id'], me['id']] if role == 'supervisor'
                       else [user_id] if role == 'manager' else []))
        brand_perf = [dict(r) for r in c.fetchall()]

        today_for_performance = datetime.now().strftime('%Y-%m-%d')
        employee_visibility = (member_of_brands_sql('u', '(SELECT id FROM brands WHERE manager_id=?)') if role == 'manager'
            else member_of_brands_sql('u', f'(SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)') + ' AND u.department_id=?'
            if role == 'supervisor' else '1=1')
        employee_params = ([today_for_performance] + params +
                           ([user_id] if role == 'manager' else
                            [me['id'], me['department_id']] if role == 'supervisor' else []))
        c.execute(f"""SELECT u.id, u.name, COUNT(t.id) as total,
                      COALESCE(SUM(CASE WHEN t.status='done' THEN 1 ELSE 0 END), 0) as done,
                      COALESCE(SUM(CASE WHEN t.due_date IS NOT NULL AND t.due_date != ''
                           AND t.due_date < ? AND t.status NOT IN ('done','rejected')
                           THEN 1 ELSE 0 END), 0) as overdue,
                      AVG(CASE WHEN t.status='done' THEN t.task_score END) as avg_task_score,
                      AVG(CASE WHEN t.status='done' THEN t.quality_score END) as avg_quality_score
                      FROM users u 
                      LEFT JOIN task_assignees ta ON ta.user_id = u.id
                      LEFT JOIN tasks t ON t.id = ta.task_id AND ({ws})
                      WHERE u.role NOT IN ('admin','administrator','manager') AND ({employee_visibility})
                      GROUP BY u.id ORDER BY done DESC, u.name""", employee_params)
        emp_perf = [dict(r) for r in c.fetchall()]

    daily = []
    for i in range(13, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        next_day = (datetime.now() - timedelta(days=i - 1)).strftime('%Y-%m-%d') if i > 0 else datetime.now().strftime(
            '%Y-%m-%d')
        s = int(datetime.strptime(day, '%Y-%m-%d').timestamp() * 1000)
        e = int(datetime.strptime(next_day, '%Y-%m-%d').timestamp() * 1000)
        c.execute(f'SELECT COUNT(*) as count FROM tasks t WHERE {ws} AND t.completed_at >= ? AND t.completed_at < ?',
                  params + [s, e])
        daily.append({'date': day, 'count': c.fetchone()['count']})

    today = datetime.now().strftime('%Y-%m-%d')
    c.execute(
        f"""SELECT COUNT(*) as count FROM tasks t WHERE {ws} AND t.due_date != '' AND t.due_date < ? AND t.status NOT IN ('done','rejected')""",
        params + [today])
    overdue_count = c.fetchone()['count']

    c.execute(f'SELECT priority, COUNT(*) as count FROM tasks t WHERE {ws} GROUP BY priority', params)
    priority_dist = {r['priority']: r['count'] for r in c.fetchall()}

    conn.close()
    return jsonify({'status_dist': status_dist, 'brand_perf': brand_perf, 'emp_perf': emp_perf, 'daily': daily,
                    'overdue_count': overdue_count, 'priority_dist': priority_dist})


@app.route('/api/export/<page>')
@login_required
def export_page(page):
    allowed = {'dashboard', 'analytics', 'tasks', 'profile', 'users', 'staff',
               'brands', 'departments', 'roles'}
    if page not in allowed:
        return jsonify({'error': 'صفحه نامعتبر است'}), 404
    me = current_user()
    conn = get_db()
    if me['role'] in ('admin', 'manager', 'supervisor') and not has_permission(conn, me, 'export_data'):
        conn.close()
        return jsonify({'error': 'مجوز خروجی Excel فعال نیست'}), 403
    if page == 'analytics' and not has_permission(conn, me, 'view_analytics'):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    module_permissions = {'brands': 'manage_brands', 'departments': 'manage_departments',
                          'roles': 'manage_roles'}
    if page in module_permissions and not has_permission(conn, me, module_permissions[page]):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if page == 'users' and not has_permission(conn, me, 'view_staff'):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403
    if page == 'staff' and not has_permission(conn, me, 'view_staff'):
        conn.close()
        return jsonify({'error': 'دسترسی غیرمجاز'}), 403

    workbook = Workbook()
    first_sheet = True

    def add_sheet(title, headers, rows):
        nonlocal first_sheet
        ws = workbook.active if first_sheet else workbook.create_sheet()
        first_sheet = False
        ws.title = title
        ws.sheet_view.rightToLeft = True
        ws.append(headers)
        for cell in ws[1]:
            cell.fill = PatternFill('solid', fgColor='263B59')
            cell.font = Font(bold=True, color='FFFFFF')
            cell.alignment = Alignment(horizontal='right', vertical='center')
        for row in rows:
            safe_row = [("'" + value if value.startswith(('=', '+', '-', '@')) else value)
                        if isinstance(value, str) else value for value in row]
            ws.append(safe_row)
        ws.freeze_panes = 'A2'
        ws.auto_filter.ref = ws.dimensions
        for column in ws.columns:
            letter = get_column_letter(column[0].column)
            width = max(len(str(cell.value or '')) for cell in column)
            ws.column_dimensions[letter].width = min(55, max(15, width + 3))
            for cell in column[1:]:
                cell.alignment = Alignment(vertical='top', horizontal='right', wrap_text=True)

    role_names = {r['key']: r['name'] for r in conn.execute('SELECT key, name FROM role_catalog')}
    status_names = {'new': 'جدید', 'progress': 'در حال انجام', 'done': 'انجام شده', 'rejected': 'رد شده'}
    priority_names = {'low': 'کم', 'normal': 'عادی', 'high': 'بالا', 'urgent': 'فوری'}
    users = {r['id']: dict(r) for r in conn.execute('SELECT * FROM users')}
    brands = {r['id']: dict(r) for r in conn.execute('SELECT * FROM brands')}
    departments = {r['id']: dict(r) for r in conn.execute('SELECT * FROM departments')}
    tasks = get_tasks().get_json() if page in {'dashboard', 'tasks', 'users', 'brands'} else []
    if page == 'dashboard' and me['role'] == 'manager':
        permitted = set(dashboard_scope(conn, me)['task_ids'])
        tasks = [task for task in tasks if task['id'] in permitted]

    def task_table(rows):
        result = []
        for t in rows:
            assignees = [users.get(uid, {}).get('name', '') for uid in t['assignee_ids']]
            acceptance = [f"{users.get(uid, {}).get('name', '')}: " +
                          ('تأییدشده' if t['assignee_acceptance'].get(str(uid)) == 'accepted' else 'در انتظار')
                          for uid in t['assignee_ids']]
            result.append([t['task_code'], t['title'], brands.get(t['brand_id'], {}).get('name', ''),
                           users.get(t['creator_id'], {}).get('name', ''), '، '.join(assignees),
                           '، '.join(acceptance), status_names.get(t['status'], t['status']),
                           priority_names.get(t['priority'], t['priority']), t['progress'],
                           t['task_score'], t['quality_score'],
                           t['due_date'] or '',
                           datetime.fromtimestamp(t['created_at'] / 1000).strftime('%Y-%m-%d %H:%M') if t['created_at'] else '',
                           t['description'] or ''])
        return result

    task_headers = ['کد', 'عنوان', 'برند', 'واگذارکننده', 'مسئولان', 'تأیید دریافت', 'وضعیت',
                    'اولویت', 'پیشرفت ٪', 'نمره کمی', 'نمره کیفی',
                    'مهلت (میلادی)', 'تاریخ ایجاد (میلادی)', 'توضیحات']

    if page == 'tasks':
        add_sheet('تسک‌ها', task_headers, task_table(tasks))
        add_sheet('گفت‌وگوها', ['کد تسک', 'عنوان', 'فرستنده', 'زمان (میلادی)', 'پیام'],
                  [[t['task_code'], t['title'], c['user_name'] or 'کاربر حذف‌شده',
                    datetime.fromtimestamp(c['created_at'] / 1000).strftime('%Y-%m-%d %H:%M'), c['comment']]
                   for t in tasks for c in t['comments']])
    elif page == 'dashboard':
        today = datetime.now().strftime('%Y-%m-%d')
        active = lambda t: t['status'] not in ('done', 'rejected')
        manager_view = me['role'] in MANAGEMENT_ROLES | {'supervisor'}
        mine = [t for t in tasks if me['id'] in t['assignee_ids'] or
                (not manager_view and t['creator_id'] == me['id'])]
        delegated = [t for t in tasks if t['creator_id'] == me['id'] and
                     any(uid != me['id'] for uid in t['assignee_ids'])] if manager_view else []
        due_today = [t for t in tasks if active(t) and (t['due_date'] == today or
                     (t['is_daily'] and (not t['due_date'] or t['due_date'] >= today)))]
        overdue = [t for t in tasks if active(t) and t['due_date'] and t['due_date'] < today]
        overdue_mine = [t for t in mine if t in overdue]
        overdue_delegated = [t for t in delegated if t in overdue]
        sections = [('همه کارها', tasks), ('کارهای من', mine)]
        if manager_view:
            sections.append(('کارهای واگذارشده', delegated))
        sections.append(('امروز', due_today))
        if manager_view:
            sections.extend([('تأخیردار من', overdue_mine), ('تأخیردار واگذارشده', overdue_delegated)])
        else:
            sections.append(('تاخیردارها', overdue))
        add_sheet('خلاصه', ['شاخص', 'مقدار'],
                  [['کل تسک‌ها', len(tasks)],
                   ['انجام شده', sum(t['status'] == 'done' for t in tasks)],
                   ['در حال انجام', sum(t['status'] == 'progress' for t in tasks)]] +
                  [[title, len(rows)] for title, rows in sections[1:]])
        for title, rows in sections:
            add_sheet(title, task_headers, task_table(rows))
    elif page == 'analytics':
        stats_data = get_stats().get_json()
        add_sheet('عملکرد', ['کارمند', 'کل تسک‌ها', 'انجام شده', 'تاخیردار', 'میانگین کمی', 'میانگین کیفی'],
                  [[e['name'], e['total'], e['done'], e['overdue'], e['avg_task_score'], e['avg_quality_score']]
                   for e in stats_data['emp_perf']])
        add_sheet('اولویت‌ها', ['اولویت', 'تعداد'],
                  [[priority_names.get(k, k), v] for k, v in stats_data['priority_dist'].items()])
    elif page == 'profile':
        try:
            user_id = int(request.args.get('user_id') or me['id'])
        except ValueError:
            conn.close()
            return jsonify({'error': 'شناسه کاربر نامعتبر است'}), 400
        user = users.get(user_id)
        if not user:
            conn.close()
            return jsonify({'error': 'کاربر پیدا نشد'}), 404
        if me['role'] not in EXECUTIVE_ROLES and user_id != me['id'] and not (
            manages_user(conn, me, user) or supervisor_staff_scope(conn, me, user)):
            conn.close()
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        profile_scope = 'AND t.brand_id IN (SELECT id FROM brands WHERE manager_id=?)' if me['role'] == 'manager' and user_id != me['id'] else ''
        if me['role'] == 'supervisor' and user_id != me['id']:
            profile_scope = f'AND t.brand_id IN (SELECT brand_id FROM {BRAND_MEMBERSHIP} WHERE user_id=?)'
        counts = conn.execute(f"""SELECT COUNT(*) total, COALESCE(SUM(t.status='done'),0) done
            FROM task_assignees ta JOIN tasks t ON t.id=ta.task_id WHERE ta.user_id=? {profile_scope}""",
            (user_id, me['id']) if profile_scope else (user_id,)).fetchone()
        add_sheet('پروفایل', ['فیلد', 'مقدار'], [
            ['نام', user['name']], ['نام کاربری', user['username']], ['نقش', role_names.get(user['role'])],
            ['برند', brands.get(user['brand_id'], {}).get('name', '')],
            ['بخش', departments.get(user['department_id'], {}).get('name', '')],
            ['شماره تماس', user['phone'] or ''], ['درباره من', user['bio'] or ''],
            ['تسک‌های محول‌شده', counts['total']], ['انجام‌شده', counts['done']]])
    elif page in {'users', 'staff'}:
        selected = list(users.values())
        if me['role'] == 'manager':
            owned_brands = managed_brand_ids(conn, me['id'])
            selected = [u for u in selected if u['id'] == me['id'] or user_brand_ids(conn, u['id']) & owned_brands]
        if me['role'] == 'supervisor':
            selected = [u for u in selected if u['id'] == me['id'] or supervisor_staff_scope(conn, me, u)]
        add_sheet('کارکنان' if page == 'staff' else 'کاربران',
                  ['نام', 'نام کاربری', 'نقش', 'برند', 'بخش', 'شماره تماس'],
                  [[u['name'], u['username'], role_names.get(u['role']),
                    brands.get(u['brand_id'], {}).get('name', ''),
                    departments.get(u['department_id'], {}).get('name', ''), u['phone'] or '']
                   for u in sorted(selected, key=lambda item: item['name'])])
    elif page == 'brands':
        add_sheet('برندها', ['نام برند', 'رنگ', 'مدیر', 'تعداد تسک‌ها', 'میانگین نمره تسک'],
                  [[b['name'], b['color'], users.get(b['manager_id'], {}).get('name', ''),
                    sum(t['brand_id'] == b['id'] for t in tasks),
                    round(sum(t['task_score'] for t in tasks if t['brand_id'] == b['id'] and t['task_score'] is not None) /
                          sum(t['brand_id'] == b['id'] and t['task_score'] is not None for t in tasks), 1)
                    if any(t['brand_id'] == b['id'] and t['task_score'] is not None for t in tasks) else None]
                   for b in brands.values()])
    elif page == 'departments':
        add_sheet('بخش‌ها', ['بخش', 'تعداد کارمند'],
                  [[d['name'], sum(u['department_id'] == d['id'] for u in users.values())]
                   for d in departments.values()])
    elif page == 'roles':
        add_sheet('نقش‌ها', ['نقش', 'تعداد کاربران'],
                  [[name, sum(u['role'] == key for u in users.values())] for key, name in role_names.items()])

    stream = BytesIO()
    workbook.save(stream)
    stream.seek(0)
    conn.close()
    filename = f'Acom_{page}_{datetime.now().strftime("%Y%m%d")}.xlsx'
    response = send_file(stream, as_attachment=True, download_name=filename,
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response.headers['Cache-Control'] = 'no-store'
    return response


# ── ارتقای خودکار ساختار دیتابیس ─────────────────────────────────────────────
# روی هاست (cPanel/Passenger) فایل ورودی ممکن است init_db را صدا نزند، یا دیتابیس قدیمی‌تری
# جایگزین شود. پس پیش از اولین درخواست هر پروسس، و هر بار که خطای «ستون/جدول وجود ندارد» رخ دهد،
# init_db اجرا می‌شود (اجرای چندباره بی‌خطر است و داده‌ای پاک نمی‌کند).
import threading as _threading
_schema_lock = _threading.Lock()
_schema_ready = False


def ensure_schema(force=False):
    global _schema_ready
    if _schema_ready and not force:
        return
    with _schema_lock:
        if _schema_ready and not force:
            return
        init_db()
        _schema_ready = True


@app.before_request
def _ensure_schema_before_request():
    if not _schema_ready:
        try:
            ensure_schema()
        except Exception:  # اجازه بده خود درخواست خطای واقعی را نشان دهد
            app.logger.exception('init_db failed')


@app.errorhandler(sqlite3.OperationalError)
def _schema_error(exc):
    if 'no such column' in str(exc) or 'no such table' in str(exc):
        app.logger.warning('Database schema outdated (%s); running init_db', exc)
        ensure_schema(force=True)
        return jsonify({'error': 'ساختار دیتابیس به‌روزرسانی شد؛ لطفاً صفحه را دوباره بارگذاری کنید'}), 503
    app.logger.exception('Database error')
    return jsonify({'error': 'خطای دیتابیس'}), 500


# ======================================================================
# روند پرداخت (تسک مستقل: مالی / دستور پرداخت)
# ایجادکننده ← مدیر برند ← کارشناس مالی ← خزانه‌داری (بررسی موجودی) ← مدیرعامل
# ← خزانه‌داری (پرداخت؛ اگر آنلاین باشد ← ایجادکننده پرداخت و رسید ← تأیید خزانه‌داری) ← بایگانی
# در همهٔ مراحل «برگشت برای اصلاح» به مرحلهٔ قبل وجود دارد. همهٔ اعضا از ابتدا ناظر تسک‌اند.
# ======================================================================
PAYMENT_KINDS = {'official': 'رسمی', 'unofficial': 'غیر رسمی'}
# (کلید، نام برند در جدول brands، مدیر برند در روند مالی، کارشناس مالی)
PAYMENT_BRANDS = (
    ('group', 'گروه', 'احسان آشتیانی', 'سحر لطفی'),
    ('ximent', 'XIMENT', 'حامد حواصلی آشتیانی', 'سحر لطفی'),
    ('leepica', 'Leepica', 'حامد حواصلی آشتیانی', 'سحر لطفی'),
    ('eryxol', 'ERYXOL', 'محدثه پناهی', 'سحر لطفی'),
    ('pexol', 'PEXOL', 'محدثه پناهی', 'سحر لطفی'),
    ('retrona', 'RETRONA', 'احسان آشتیانی', 'سحر لطفی'),
    ('vta', 'VTA', 'محسن عباسی', 'فاطمه احمدخانی'),
    ('xyland', 'Xyland', 'محسن عباسی', 'فاطمه احمدخانی'),
)
PAYMENT_TREASURY_NAME = 'فاطمه کیا'
PAYMENT_ARCHIVE_NAME = 'مسیح صیدی'
PAYMENT_CEO_NAME = 'احسان آشتیانی'
PAYER_COMPANIES = ('ونوس تجارت اکام', 'ونوس تجارت عرشیا', 'آرمان اکسیر عرشیا', 'ابادیس')
PAYMENT_METHODS_FLOW = {'cash': 'نقدی', 'online': 'آنلاین', 'cheque': 'چک', 'card': 'کارت به کارت', 'sheba': 'شبا'}
PAYMENT_STAGES = {
    'creator_fix': 'اصلاح فرم توسط ایجادکننده', 'manager': 'تأیید مدیر برند', 'finance': 'کارشناس مالی',
    'treasury_check': 'خزانه‌داری — بررسی موجودی', 'ceo': 'تأیید مدیرعامل', 'treasury_pay': 'خزانه‌داری — پرداخت',
    'creator_pay': 'پرداخت آنلاین توسط ایجادکننده', 'treasury_confirm': 'خزانه‌داری — تأیید رسید',
    'archive': 'بایگانی', 'done': 'بایگانی شد', 'rejected': 'رد شد'}
PAYMENT_STAGE_HOLDER = {'creator_fix': 'creator_id', 'manager': 'manager_id', 'finance': 'finance_id',
                        'treasury_check': 'treasury_id', 'ceo': 'ceo_id', 'treasury_pay': 'treasury_id',
                        'creator_pay': 'creator_id', 'treasury_confirm': 'treasury_id', 'archive': 'archive_id'}
PAYMENT_MEMBER_FIELDS = ('creator_id', 'manager_id', 'finance_id', 'treasury_id', 'ceo_id', 'archive_id')
PAYMENT_FA_DIGITS = str.maketrans('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩', '01234567890123456789')


def payment_init_tables(c):
    c.execute('''CREATE TABLE IF NOT EXISTS payment_processes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id INTEGER NOT NULL UNIQUE, kind TEXT NOT NULL,
        brand_key TEXT NOT NULL, brand_id INTEGER, creator_id INTEGER NOT NULL, manager_id INTEGER NOT NULL,
        finance_id INTEGER NOT NULL, treasury_id INTEGER NOT NULL, ceo_id INTEGER NOT NULL, archive_id INTEGER NOT NULL,
        stage TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', pending INTEGER NOT NULL DEFAULT 0,
        pending_note TEXT, form TEXT, finance TEXT, created_at INTEGER, updated_at INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS payment_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, process_id INTEGER NOT NULL, actor_id INTEGER, stage TEXT,
        action TEXT NOT NULL, text TEXT, created_at INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS payment_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, process_id INTEGER NOT NULL, stage TEXT, filename TEXT NOT NULL,
        original_name TEXT, file_type TEXT, file_size INTEGER, uploader_id INTEGER, created_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_payment_events_process ON payment_events(process_id)')


def payment_brand(key):
    return next((b for b in PAYMENT_BRANDS if b[0] == key), None)


def payment_user_by_name(conn, name):
    return conn.execute('SELECT id, name FROM users WHERE name=? ORDER BY id LIMIT 1', (name,)).fetchone()


def payment_team(conn, brand_key):
    """(team dict, error) — اعضای روند بر اساس برند انتخاب‌شده."""
    brand = payment_brand(brand_key)
    if not brand:
        return None, 'برند را انتخاب کنید'
    team = {}
    for field, name in (('manager_id', brand[2]), ('finance_id', brand[3]), ('treasury_id', PAYMENT_TREASURY_NAME),
                        ('ceo_id', PAYMENT_CEO_NAME), ('archive_id', PAYMENT_ARCHIVE_NAME)):
        row = payment_user_by_name(conn, name)
        if not row:
            return None, f'کاربر «{name}» در سیستم پیدا نشد'
        team[field] = row['id']
    row = conn.execute('SELECT id FROM brands WHERE lower(name)=lower(?)', (brand[1],)).fetchone()
    team['brand_id'] = row['id'] if row else None
    return team, None


def payment_digits(value, limit=40):
    return ''.join(ch for ch in str(value or '').translate(PAYMENT_FA_DIGITS) if ch.isdigit())[:limit]


def clean_payment_form(kind, raw):
    """(form, error) — همهٔ فیلدها اجباری به‌جز شمارهٔ پروژهٔ بازرگانی و شمارهٔ صورتحساب/فاکتور."""
    if kind not in PAYMENT_KINDS:
        return None, 'رسمی یا غیر رسمی بودن پرداخت را انتخاب کنید'
    if not isinstance(raw, dict):
        return None, 'فرم پرداخت نامعتبر است'
    text = lambda key, limit=500: str(raw.get(key) or '').strip()[:limit]
    form = {'unit_name': text('unit_name'), 'recipient_company': text('recipient_company'),
            'subject': text('subject', 3000), 'project_number': text('project_number', 100),
            'payer_company': text('payer_company') if kind == 'official' else '',
            'amount': payment_digits(raw.get('amount'), 20), 'amount_words': text('amount_words', 1000),
            'invoice_number': text('invoice_number', 100), 'method': text('method', 20),
            'card_number': '', 'sheba': ''}
    labels = (('unit_name', 'نام واحد تنظیم‌کننده'), ('recipient_company', 'نام شرکت گیرنده'), ('subject', 'شرح'),
              ('amount', 'مبلغ به عدد (ریال)'), ('amount_words', 'مبلغ به حروف (ریال)'))
    for key, label in labels:
        if not form[key]:
            return None, f'«{label}» را وارد کنید'
    if int(form['amount']) <= 0:
        return None, 'مبلغ باید بیشتر از صفر باشد'
    if kind == 'official' and form['payer_company'] not in PAYER_COMPANIES:
        return None, 'نام شرکت پرداخت‌کننده را انتخاب کنید'
    if form['method'] not in PAYMENT_METHODS_FLOW:
        return None, 'نوع پرداخت را انتخاب کنید'
    if form['method'] == 'card':
        form['card_number'] = payment_digits(raw.get('card_number'), 19)
        if len(form['card_number']) != 16:
            return None, 'شمارهٔ کارت باید ۱۶ رقم باشد'
    if form['method'] == 'sheba':
        form['sheba'] = payment_digits(raw.get('sheba'), 26)
        if len(form['sheba']) != 24:
            return None, 'شمارهٔ شبا باید ۲۴ رقم (بعد از IR) باشد'
    return form, None


def clean_payment_finance(raw):
    if not isinstance(raw, dict):
        return None, 'اطلاعات مالی نامعتبر است'
    finance = {k: str(raw.get(k) or '').strip()[:500] for k in ('counterparty_detail', 'bank_name', 'statement_number')}
    for key, label in (('counterparty_detail', 'تفصیل طرف حساب'), ('bank_name', 'نام بانک'),
                       ('statement_number', 'شماره صورتحساب')):
        if not finance[key]:
            return None, f'«{label}» را وارد کنید'
    return finance, None


def payment_json(text):
    try:
        value = json.loads(text) if text else {}
    except ValueError:
        value = {}
    return value if isinstance(value, dict) else {}


def payment_holder(proc):
    if proc['status'] in ('done', 'rejected'):
        return None
    field = PAYMENT_STAGE_HOLDER.get(proc['stage'])
    return proc[field] if field else None


def payment_previous_stage(proc):
    """مرحلهٔ قبل برای «برگشت برای اصلاح» (None یعنی برگشتی ندارد)."""
    online = payment_json(proc['form']).get('method') == 'online'
    return {'manager': 'creator_fix', 'finance': 'manager', 'treasury_check': 'finance', 'ceo': 'treasury_check',
            'treasury_pay': 'ceo', 'creator_pay': 'treasury_pay', 'treasury_confirm': 'creator_pay',
            'archive': 'treasury_confirm' if online else 'treasury_pay'}.get(proc['stage'])


def payment_actions(proc, me):
    """اقدام‌هایی که این کاربر الان روی روند دارد."""
    if payment_holder(proc) != me['id']:
        return []
    stage = proc['stage']
    online = payment_json(proc['form']).get('method') == 'online'
    actions = {
        'creator_fix': ['resubmit'],
        'manager': ['approve', 'reject'],
        'finance': ['send'],
        'treasury_check': ['approve', 'pending'],
        'ceo': ['approve', 'pending', 'reject'],
        'treasury_pay': ['to_creator'] if online else ['paid'],
        'creator_pay': ['paid'],
        'treasury_confirm': ['confirm'],
        'archive': ['archive'],
    }.get(stage, [])
    if payment_previous_stage(proc):
        actions = actions + ['return']
    return actions


def payment_visible(conn, proc, me):
    return is_super(me) or me['id'] in {proc[f] for f in PAYMENT_MEMBER_FIELDS}


def payment_event(conn, proc, actor_id, action, text):
    conn.execute('INSERT INTO payment_events (process_id, actor_id, stage, action, text, created_at) VALUES (?,?,?,?,?,?)',
                 (proc['id'], actor_id, proc['stage'], action, text, int(time.time() * 1000)))


def payment_sync_task(conn, proc):
    """تسک مربوط را با روند هم‌سو می‌کند: مسئول = نفرِ مرحلهٔ فعلی، بقیهٔ اعضا ناظر، وضعیت تسک از وضعیت روند."""
    task_id = proc['task_id']
    holder = payment_holder(proc)
    members = {proc[f] for f in PAYMENT_MEMBER_FIELDS}
    current = set(get_task_assignees(conn, task_id))
    keep = {holder} if holder else {proc['creator_id']}
    for uid in current - keep:
        conn.execute('DELETE FROM task_assignees WHERE task_id=? AND user_id=?', (task_id, uid))
    for uid in keep - current:
        conn.execute("INSERT INTO task_assignees (task_id, user_id, acceptance_status) VALUES (?,?,'accepted')", (task_id, uid))
    conn.execute("UPDATE task_assignees SET acceptance_status='accepted' WHERE task_id=?", (task_id,))
    observers = members - keep - {proc['creator_id']}
    conn.execute('DELETE FROM task_observers WHERE task_id=?', (task_id,))
    for uid in observers:
        conn.execute('INSERT OR IGNORE INTO task_observers (task_id, user_id) VALUES (?,?)', (task_id, uid))
    for uid in members:
        conn.execute('INSERT OR IGNORE INTO task_participants (task_id, user_id) VALUES (?,?)', (task_id, uid))
    stamp = int(time.time() * 1000)
    if proc['status'] == 'done':
        conn.execute("UPDATE tasks SET status='done', progress=100, completed_at=COALESCE(completed_at, ?) WHERE id=?",
                     (stamp, task_id))
    elif proc['status'] == 'rejected':
        conn.execute("UPDATE tasks SET status='rejected' WHERE id=?", (task_id,))
    else:
        progress = {'creator_fix': 5, 'manager': 10, 'finance': 25, 'treasury_check': 40, 'ceo': 55,
                    'treasury_pay': 70, 'creator_pay': 75, 'treasury_confirm': 85, 'archive': 95}.get(proc['stage'], 0)
        conn.execute("UPDATE tasks SET status='progress', progress=?, completed_at=NULL WHERE id=?", (progress, task_id))


def payment_for_task(conn, task_id):
    return conn.execute('SELECT * FROM payment_processes WHERE task_id=?', (task_id,)).fetchone()


def payment_locked_response(conn, task_id):
    if payment_for_task(conn, task_id):
        return jsonify({'error': 'این تسک با «روند پرداخت» مدیریت می‌شود؛ اقدام‌ها را از بخش روند پرداخت انجام دهید'}), 409
    return None


def serialize_payment(conn, proc, me):
    ids = {proc[f] for f in PAYMENT_MEMBER_FIELDS}
    names = {r['id']: r['name'] for r in conn.execute(
        f"SELECT id,name FROM users WHERE id IN ({','.join('?' for _ in ids)})", tuple(ids))}
    brand = payment_brand(proc['brand_key'])
    holder = payment_holder(proc)
    form = payment_json(proc['form'])
    return {
        'id': proc['id'], 'task_id': proc['task_id'], 'code': f'PAY-{proc["id"]:05d}',
        'kind': proc['kind'], 'kind_label': PAYMENT_KINDS.get(proc['kind'], ''),
        'brand_key': proc['brand_key'], 'brand_label': brand[1] if brand else proc['brand_key'],
        'stage': proc['stage'], 'stage_label': PAYMENT_STAGES.get(proc['stage'], proc['stage']),
        'status': proc['status'], 'pending': bool(proc['pending']), 'pending_note': proc['pending_note'],
        'form': form, 'finance': payment_json(proc['finance']),
        'method_label': PAYMENT_METHODS_FLOW.get(form.get('method'), ''),
        'team': {f: {'id': proc[f], 'name': names.get(proc[f])} for f in PAYMENT_MEMBER_FIELDS},
        'holder_id': holder, 'holder_name': names.get(holder) if holder else None,
        'my_actions': payment_actions(proc, me),
        'previous_stage_label': PAYMENT_STAGES.get(payment_previous_stage(proc) or '', ''),
        'files': [dict(r) for r in conn.execute(
            '''SELECT f.id, f.stage, f.filename, f.original_name, f.file_type, f.file_size, f.uploader_id, f.created_at,
               u.name AS uploader_name FROM payment_files f LEFT JOIN users u ON u.id=f.uploader_id
               WHERE f.process_id=? ORDER BY f.id''', (proc['id'],))],
        'events': [dict(r) for r in conn.execute(
            '''SELECT e.stage, e.action, e.text, e.created_at, e.actor_id, u.name AS actor_name FROM payment_events e
               LEFT JOIN users u ON u.id=e.actor_id WHERE e.process_id=? ORDER BY e.id''', (proc['id'],))],
        'created_at': proc['created_at'], 'updated_at': proc['updated_at'],
        'task_title': (conn.execute('SELECT title FROM tasks WHERE id=?', (proc['task_id'],)).fetchone() or {'title': ''})['title'],
        'can_print': is_super(me) or me['id'] in ids,
    }


@app.route('/api/payments/options')
@login_required
def payment_options():
    conn = get_db()
    try:
        brands = []
        for key, label, manager, finance in PAYMENT_BRANDS:
            brands.append({'key': key, 'label': label, 'manager': manager, 'finance': finance,
                           'missing': [n for n in (manager, finance) if not payment_user_by_name(conn, n)]})
        return jsonify({'kinds': PAYMENT_KINDS, 'brands': brands, 'payer_companies': list(PAYER_COMPANIES),
                        'methods': PAYMENT_METHODS_FLOW, 'stages': PAYMENT_STAGES,
                        'treasury': PAYMENT_TREASURY_NAME, 'ceo': PAYMENT_CEO_NAME, 'archive': PAYMENT_ARCHIVE_NAME})
    finally:
        conn.close()


@app.route('/api/payments')
@login_required
def list_payments():
    me = current_user()
    conn = get_db()
    try:
        rows = conn.execute('SELECT * FROM payment_processes ORDER BY updated_at DESC, id DESC').fetchall()
        result = []
        for proc in rows:
            if payment_visible(conn, proc, me):
                item = serialize_payment(conn, proc, me)
                item.pop('events', None)
                result.append(item)
        return jsonify(result)
    finally:
        conn.close()


@app.route('/api/payments/<int:pid>')
@login_required
def get_payment(pid):
    me = current_user()
    conn = get_db()
    try:
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (pid,)).fetchone()
        if not proc or not payment_visible(conn, proc, me):
            return jsonify({'error': 'روند پرداخت پیدا نشد'}), 404
        return jsonify(serialize_payment(conn, proc, me))
    finally:
        conn.close()


@app.route('/api/payments', methods=['POST'])
@login_required
def create_payment():
    """ساخت تسک مستقل «مالی / دستور پرداخت» همراه با روند پرداخت."""
    data = request.get_json(silent=True) or {}
    me = current_user()
    conn = get_db()
    try:
        kind = data.get('kind')
        form, error = clean_payment_form(kind, data.get('form'))
        if error:
            return jsonify({'error': error}), 400
        title = str(data.get('title') or '').strip()[:300] or \
            f'دستور پرداخت {PAYMENT_KINDS[kind]} — {form["recipient_company"]} — {int(form["amount"]):,} ریال'
        team, error = payment_team(conn, data.get('brand_key'))
        if error:
            return jsonify({'error': error}), 400
        brand_id = team['brand_id'] or me['brand_id']
        if not brand_id:
            return jsonify({'error': 'برند پرداخت در سیستم پیدا نشد'}), 400
        priority = data.get('priority') if data.get('priority') in ('low', 'normal', 'high', 'urgent') else 'normal'
        stamp = int(time.time() * 1000)
        lock_for_create(conn)
        duplicate = conn.execute('''SELECT p.id, p.task_id FROM payment_processes p JOIN tasks t ON t.id=p.task_id
            WHERE p.creator_id=? AND t.title=? AND p.form=? AND p.created_at>=? ORDER BY p.id DESC''',
            (me['id'], title, json.dumps(form, ensure_ascii=False), stamp - DUPLICATE_WINDOW_MS)).fetchone()
        if duplicate:
            return jsonify({'success': True, 'task_id': duplicate['task_id'], 'payment_id': duplicate['id'], 'duplicate': True})
        cur = conn.execute('''INSERT INTO tasks (title, description, creator_id, brand_id, status, priority, progress,
            requirements, due_date, created_at, project_id, category, subcategory)
            VALUES (?,?,?,?,?,?,?,?,?,?,NULL,'finance','payment_order')''',
            (title, str(data.get('description') or '')[:5000], me['id'], brand_id, 'progress', priority, 10,
             str(data.get('requirements') or '')[:5000], data.get('due_date') or None, stamp))
        task_id = cur.lastrowid
        code = f'TASK-{task_id:06d}'
        if conn.execute('SELECT 1 FROM tasks WHERE task_code=? AND id!=?', (code, task_id)).fetchone():
            code = f'TASK-{task_id:06d}-{secrets.token_hex(3).upper()}'
        conn.execute('UPDATE tasks SET task_code=? WHERE id=?', (code, task_id))
        cur = conn.execute('''INSERT INTO payment_processes (task_id, kind, brand_key, brand_id, creator_id, manager_id,
            finance_id, treasury_id, ceo_id, archive_id, stage, status, form, finance, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,'manager','active',?,'{}',?,?)''',
            (task_id, kind, data.get('brand_key'), team['brand_id'], me['id'], team['manager_id'], team['finance_id'],
             team['treasury_id'], team['ceo_id'], team['archive_id'], json.dumps(form, ensure_ascii=False), stamp, stamp))
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (cur.lastrowid,)).fetchone()
        payment_event(conn, proc, me['id'], 'create',
                      f'فرم پرداخت {PAYMENT_KINDS[kind]} ثبت شد و برای تأیید مدیر برند ارسال شد')
        payment_sync_task(conn, proc)
        create_notification(team['manager_id'], '💳 دستور پرداخت جدید',
                            f'{me["name"]} دستور پرداخت «{title}» را برای تأیید شما فرستاد.', 'info', task_id, conn=conn)
        conn.commit()
        return jsonify({'success': True, 'task_id': task_id, 'payment_id': proc['id']})
    finally:
        conn.close()


@app.route('/api/payments/<int:pid>/action', methods=['POST'])
@login_required
def payment_action(pid):
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    comment = str(data.get('comment') or '').strip()[:2000]
    me = current_user()
    conn = get_db()
    try:
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (pid,)).fetchone()
        if not proc or not payment_visible(conn, proc, me):
            return jsonify({'error': 'روند پرداخت پیدا نشد'}), 404
        if action not in payment_actions(proc, me):
            return jsonify({'error': 'این اقدام الان در نوبت شما نیست'}), 403
        stage = proc['stage']
        task = conn.execute('SELECT title FROM tasks WHERE id=?', (proc['task_id'],)).fetchone()
        title = task['title'] if task else ''
        stamp = int(time.time() * 1000)
        new_stage, new_status, extra = stage, proc['status'], {}
        label = PAYMENT_STAGES[stage]
        if action in ('return', 'reject') and not comment:
            return jsonify({'error': 'توضیح را بنویسید'}), 400
        if action == 'return':
            new_stage = payment_previous_stage(proc)
            text = f'برگشت برای اصلاح از «{label}» به «{PAYMENT_STAGES[new_stage]}» — {comment}'
        elif action == 'reject':
            new_status = 'rejected'
            text = f'{label}: رد شد — {comment}'
        elif action == 'pending':
            extra = {'pending': 1, 'pending_note': comment or None}
            text = f'{label}: در حالت انتظار (Pending) نگه داشته شد' + (f' — {comment}' if comment else '')
        elif action == 'resubmit':
            form, error = clean_payment_form(proc['kind'], data.get('form'))
            if error:
                return jsonify({'error': error}), 400
            extra = {'form': json.dumps(form, ensure_ascii=False)}
            new_stage = 'manager'
            text = 'فرم اصلاح شد و دوباره برای تأیید مدیر برند ارسال شد' + (f' — {comment}' if comment else '')
        elif action == 'send':  # کارشناس مالی
            finance, error = clean_payment_finance(data.get('finance'))
            if error:
                return jsonify({'error': error}), 400
            extra = {'finance': json.dumps(finance, ensure_ascii=False)}
            new_stage = 'treasury_check'
            text = 'کارشناس مالی اطلاعات را ثبت کرد ← خزانه‌داری' + (f' — {comment}' if comment else '')
        elif action == 'approve':
            new_stage = {'manager': 'finance', 'treasury_check': 'ceo', 'ceo': 'treasury_pay'}[stage]
            verb = {'manager': 'مدیر برند تأیید کرد', 'treasury_check': 'خزانه‌داری موجودی را تأیید کرد',
                    'ceo': 'مدیرعامل تأیید کرد'}[stage]
            text = f'{verb} ← {PAYMENT_STAGES[new_stage]}' + (f' — {comment}' if comment else '')
        elif action == 'to_creator':
            new_stage = 'creator_pay'
            text = 'پرداخت آنلاین است ← برای پرداخت به ایجادکننده سپرده شد' + (f' — {comment}' if comment else '')
        elif action == 'paid':
            has_receipt = conn.execute('SELECT 1 FROM payment_files WHERE process_id=? AND stage=? LIMIT 1',
                                       (pid, stage)).fetchone()
            if not has_receipt:
                return jsonify({'error': 'ابتدا رسید پرداخت را آپلود کنید'}), 400
            new_stage = 'archive' if stage == 'treasury_pay' else 'treasury_confirm'
            text = ('پرداخت انجام شد و رسید آپلود شد' if stage == 'treasury_pay'
                    else 'ایجادکننده پرداخت آنلاین را انجام داد و رسید را برای خزانه‌داری فرستاد') + (f' — {comment}' if comment else '')
        elif action == 'confirm':
            new_stage = 'archive'
            text = 'خزانه‌داری رسید پرداخت را تأیید کرد ← بایگانی' + (f' — {comment}' if comment else '')
        elif action == 'archive':
            new_stage, new_status = 'done', 'done'
            text = 'بایگانی شد؛ روند پرداخت به پایان رسید' + (f' — {comment}' if comment else '')
        else:
            return jsonify({'error': 'اقدام نامعتبر است'}), 400
        if action != 'pending':
            extra.setdefault('pending', 0)
            extra.setdefault('pending_note', None)
        sets = ', '.join(f'{k}=?' for k in extra)
        conn.execute(f'UPDATE payment_processes SET stage=?, status=?, updated_at=?{", " + sets if sets else ""} WHERE id=?',
                     (new_stage, new_status, stamp, *extra.values(), pid))
        payment_event(conn, proc, me['id'], action, text)
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (pid,)).fetchone()
        payment_sync_task(conn, proc)
        holder = payment_holder(proc)
        if action != 'pending' and holder and holder != me['id']:
            create_notification(holder, '↩️ دستور پرداخت برای اصلاح برگشت' if action == 'return' else '💳 دستور پرداخت در نوبت شماست',
                                f'«{title}» — {PAYMENT_STAGES[proc["stage"]]}' + (f': {comment[:120]}' if comment else ''),
                                'warning' if action == 'return' else 'info', proc['task_id'], conn=conn)
        # پرداخت انجام شد ← اطلاع به ایجادکننده (پرداخت خزانه‌دار، پرداخت آنلاین خود ایجادکننده و تأیید رسید آن)
        if action == 'paid' or action == 'confirm':
            amount_text = f'{int(payment_json(proc["form"]).get("amount") or 0):,} ریال'
            if action == 'paid' and stage == 'treasury_pay':
                note = f'خزانه‌داری مبلغ {amount_text} را برای «{title}» پرداخت کرد و رسید آن ثبت شد.'
            elif action == 'paid':
                note = f'پرداخت آنلاین شما ({amount_text}) برای «{title}» ثبت شد و رسید برای تأیید خزانه‌داری رفت.'
            else:
                note = f'خزانه‌داری رسید پرداخت آنلاین شما ({amount_text}) برای «{title}» را تأیید کرد.'
            create_notification(proc['creator_id'], '💸 پرداخت انجام شد', note, 'success', proc['task_id'], conn=conn)
        if new_status in ('done', 'rejected') and proc['creator_id'] != me['id']:
            create_notification(proc['creator_id'], '✅ دستور پرداخت بایگانی شد' if new_status == 'done' else '⛔ دستور پرداخت رد شد',
                                f'«{title}»' + (f': {comment[:120]}' if comment else ''),
                                'success' if new_status == 'done' else 'warning', proc['task_id'], conn=conn)
        conn.commit()
        return jsonify({'success': True, 'stage': proc['stage'], 'status': proc['status']})
    finally:
        conn.close()


@app.route('/api/payments/<int:pid>/files', methods=['POST'])
@login_required
def upload_payment_file(pid):
    me = current_user()
    conn = get_db()
    try:
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (pid,)).fetchone()
        if not proc or not payment_visible(conn, proc, me):
            return jsonify({'error': 'روند پرداخت پیدا نشد'}), 404
        if payment_holder(proc) != me['id'] or proc['stage'] not in ('treasury_pay', 'creator_pay'):
            return jsonify({'error': 'آپلود رسید فقط در مرحلهٔ پرداخت و توسط پرداخت‌کننده ممکن است'}), 403
        file = request.files.get('file')
        if not file or not file.filename or not allowed_file(file.filename):
            return jsonify({'error': 'نوع فایل مجاز نیست'}), 400
        ext = file.filename.rsplit('.', 1)[-1].lower()
        filename = f'pay_{uuid.uuid4().hex}.{ext}'
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        conn.execute('''INSERT INTO payment_files (process_id, stage, filename, original_name, file_type, file_size,
            uploader_id, created_at) VALUES (?,?,?,?,?,?,?,?)''',
            (pid, proc['stage'], filename, file.filename, file.content_type or 'application/octet-stream',
             os.path.getsize(path), me['id'], int(time.time() * 1000)))
        payment_event(conn, proc, me['id'], 'file', f'رسید پرداخت «{file.filename}» آپلود شد')
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/payment-files/<int:fid>', methods=['GET', 'DELETE'])
@login_required
def payment_file(fid):
    me = current_user()
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM payment_files WHERE id=?', (fid,)).fetchone()
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (row['process_id'],)).fetchone() if row else None
        if not row or not proc or not payment_visible(conn, proc, me):
            return jsonify({'error': 'فایل پیدا نشد'}), 404
        if request.method == 'DELETE':
            if row['uploader_id'] != me['id'] or payment_holder(proc) != me['id'] or proc['stage'] != row['stage']:
                return jsonify({'error': 'فقط آپلودکننده تا وقتی مرحله در نوبت اوست می‌تواند رسید را حذف کند'}), 403
            conn.execute('DELETE FROM payment_files WHERE id=?', (fid,))
            payment_event(conn, proc, me['id'], 'file', f'رسید «{row["original_name"]}» حذف شد')
            conn.commit()
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], row['filename']))
            except OSError:
                pass
            return jsonify({'success': True})
        inline = (row['file_type'] or '').startswith('image/') or (row['file_type'] or '') == 'application/pdf'
        response = send_from_directory(app.config['UPLOAD_FOLDER'], row['filename'], as_attachment=not inline,
                                       download_name=row['original_name'] or row['filename'])
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    finally:
        conn.close()


PAYMENT_PRINT_TEMPLATE = '''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<title>{{ p.code }} — دستور پرداخت</title>
<style>
 @page { size: A4; margin: 14mm; }
 body { font-family: Vazirmatn, Tahoma, Arial, sans-serif; color: #1c2833; font-size: 13px; margin: 0; padding: 18px; }
 h1 { font-size: 20px; margin: 0 0 4px; } .muted { color: #7f8c8d; font-size: 12px; }
 .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #2c3e50; padding-bottom: 10px; margin-bottom: 14px; }
 .badge { display: inline-block; border: 1px solid #2c3e50; border-radius: 12px; padding: 2px 10px; font-size: 12px; margin-inline-start: 6px; }
 h2 { font-size: 15px; background: #eef2f6; padding: 6px 10px; border-radius: 6px; margin: 16px 0 8px; }
 table { width: 100%; border-collapse: collapse; } td, th { border: 1px solid #d5dbe1; padding: 6px 8px; text-align: right; vertical-align: top; }
 th { background: #f7f9fb; width: 28%; font-weight: 600; }
 .events td { font-size: 12px; } .receipts img { max-width: 100%; max-height: 520px; border: 1px solid #d5dbe1; margin: 6px 0; page-break-inside: avoid; }
 .noprint { margin-bottom: 12px; } .noprint button { font-family: inherit; font-size: 14px; padding: 8px 18px; border: 0; border-radius: 8px; background: #2c3e50; color: #fff; cursor: pointer; }
 @media print { .noprint { display: none; } body { padding: 0; } }
</style></head><body>
<div class="noprint"><button onclick="window.print()">🖨️ ذخیره به‌صورت PDF / چاپ</button> <span class="muted">در پنجرهٔ چاپ، مقصد را «Save as PDF» انتخاب کنید.</span></div>
<div class="head"><div><h1>دستور پرداخت {{ p.kind_label }}</h1>
<div class="muted">{{ p.code }} · تسک {{ task.task_code }} · {{ task.title }}</div></div>
<div><span class="badge">برند: {{ p.brand_label }}</span><span class="badge">وضعیت: {{ p.stage_label }}</span></div></div>
<h2>فرم پرداخت</h2><table>
<tr><th>نام واحد تنظیم‌کننده</th><td>{{ f.unit_name }}</td></tr>
<tr><th>نام شرکت گیرنده</th><td>{{ f.recipient_company }}</td></tr>
<tr><th>شرح</th><td style="white-space:pre-wrap">{{ f.subject }}</td></tr>
<tr><th>شماره پروژه بازرگانی</th><td>{{ f.project_number or '-' }}</td></tr>
{% if p.kind == 'official' %}<tr><th>نام شرکت پرداخت‌کننده</th><td>{{ f.payer_company }}</td></tr>{% endif %}
<tr><th>مبلغ (ریال)</th><td>{{ amount }}</td></tr>
<tr><th>مبلغ به حروف (ریال)</th><td>{{ f.amount_words }}</td></tr>
<tr><th>شماره صورتحساب / فاکتور</th><td>{{ f.invoice_number or '-' }}</td></tr>
<tr><th>نوع پرداخت</th><td>{{ p.method_label }}{% if f.card_number %} — کارت: <span dir="ltr">{{ f.card_number }}</span>{% endif %}{% if f.sheba %} — شبا: <span dir="ltr">IR{{ f.sheba }}</span>{% endif %}</td></tr>
</table>
<h2>اطلاعات کارشناس مالی</h2><table>
<tr><th>تفصیل طرف حساب</th><td>{{ fin.counterparty_detail or '-' }}</td></tr>
<tr><th>نام بانک</th><td>{{ fin.bank_name or '-' }}</td></tr>
<tr><th>شماره صورتحساب</th><td>{{ fin.statement_number or '-' }}</td></tr></table>
<h2>اعضای روند</h2><table>
<tr><th>ایجادکننده</th><td>{{ p.team.creator_id.name }}</td></tr><tr><th>مدیر برند</th><td>{{ p.team.manager_id.name }}</td></tr>
<tr><th>کارشناس مالی</th><td>{{ p.team.finance_id.name }}</td></tr><tr><th>خزانه‌دار</th><td>{{ p.team.treasury_id.name }}</td></tr>
<tr><th>مدیرعامل</th><td>{{ p.team.ceo_id.name }}</td></tr><tr><th>بایگانی</th><td>{{ p.team.archive_id.name }}</td></tr></table>
<h2>تأییدات و روند</h2><table class="events"><tr><th style="width:22%">زمان</th><th style="width:20%">شخص</th><th>شرح</th></tr>
{% for e in events %}<tr><td>{{ e.when }}</td><td>{{ e.actor_name or '-' }}</td><td>{{ e.text }}</td></tr>{% endfor %}</table>
<h2>رسیدهای پرداخت</h2><div class="receipts">
{% for r in p.files %}<div><b>{{ r.original_name }}</b> <span class="muted">— {{ r.uploader_name }}</span>
{% if r.file_type.startswith('image/') %}<br><img src="/api/payment-files/{{ r.id }}">{% else %} — <a href="/api/payment-files/{{ r.id }}" target="_blank">مشاهده فایل</a>{% endif %}</div>
{% else %}<p class="muted">رسیدی ثبت نشده است.</p>{% endfor %}</div>
<p class="muted" style="margin-top:20px">تاریخ تهیهٔ گزارش: {{ printed }}</p>
</body></html>'''


def payment_jalali(ms):
    """تاریخ و ساعت شمسی برای گزارش چاپی."""
    if not ms:
        return '-'
    d = datetime.fromtimestamp(ms / 1000)
    gy, gm, gd = d.year, d.month, d.day
    g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    gy2 = gy + 1 if gm > 2 else gy
    days = 355666 + (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100) + ((gy2 + 399) // 400) + gd + g_d_m[gm - 1]
    jy = -1595 + (33 * (days // 12053))
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    jm = 1 + days // 31 if days < 186 else 7 + (days - 186) // 30
    jd = 1 + (days % 31 if days < 186 else (days - 186) % 30)
    return f'{jy}/{jm:02d}/{jd:02d} {d.hour:02d}:{d.minute:02d}'.translate(str.maketrans('0123456789', '۰۱۲۳۴۵۶۷۸۹'))


@app.route('/payments/<int:pid>/print')
@login_required
def print_payment(pid):
    me = current_user()
    conn = get_db()
    try:
        proc = conn.execute('SELECT * FROM payment_processes WHERE id=?', (pid,)).fetchone()
        if not proc or not payment_visible(conn, proc, me):
            return 'روند پرداخت پیدا نشد', 404
        p = serialize_payment(conn, proc, me)
        task = conn.execute('SELECT task_code, title FROM tasks WHERE id=?', (proc['task_id'],)).fetchone()
        events = [dict(e, when=payment_jalali(e['created_at'])) for e in p['events'] if e['action'] != 'file']
        amount = '{:,}'.format(int(p['form'].get('amount') or 0))
        return render_template_string(PAYMENT_PRINT_TEMPLATE, p=p, f=p['form'], fin=p['finance'], events=events,
                                      task=task or {'task_code': '', 'title': ''}, amount=amount,
                                      printed=payment_jalali(int(time.time() * 1000)))
    finally:
        conn.close()


# ================= تابلو اعلانات فروش (زیر تب روند پرداخت) =================
# بخش‌ها: مدیریت کالا (با آپلود اکسل)، قیمت‌گذاری مدیر برند با تاریخچهٔ قیمتها،
# مدیریت مشتریان (با آپلود اکسل) و ثبت پیشنهاد فروش توسط تیم فروش.

SALES_BOARD_ROLES = ('admin', 'administrator', 'manager', 'supervisor', 'specialist')
SALES_UNITS = ('عدد', 'کیلوگرم', 'لیتر', 'بسته', 'جفت')
# ستون‌های پذیرفته‌شده در فایل اکسل کالا (نام‌های جایگزین هم پشتیبانی می‌شوند)
PRODUCT_EXCEL_ALIASES = {
    'source_product_id': ('SourceProductID', 'SourceProdictID', 'Source Product ID', 'کد کالا', 'کد محصول'),
    'name': ('Product Name', 'ProductName', 'نام کالا', 'نام محصول'),
    'unit': ('Unit', 'واحد'),
    'sub_category': ('SubCategory', 'Sub Category', 'ساب کتگوری', 'زیرشاخه'),
    'brand': ('Brand', 'برند'),
}
CUSTOMER_EXCEL_ALIASES = {
    'customer_code': ('CustomerCode', 'Customer Code', 'کد مشتری'),
    'name': ('CustomerName', 'Customer Name', 'نام مشتری'),
    'brand': ('Brand', 'برند'),
    'brand_code': ('code-brand', 'Code-Brand', 'CodeBrand', 'کدبرند', 'کد برند'),
    'company': ('Company', 'CompanyName', 'شرکت', 'نام شرکت'),
    'address': ('Address', 'آدرس'),
    'phone': ('Phone', 'Tel', 'Telephone', 'تلفن'),
    'email': ('Email', 'ایمیل'),
}


def header_variants(title):
    """شکل‌های مقایسه‌پذیر یک عنوان ستون (حساس به خط تیره، بدون آن و بدون فاصله)."""
    norm = normalize_header(title)
    variants = {norm, norm.replace(' ', '-'), norm.replace(' ', '')}
    return {v for v in variants if v}


def map_excel_headers(header_row, aliases):
    """(نگاشت نام_منطقی -> ایندکس ستون، لیست ستون‌های ناشناخته)"""
    mapping = {}
    unknown = []
    for idx, title in enumerate(header_row):
        variants = header_variants(title)
        if not variants:
            continue
        matched = None
        for logical, names in aliases.items():
            if logical in mapping:
                continue
            accepted = set()
            for name in names:
                accepted |= header_variants(name)
            if variants & accepted:
                matched = logical
                break
        if matched:
            mapping[matched] = idx
        else:
            unknown.append(str(title))
    return mapping, unknown


def sales_board_init_tables(c):
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, source_product_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, unit TEXT, sub_category TEXT, brand_id INTEGER, brand_name TEXT,
        created_at INTEGER, updated_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_products_brand ON products(brand_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_products_subcat ON products(sub_category)')
    # قیمت فعلی هر کالا (تک‌قیمت یا بازه). درصد پایه برای تغییرات درصدی بعدی.
    c.execute('''CREATE TABLE IF NOT EXISTS product_prices (
        product_id INTEGER PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'single' CHECK(mode IN ('single','range')),
        price REAL, min_price REAL, max_price REAL, percent_base REAL, updated_by INTEGER, updated_at INTEGER)''')
    # تاریخچهٔ قیمتها: هر تغییر قیمت یک رکورد جدید با قیمت قبلی ثبت می‌کند.
    c.execute('''CREATE TABLE IF NOT EXISTS product_price_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL, mode TEXT NOT NULL,
        price REAL, min_price REAL, max_price REAL, change_note TEXT, changed_by INTEGER, created_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_price_history_product ON product_price_history(product_id, id)')
    c.execute('''CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, customer_key TEXT UNIQUE NOT NULL, customer_code TEXT,
        name TEXT NOT NULL, brand_id INTEGER, brand_name TEXT, brand_code TEXT, company TEXT,
        address TEXT, phone TEXT, email TEXT, source TEXT NOT NULL DEFAULT 'manual',
        created_by INTEGER, created_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_customers_brand ON customers(brand_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name)')
    # پیشنهاد فروش (هر ردیف = یک کالا در پیشنهاد؛ سررسیدهای متعدد = چند ردیف اعتباری)
    c.execute('''CREATE TABLE IF NOT EXISTS sale_proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_code TEXT NOT NULL UNIQUE,
        creator_id INTEGER NOT NULL, brand_id INTEGER, brand_name TEXT, job_role TEXT, department TEXT,
        customer_id INTEGER, customer_key TEXT, customer_name TEXT, is_new_customer INTEGER DEFAULT 0,
        sub_category TEXT, product_id INTEGER, product_code TEXT, product_name TEXT, unit TEXT,
        quantity REAL, weight REAL, volume REAL, unit_price REAL, final_amount REAL,
        description TEXT, checks_in_collection REAL, credit_balance REAL,
        cash_amount REAL, cash_date TEXT, total_credit REAL, status TEXT NOT NULL DEFAULT 'active',
        created_at INTEGER)''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_proposals_creator ON sale_proposals(creator_id, id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_proposals_brand ON sale_proposals(brand_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS sale_proposal_credits (
        id INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id INTEGER NOT NULL, amount REAL NOT NULL,
        due_date TEXT, FOREIGN KEY(proposal_id) REFERENCES sale_proposals(id) ON DELETE CASCADE)''')


def sales_board_access(conn, me):
    """(allowed, brand_ids|None) — دسترسی به تابلو اعلانات فروش.
    None یعنی همهٔ برندها (مدیرعامل/Administrator)."""
    role = me['role'] if me else None
    if role in SUPER_ROLES:
        return True, None
    if role == 'manager':
        brands = managed_brand_ids(conn, me['id'])
        return bool(brands), brands
    if role in ('supervisor', 'specialist'):
        dept = conn.execute('SELECT department_id FROM users WHERE id=?', (me['id'],)).fetchone()
        dept_name = ''
        if dept and dept['department_id']:
            row = conn.execute('SELECT name FROM departments WHERE id=?', (dept['department_id'],)).fetchone()
            dept_name = row['name'] if row else ''
        if 'فروش' not in dept_name:
            return False, set()
        return True, user_brand_ids(conn, me['id'])
    return False, set()


def sales_scoped_brands(conn, me):
    """برندهایی که کاربر فعلی در تابلو اعلانات فروش مجاز به دیدنشان است.
    None یعنی بدون محدودیت."""
    allowed, brands = sales_board_access(conn, me)
    if not allowed:
        return set()
    return brands


def sales_row_brand_filter(field='brand_id'):
    """شرط SQL محدودسازی ردیف‌ها به برندهای مجاز؛ {brands} با placeholder جایگزین می‌شود."""
    return f'{field} IS NOT NULL AND {field} IN ({{brands}})'


def excel_table_from_upload(file_storage):
    """اولین برگٔ فایل اکسل را به فهرست ردیف‌های متنی تبدیل می‌کند."""
    if file_storage is None or not file_storage.filename:
        return None, 'فایل اکسل انتخاب نشده است'
    if not file_storage.filename.lower().endswith(('.xlsx', '.xlsm')):
        return None, 'فقط فایل اکسل با پسوند xlsx یا xlsm پذیرفته می‌شود'
    try:
        wb = load_workbook(file_storage.stream, read_only=True, data_only=True)
    except Exception:
        return None, 'فایل اکسل خوانده نشد؛ مطمئن شوید فرمت معتبر است'
    ws = wb.active
    rows = []
    for raw in ws.iter_rows(values_only=True):
        rows.append([('' if cell is None else str(cell).strip()) for cell in raw])
    wb.close()
    if not rows:
        return None, 'فایل اکسل خالی است'
    return rows, None


def normalize_header(title):
    return ' '.join(str(title or '').strip().lower().replace('\u200c', ' ').replace('_', ' ').split())


def map_excel_headers(header_row, aliases):
    """(نگاشت نام_منطقی -> ایندکس ستون، لیست ستون‌های ناشناخته)"""
    mapping = {}
    unknown = []
    for idx, title in enumerate(header_row):
        norm = normalize_header(title)
        if not norm:
            continue
        matched = None
        for logical, names in aliases.items():
            if norm in {normalize_header(n) for n in names} and logical not in mapping:
                matched = logical
                break
        if matched:
            mapping[matched] = idx
        else:
            unknown.append(str(title))
    return mapping, unknown


def cell_value(row, mapping, key):
    idx = mapping.get(key)
    if idx is None or idx >= len(row):
        return ''
    return str(row[idx] or '').strip()


def parse_number(value):
    s = str(value or '').strip().replace(',', '').replace('\u066b', '.').replace('%', '')
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def jalali_today_str():
    return date.today().isoformat()


def new_customer_key(conn):
    while True:
        key = 'CUS-' + uuid.uuid4().hex[:8].upper()
        if not conn.execute('SELECT 1 FROM customers WHERE customer_key=?', (key,)).fetchone():
            return key


def next_proposal_code(conn):
    last = conn.execute("SELECT MAX(CAST(substr(proposal_code,5) AS INTEGER)) FROM sale_proposals "
                        "WHERE proposal_code LIKE 'SP-%'").fetchone()[0] or 0
    return f'SP-{last + 1:06d}'


def record_price_history(c, product_id, mode, price, min_price, max_price, note, actor_id, when_ms):
    c.execute('''INSERT INTO product_price_history (product_id,mode,price,min_price,max_price,change_note,changed_by,created_at)
                 VALUES (?,?,?,?,?,?,?,?)''',
              (product_id, mode, price, min_price, max_price, note, actor_id, when_ms))


def upsert_product_price(c, product_id, mode, price, min_price, max_price, percent_base, actor_id, now_ms):
    """ثبت قیمت جدید؛ قیمت قبلی قبل از بازنویسی در تاریخچه حفظ می‌شود."""
    prev = c.execute('SELECT * FROM product_prices WHERE product_id=?', (product_id,)).fetchone()
    if prev:
        record_price_history(c, product_id, prev['mode'], prev['price'], prev['min_price'], prev['max_price'],
                             'جایگزینی قیمت قبلی', prev['updated_by'], prev['updated_at'] or now_ms)
    c.execute('''INSERT INTO product_prices (product_id,mode,price,min_price,max_price,percent_base,updated_by,updated_at)
                 VALUES (?,?,?,?,?,?,?,?)
                 ON CONFLICT(product_id) DO UPDATE SET mode=excluded.mode, price=excluded.price,
                   min_price=excluded.min_price, max_price=excluded.max_price,
                   percent_base=excluded.percent_base, updated_by=excluded.updated_by, updated_at=excluded.updated_at''',
              (product_id, mode, price, min_price, max_price, percent_base, actor_id, now_ms))


def resolve_product_brand(conn, c, brand_name, brand_id=None):
    if brand_id:
        row = conn.execute('SELECT id, name FROM brands WHERE id=?', (brand_id,)).fetchone()
        if row:
            return row['id'], row['name']
    if brand_name:
        row = conn.execute('SELECT id, name FROM brands WHERE lower(name)=lower(?)', (brand_name,)).fetchone()
        if row:
            return row['id'], row['name']
    return None, (brand_name or None)


def default_user_brand(conn, me):
    """برند پیش‌فرض کاربر برای فایل‌های اکسل بدون ستون برند."""
    if me['role'] in SUPER_ROLES:
        return None
    row = conn.execute('SELECT brand_id FROM users WHERE id=?', (me['id'],)).fetchone()
    return row['brand_id'] if row else None


@app.route('/api/sales-board/access')
@login_required
def sales_board_access_api():
    """وضعیت دسترسی کاربر به تابلو اعلانات فروش + نقش/بخش/برند او برای رابط کاربری."""
    me = current_user()
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed:
            return jsonify({'allowed': False})
        full = brands is None
        brand_rows = conn.execute('SELECT id, name FROM brands ORDER BY id').fetchall()
        visible = [dict(b) for b in brand_rows if full or b['id'] in brands]
        profile = conn.execute('''SELECT u.name, u.role, u.department_id, d.name AS department_name,
                                         r.name AS job_role_name
                                  FROM users u LEFT JOIN departments d ON d.id=u.department_id
                                  LEFT JOIN job_roles r ON r.id=u.job_role_id WHERE u.id=?''', (me['id'],)).fetchone()
        return jsonify({
            'allowed': True, 'fullAccess': full, 'brands': visible,
            'canManageProducts': True,
            'canSetPrices': bool(profile and profile['role'] in SUPER_ROLES + ('manager',)),
            'canCreateProposal': bool(profile and profile['role'] == 'specialist'),
            'profile': {'name': profile['name'], 'role': profile['role'],
                        'roleName': {'admin': 'مدیرعامل', 'administrator': 'Administrator', 'manager': 'مدیر برند',
                                     'supervisor': 'سرپرست', 'specialist': 'کارشناس', 'employee': 'کارمند'}
                                    .get(profile['role'], profile['role']),
                        'department': profile['department_name'], 'jobRole': profile['job_role_name']},
        })
    finally:
        conn.close()


@app.route('/api/sales-board/products')
@login_required
def list_products():
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        where, params = '', []
        search = str(request.args.get('q') or '').strip()
        sub = str(request.args.get('sub_category') or '').strip()
        brand = request.args.get('brand_id')
        if brands is not None:
            where = f'p.brand_id IN ({",".join("?" * len(brands))})'
            params += list(brands)
        if search:
            where = (where + ' AND ' if where else '') + '(p.name LIKE ? OR p.source_product_id LIKE ? OR p.sub_category LIKE ?)'
            params += [f'%{search}%'] * 3
        if sub:
            where = (where + ' AND ' if where else '') + 'p.sub_category=?'
            params.append(sub)
        if brand:
            where = (where + ' AND ' if where else '') + 'p.brand_id=?'
            params.append(int(brand))
        rows = conn.execute(f'''SELECT p.*, pp.mode AS price_mode, pp.price, pp.min_price, pp.max_price,
                                        pp.updated_at AS price_updated_at
                                 FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id
                                 {"WHERE " + where if where else ""} ORDER BY p.name COLLATE NOCASE''', params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route('/api/sales-board/products/subcategories')
@login_required
def list_product_subcategories():
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify([])
        where, params = 'sub_category IS NOT NULL AND TRIM(sub_category)<>""', []
        if brands is not None:
            where += f' AND brand_id IN ({",".join("?" * len(brands))})'
            params += list(brands)
        rows = conn.execute(f'SELECT DISTINCT sub_category FROM products WHERE {where} ORDER BY sub_category',
                            params).fetchall()
        return jsonify([r['sub_category'] for r in rows])
    finally:
        conn.close()


@app.route('/api/sales-board/products', methods=['POST'])
@login_required
def create_product():
    me = current_user()
    data = request.json or {}
    code = str(data.get('source_product_id') or '').strip()
    name = str(data.get('name') or '').strip()
    if not code or not name:
        return jsonify({'error': 'کد کالا و نام کالا الزامی است'}), 400
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        brand_id = data.get('brand_id')
        brand_id = int(brand_id) if brand_id not in (None, '') else None
        if brands is not None:
            if brand_id not in brands:
                return jsonify({'error': 'فقط می‌توانید کالای برندهای خود را ثبت کنید'}), 403
        elif brand_id is None and not is_super(me):
            return jsonify({'error': 'برند را انتخاب کنید'}), 400
        if conn.execute('SELECT 1 FROM products WHERE source_product_id=?', (code,)).fetchone():
            return jsonify({'error': f'کد کالا «{code}» قبلاً ثبت شده است'}), 409
        brand_id, brand_name = resolve_product_brand(conn, None, data.get('brand_name'), brand_id)
        now_ms = int(time.time() * 1000)
        cur = conn.execute('''INSERT INTO products (source_product_id,name,unit,sub_category,brand_id,brand_name,created_at,updated_at)
                              VALUES (?,?,?,?,?,?,?,?)''',
                           (code, name, str(data.get('unit') or '').strip() or None,
                            str(data.get('sub_category') or '').strip() or None, brand_id, brand_name, now_ms, now_ms))
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid})
    finally:
        conn.close()


@app.route('/api/sales-board/products/<int:pid>', methods=['PUT'])
@login_required
def update_product(pid):
    me = current_user()
    data = request.json or {}
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        product = conn.execute('SELECT * FROM products WHERE id=?', (pid,)).fetchone()
        if not product:
            return jsonify({'error': 'کالا پیدا نشد'}), 404
        if brands is not None and product['brand_id'] not in brands:
            return jsonify({'error': 'فقط کالاهای برندهای خود را می‌توانید ویرایش کنید'}), 403
        fields = {k: data[k] for k in ('name', 'unit', 'sub_category', 'brand_name') if k in data}
        if 'brand_id' in data:
            brand_id = data['brand_id']
            fields['brand_id'] = int(brand_id) if brand_id not in (None, '') else None
            if brands is not None and fields['brand_id'] not in brands:
                return jsonify({'error': 'انتقال کالا به برند دیگر مجاز نیست'}), 403
        sets = ', '.join(f'{k}=?' for k in fields)
        conn.execute(f'UPDATE products SET {sets}, updated_at=? WHERE id=?',
                     (*fields.values(), int(time.time() * 1000), pid))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/sales-board/products/import', methods=['POST'])
@login_required
def import_products_excel():
    """آپلود اکسل کالا: کدهای جدید درج و کدهای تکراری بروزرسانی می‌شوند."""
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        rows, err = excel_table_from_upload(request.files.get('file'))
        if err:
            return jsonify({'error': err}), 400
        header_idx = next((i for i, r in enumerate(rows)
                           if any(str(x or '').strip().lower().replace('\u200c', ' ').find('sourcepro') == 0
                                  or str(x or '').strip() in ('کد کالا', 'کد محصول') for x in r)), None)
        if header_idx is None:
            return jsonify({'error': 'سطر عنوان با ستون SourceProductID (یا «کد کالا») پیدا نشد'}), 400
        mapping, _unknown = map_excel_headers(rows[header_idx], PRODUCT_EXCEL_ALIASES)
        if 'source_product_id' not in mapping or 'name' not in mapping:
            return jsonify({'error': 'ستون‌های الزامی SourceProductID و Product Name در فایل وجود ندارند'}), 400
        now_ms = int(time.time() * 1000)
        fallback_brand = default_user_brand(conn, me) if brands is not None else None
        added = updated = skipped = 0
        errors = []
        lock_for_create(conn)
        seen_codes = set()
        for line_no, row in enumerate(rows[header_idx + 1:], start=header_idx + 2):
            code = cell_value(row, mapping, 'source_product_id')
            name = cell_value(row, mapping, 'name')
            if not code and not name:
                continue
            if not code:
                skipped += 1
                errors.append(f'سطر {line_no}: کد کالا خالی است')
                continue
            if code in seen_codes:
                skipped += 1
                errors.append(f'سطر {line_no}: کد کالا «{code}» تکراری است در همین فایل')
                continue
            seen_codes.add(code)
            unit = cell_value(row, mapping, 'unit') or None
            sub = cell_value(row, mapping, 'sub_category') or None
            brand_name_raw = cell_value(row, mapping, 'brand') or None
            brand_id, brand_name = resolve_product_brand(conn, None, brand_name_raw)
            if brand_id is None and not brand_name_raw:
                brand_id, brand_name = fallback_brand, None
                if brand_id:
                    b = conn.execute('SELECT name FROM brands WHERE id=?', (brand_id,)).fetchone()
                    brand_name = b['name'] if b else None
            if brands is not None and brand_id not in brands:
                skipped += 1
                errors.append(f'سطر {line_no}: برند «{brand_name_raw or "بدون برند"}» خارج از محدودهٔ دسترسی شماست')
                continue
            existing = conn.execute('SELECT * FROM products WHERE source_product_id=?', (code,)).fetchone()
            if existing:
                conn.execute('''UPDATE products SET name=?, unit=COALESCE(?,unit), sub_category=COALESCE(?,sub_category),
                                brand_id=COALESCE(?,brand_id), brand_name=COALESCE(?,brand_name), updated_at=?
                                WHERE id=?''', (name or existing['name'], unit, sub, brand_id, brand_name, now_ms,
                                                 existing['id']))
                updated += 1
            else:
                conn.execute('''INSERT INTO products (source_product_id,name,unit,sub_category,brand_id,brand_name,created_at,updated_at)
                                VALUES (?,?,?,?,?,?,?,?)''',
                             (code, name, unit, sub, brand_id, brand_name, now_ms, now_ms))
                added += 1
        conn.commit()
        return jsonify({'success': True, 'added': added, 'updated': updated, 'skipped': skipped,
                        'errors': errors[:20], 'message': f'{added} کالا افزوده و {updated} کالا بروزرسانی شد'})
    finally:
        conn.close()


@app.route('/api/sales-board/prices')
@login_required
def list_product_prices():
    """فهرست کالاهای قابل قیمت‌گذاری همراه قیمت فعلی (برای تب قیمت‌گذاری مدیر برند)."""
    me = current_user()
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed or (brands is not None and not brands):
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        if brands is None:
            rows = conn.execute('''SELECT p.id, p.source_product_id, p.name, p.unit, p.sub_category,
                                          p.brand_id, p.brand_name, b.name AS brand_label,
                                          pp.mode AS price_mode, pp.price, pp.min_price, pp.max_price, pp.percent_base
                                   FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id
                                   LEFT JOIN brands b ON b.id=p.brand_id ORDER BY p.name COLLATE NOCASE''').fetchall()
        else:
            rows = conn.execute(f'''SELECT p.id, p.source_product_id, p.name, p.unit, p.sub_category,
                                            p.brand_id, p.brand_name, b.name AS brand_label,
                                            pp.mode AS price_mode, pp.price, pp.min_price, pp.max_price, pp.percent_base
                                     FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id
                                     LEFT JOIN brands b ON b.id=p.brand_id
                                     WHERE p.brand_id IN ({",".join("?" * len(brands))})
                                     ORDER BY p.name COLLATE NOCASE''', list(brands)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route('/api/sales-board/prices/set', methods=['POST'])
@login_required
def set_product_price():
    """تعیین تک‌قیمت یا بازهٔ قیمتی. حالت percent: افزایش/کاهش درصدی از آخرین قیمت ثبت‌شده.
    هر تغییر، قیمت قبلی را در تاریخچه حفظ می‌کند."""
    me = current_user()
    data = request.json or {}
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        if me['role'] not in SUPER_ROLES + ('manager',):
            return jsonify({'error': 'فقط مدیرعامل و مدیر برند می‌توانند قیمت‌گذاری کنند'}), 403
        try:
            product_id = int(data.get('product_id'))
        except (TypeError, ValueError):
            return jsonify({'error': 'کالا نامعتبر است'}), 400
        product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            return jsonify({'error': 'کالا پیدا نشد'}), 404
        if brands is not None and product['brand_id'] not in brands:
            return jsonify({'error': 'فقط کالاهای برندهای خود را می‌توانید قیمت‌گذاری کنید'}), 403
        mode = str(data.get('mode') or 'single')
        if mode not in ('single', 'range', 'percent'):
            return jsonify({'error': 'حالت قیمت نامعتبر است'}), 400
        now_ms = int(time.time() * 1000)
        c = conn.cursor()
        lock_for_create(conn)
        current = c.execute('SELECT * FROM product_prices WHERE product_id=?', (product_id,)).fetchone()
        if mode == 'percent':
            if not current:
                return jsonify({'error': 'ابتدا باید یک قیمت یا بازه برای این کالا ثبت شود'}), 400
            pct = parse_number(data.get('percent'))
            if pct is None:
                return jsonify({'error': 'درصد را وارد کنید (مثلاً ۵ یا -۵)'}), 400
            base = current['percent_base']
            if base is None:
                base = current['price'] if current['mode'] == 'single' and current['price'] is not None else None
                if base is None and current['mode'] == 'range':
                    base = ((current['min_price'] or 0) + (current['max_price'] or 0)) / 2
                if base is None:
                    return jsonify({'error': 'پایهٔ محاسبهٔ درصد موجود نیست؛ ابتدا قیمت ثابت ثبت کنید'}), 400
                c.execute('UPDATE product_prices SET percent_base=? WHERE product_id=?', (base, product_id))
            factor = 1 + pct / 100.0
            if current['mode'] == 'range':
                price = None
                min_p = round((current['min_price'] or 0) * factor, 2)
                max_p = round((current['max_price'] or 0) * factor, 2)
            else:
                price = round((current['price'] or 0) * factor, 2)
                min_p = max_p = None
            c.execute('''UPDATE product_prices SET mode=?, price=?, min_price=?, max_price=?, updated_by=?, updated_at=?
                         WHERE product_id=?''', (current['mode'], price, min_p, max_p, me['id'], now_ms, product_id))
            record_price_history(c, product_id, current['mode'], price, min_p, max_p,
                                 f'تغییر درصدی {pct:+g}٪ (پایه {base:g})', me['id'], now_ms)
        elif mode == 'range':
            min_p = parse_number(data.get('min_price'))
            max_p = parse_number(data.get('max_price'))
            if min_p is None or max_p is None or min_p <= 0 or max_p < min_p:
                return jsonify({'error': 'بازهٔ قیمتی معتبر وارد کنید (حداقل ≤ حداکثر، هر دو بزرگ‌تر از صفر)'}), 400
            upsert_product_price(c, product_id, 'range', None, min_p, max_p, None, me['id'], now_ms)
            record_price_history(c, product_id, 'range', None, min_p, max_p, 'ثبت بازهٔ قیمتی جدید', me['id'], now_ms)
        else:
            price = parse_number(data.get('price'))
            if price is None or price <= 0:
                return jsonify({'error': 'قیمت معتبر (بزرگ‌تر از صفر) وارد کنید'}), 400
            upsert_product_price(c, product_id, 'single', price, None, None, price, me['id'], now_ms)
            record_price_history(c, product_id, 'single', price, None, None, 'ثبت تک‌قیمت جدید', me['id'], now_ms)
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/sales-board/prices/history/<int:product_id>')
@login_required
def product_price_history(product_id):
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        product = conn.execute('SELECT * FROM products WHERE id=?', (product_id,)).fetchone()
        if not product:
            return jsonify({'error': 'کالا پیدا نشد'}), 404
        if brands is not None and product['brand_id'] not in brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        rows = conn.execute('''SELECT h.*, u.name AS changer FROM product_price_history h
                               LEFT JOIN users u ON u.id=h.changed_by WHERE h.product_id=? ORDER BY h.id DESC''',
                            (product_id,)).fetchall()
        return jsonify({'product': dict(product), 'history': [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route('/api/sales-board/customers')
@login_required
def list_customers():
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        where, params = '', []
        search = str(request.args.get('q') or '').strip()
        brand = request.args.get('brand_id')
        if brands is not None:
            where = f'c.brand_id IN ({",".join("?" * len(brands))})'
            params += list(brands)
        if search:
            where = (where + ' AND ' if where else '') + \
                    '(c.name LIKE ? OR c.customer_key LIKE ? OR IFNULL(c.customer_code,\'\') LIKE ? OR IFNULL(c.company,\'\') LIKE ?)'
            params += [f'%{search}%'] * 4
        if brand:
            where = (where + ' AND ' if where else '') + 'c.brand_id=?'
            params.append(int(brand))
        rows = conn.execute(f'''SELECT c.* FROM customers c {"WHERE " + where if where else ""}
                                 ORDER BY c.name COLLATE NOCASE''', params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route('/api/sales-board/customers', methods=['POST'])
@login_required
def create_customer():
    me = current_user()
    data = request.json or {}
    name = str(data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'نام مشتری الزامی است'}), 400
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        brand_id = data.get('brand_id')
        brand_id = int(brand_id) if brand_id not in (None, '') else None
        if brands is not None and brand_id not in brands:
            return jsonify({'error': 'فقط برای برندهای خود می‌توانید مشتری ثبت کنید'}), 403
        brand_id, brand_name = resolve_product_brand(conn, None, data.get('brand_name'), brand_id)
        key = new_customer_key(conn)
        cur = conn.execute('''INSERT INTO customers (customer_key,customer_code,name,brand_id,brand_name,brand_code,
                              company,address,phone,email,source,created_by,created_at)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (key, str(data.get('customer_code') or '').strip() or None, name, brand_id, brand_name,
                            str(data.get('brand_code') or '').strip() or None,
                            str(data.get('company') or '').strip() or None,
                            str(data.get('address') or '').strip() or None,
                            str(data.get('phone') or '').strip() or None,
                            str(data.get('email') or '').strip() or None,
                            'manual', me['id'], int(time.time() * 1000)))
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'customer_key': key})
    finally:
        conn.close()


@app.route('/api/sales-board/customers/<int:cid>', methods=['PUT'])
@login_required
def update_customer(cid):
    me = current_user()
    data = request.json or {}
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        customer = conn.execute('SELECT * FROM customers WHERE id=?', (cid,)).fetchone()
        if not customer:
            return jsonify({'error': 'مشتری پیدا نشد'}), 404
        if brands is not None and customer['brand_id'] not in brands:
            return jsonify({'error': 'فقط مشتریان برندهای خود را می‌توانید ویرایش کنید'}), 403
        fields = {k: str(data[k]).strip() or None for k in
                  ('customer_code', 'name', 'brand_code', 'company', 'address', 'phone', 'email') if k in data}
        if 'brand_id' in data:
            brand_id = data['brand_id']
            fields['brand_id'] = int(brand_id) if brand_id not in (None, '') else None
            if brands is not None and fields['brand_id'] not in brands:
                return jsonify({'error': 'انتقال مشتری به برند دیگر مجاز نیست'}), 403
            _, fields['brand_name'] = resolve_product_brand(conn, None, data.get('brand_name'), fields['brand_id'])
        if not fields:
            return jsonify({'success': True})
        sets = ', '.join(f'{k}=?' for k in fields)
        conn.execute(f'UPDATE customers SET {sets} WHERE id=?', (*fields.values(), cid))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/sales-board/customers/import', methods=['POST'])
@login_required
def import_customers_excel():
    """آپلود اکسل مشتریان: کد مشتری تکراری فقط اگر کدبرند متفاوت باشد رکورد جدید می‌سازد؛
    در غیر این صورت تکراری نادیده گرفته می‌شود. CustomerKey خودکار و یونیک ساخته می‌شود."""
    me = current_user()
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        rows, err = excel_table_from_upload(request.files.get('file'))
        if err:
            return jsonify({'error': err}), 400
        header_idx = next((i for i, r in enumerate(rows)
                           if any(str(x or '').strip().lower().replace('\u200c', '-').replace(' ', '-') == 'customercode'
                                  or str(x or '').strip() == 'کد مشتری' for x in r)), None)
        if header_idx is None:
            return jsonify({'error': 'سطر عنوان با ستون CustomerCode (یا «کد مشتری») پیدا نشد'}), 400
        mapping, _unknown = map_excel_headers(rows[header_idx], CUSTOMER_EXCEL_ALIASES)
        required = ('customer_code', 'name', 'brand', 'brand_code')
        missing = [k for k in required if k not in mapping]
        if missing:
            return jsonify({'error': 'ستون‌های زیر در فایل وجود ندارند: ' + ', '.join(missing)}), 400
        now_ms = int(time.time() * 1000)
        fallback_brand = default_user_brand(conn, me) if brands is not None else None
        added = skipped = 0
        errors = []
        lock_for_create(conn)
        for line_no, row in enumerate(rows[header_idx + 1:], start=header_idx + 2):
            code = cell_value(row, mapping, 'customer_code')
            name = cell_value(row, mapping, 'name')
            brand_name_raw = cell_value(row, mapping, 'brand')
            brand_code = cell_value(row, mapping, 'brand_code')
            if not code and not name:
                continue
            if not code:
                skipped += 1
                errors.append(f'سطر {line_no}: کد مشتری خالی است')
                continue
            brand_id, brand_name = resolve_product_brand(conn, None, brand_name_raw)
            if brand_id is None and not brand_name_raw:
                brand_id, brand_name = fallback_brand, None
                if brand_id:
                    b = conn.execute('SELECT name FROM brands WHERE id=?', (brand_id,)).fetchone()
                    brand_name = b['name'] if b else None
            if brands is not None and brand_id not in brands:
                skipped += 1
                errors.append(f'سطر {line_no}: برند «{brand_name_raw or "بدون برند"}» خارج از محدودهٔ دسترسی شماست')
                continue
            duplicate = conn.execute('''SELECT 1 FROM customers WHERE customer_code=? AND IFNULL(brand_code,'')=?''',
                                     (code, brand_code)).fetchone()
            if duplicate:
                skipped += 1
                continue
            cur = conn.execute('''INSERT INTO customers (customer_key,customer_code,name,brand_id,brand_name,brand_code,
                                  company,address,phone,email,source,created_by,created_at)
                                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                               (new_customer_key(conn), code, name or code, brand_id, brand_name, brand_code or None,
                                cell_value(row, mapping, 'company') or None,
                                cell_value(row, mapping, 'address') or None,
                                cell_value(row, mapping, 'phone') or None,
                                cell_value(row, mapping, 'email') or None,
                                'excel', me['id'], now_ms))
            added += 1
        conn.commit()
        return jsonify({'success': True, 'added': added, 'skipped': skipped, 'errors': errors[:20],
                        'message': f'{added} مشتری افزوده و {skipped} ردیف تکراری/نامعتبر نادیده گرفته شد'})
    finally:
        conn.close()


@app.route('/api/sales-board/proposal-options')
@login_required
def proposal_options():
    """اطلاعات لاگین فروشنده + مشتریان، ساب‌کتگوری‌ها و کالاهای برند خودش برای فرم پیشنهاد فروش."""
    me = current_user()
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed or (brands is not None and not brands):
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        profile = conn.execute('''SELECT u.name, u.role, d.name AS department_name, r.name AS job_role_name
                                  FROM users u LEFT JOIN departments d ON d.id=u.department_id
                                  LEFT JOIN job_roles r ON r.id=u.job_role_id WHERE u.id=?''', (me['id'],)).fetchone()
        brand_list = sorted(brands) if brands is not None else None
        if brand_list:
            ph = ','.join('?' * len(brand_list))
            customers = conn.execute(f'''SELECT id, customer_key, customer_code, name, brand_id, brand_name, company
                                          FROM customers WHERE brand_id IN ({ph}) ORDER BY name COLLATE NOCASE''',
                                     brand_list).fetchall()
            subcats = conn.execute(f'''SELECT DISTINCT sub_category FROM products
                                        WHERE brand_id IN ({ph}) AND sub_category IS NOT NULL AND TRIM(sub_category)<>''
                                        ORDER BY sub_category''', brand_list).fetchall()
        else:
            customers = conn.execute('''SELECT id, customer_key, customer_code, name, brand_id, brand_name, company
                                        FROM customers ORDER BY name COLLATE NOCASE''').fetchall()
            subcats = conn.execute('''SELECT DISTINCT sub_category FROM products
                                      WHERE sub_category IS NOT NULL AND TRIM(sub_category)<>'' ORDER BY sub_category''').fetchall()
        brands_out = conn.execute('SELECT id, name FROM brands ORDER BY id').fetchall()
        visible_brands = [dict(b) for b in brands_out if brand_list is None or b['id'] in brand_list]
        return jsonify({
            'seller': {'name': profile['name'], 'roleName': {'admin': 'مدیرعامل', 'administrator': 'Administrator',
                                                              'manager': 'مدیر برند', 'supervisor': 'سرپرست',
                                                              'specialist': 'کارشناس', 'employee': 'کارمند'}
                                                             .get(profile['role'], profile['role']),
                       'department': profile['department_name'], 'jobRole': profile['job_role_name'],
                       'brands': [b['name'] for b in conn.execute(
                           f'SELECT b.name FROM brands b WHERE b.id IN ({",".join("?" * len(brand_list))})'
                           if brand_list else 'SELECT name FROM brands WHERE 0').fetchall()] if brand_list else
                                  [b['name'] for b in brands_out]},
            'customers': [dict(r) for r in customers],
            'subCategories': [r['sub_category'] for r in subcats],
            'brands': visible_brands,
            'units': list(SALES_UNITS),
        })
    finally:
        conn.close()


@app.route('/api/sales-board/proposal-products')
@login_required
def proposal_products():
    """کالاهای یک ساب‌کتگوری در برندهای فروشنده (برای انتخاب با جستجوی نام یا کد)."""
    me = current_user()
    sub = str(request.args.get('sub_category') or '').strip()
    if not sub:
        return jsonify({'error': 'ساب‌کتگوری را مشخص کنید'}), 400
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        params = [sub]
        where = 'p.sub_category=?'
        if brands is not None:
            where += f' AND p.brand_id IN ({",".join("?" * len(brands))})'
            params += list(brands)
        q = str(request.args.get('q') or '').strip()
        if q:
            where += ' AND (p.name LIKE ? OR p.source_product_id LIKE ?)'
            params += [f'%{q}%'] * 2
        rows = conn.execute(f'''SELECT p.id, p.source_product_id, p.name, p.unit, p.sub_category, p.brand_id, p.brand_name,
                                       pp.mode AS price_mode, pp.price, pp.min_price, pp.max_price
                                FROM products p LEFT JOIN product_prices pp ON pp.product_id=p.id
                                WHERE {where} ORDER BY p.name COLLATE NOCASE''', params).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route('/api/sales-board/customers/check-name')
@login_required
def check_customer_name():
    """بررسی تکراری بودن نام مشتری جدید (در همان برند)."""
    me = current_user()
    name = str(request.args.get('name') or '').strip()
    brand_id = request.args.get('brand_id')
    conn = get_db()
    try:
        brands = sales_scoped_brands(conn, me)
        if brands is not None and not brands:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        where, params = 'name=?', [name]
        if brand_id:
            where += ' AND brand_id=?'
            params.append(int(brand_id))
        elif brands is not None:
            where += f' AND brand_id IN ({",".join("?" * len(brands))})'
            params += list(brands)
        exists = conn.execute(f'SELECT 1 FROM customers WHERE {where} LIMIT 1', params).fetchone() is not None
        return jsonify({'exists': exists})
    finally:
        conn.close()


@app.route('/api/sales-board/proposals', methods=['GET', 'POST'])
@login_required
def sale_proposals():
    me = current_user()
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        if request.method == 'GET':
            scope_brand_sql = None
            if brands is not None:
                if not brands:
                    return jsonify([])
                scope_brand_sql = ','.join(str(int(b)) for b in brands)
            if request.args.get('mine') == '1':
                rows = conn.execute('SELECT * FROM sale_proposals WHERE creator_id=? ORDER BY id DESC',
                                    (me['id'],)).fetchall()
            elif brands is None:
                rows = conn.execute('SELECT * FROM sale_proposals ORDER BY id DESC').fetchall()
            else:
                rows = conn.execute(f'SELECT * FROM sale_proposals WHERE brand_id IN ({scope_brand_sql}) ORDER BY id DESC').fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d['credits'] = [dict(x) for x in conn.execute(
                    'SELECT amount, due_date FROM sale_proposal_credits WHERE proposal_id=?', (r['id'],))]
                out.append(d)
            return jsonify(out)

        # ---- ایجاد پیشنهاد فروش ----
        if me['role'] != 'specialist':
            return jsonify({'error': 'ثبت پیشنهاد فروش فقط برای کارشناس (بخش فروش) فعال است'}), 403
        if 'فروش' not in str(conn.execute('SELECT IFNULL(d.name,\'\') n FROM users u '
                                           'LEFT JOIN departments d ON d.id=u.department_id WHERE u.id=?',
                                           (me['id'],)).fetchone()['n']):
            return jsonify({'error': 'برای ثبت پیشنهاد فروش، بخش شما باید «فروش» باشد'}), 403
        data = request.json or {}
        now_ms = int(time.time() * 1000)
        my_brands = brands if brands is not None else user_brand_ids(conn, me['id'])
        if not my_brands:
            return jsonify({'error': 'برندی برای شما تعریف نشده است'}), 400

        customer = None
        is_new_customer = 0
        customer_id = data.get('customer_id')
        if customer_id:
            customer = conn.execute('SELECT * FROM customers WHERE id=?', (customer_id,)).fetchone()
            if not customer or customer['brand_id'] not in my_brands:
                return jsonify({'error': 'مشتری انتخابی در برندهای شما یافت نشد'}), 400
        else:
            cname = str(data.get('new_customer_name') or '').strip()
            if not cname:
                return jsonify({'error': 'مشتری را انتخاب کنید یا نام مشتری جدید را بنویسید'}), 400
            clash = conn.execute(f'''SELECT 1 FROM customers WHERE name=? AND brand_id IN ({",".join("?" * len(my_brands))})
                                     LIMIT 1''', (cname, *my_brands)).fetchone()
            if clash:
                return jsonify({'error': f'نام «{cname}» قبلاً در مشتریان ثبت شده است؛ نام دیگری وارد کنید یا از فهرست انتخاب کنید'}), 409
            brand_row = conn.execute('SELECT name FROM brands WHERE id=?', (sorted(my_brands)[0],)).fetchone()
            key = new_customer_key(conn)
            cur = conn.execute('''INSERT INTO customers (customer_key,customer_code,name,brand_id,brand_name,source,created_by,created_at)
                                  VALUES (?,?,?,?,?,?,?,?)''',
                               (key, None, cname, sorted(my_brands)[0], brand_row['name'] if brand_row else None,
                                'proposal', me['id'], now_ms))
            customer = conn.execute('SELECT * FROM customers WHERE id=?', (cur.lastrowid,)).fetchone()
            is_new_customer = 1

        product = conn.execute('SELECT * FROM products WHERE id=?', (data.get('product_id') or 0,)).fetchone()
        if not product or (product['brand_id'] not in my_brands):
            return jsonify({'error': 'کالای انتخابی در برندهای شما یافت نشد'}), 400

        def qty_for(unit):
            return parse_number(data.get(unit))

        unit = product['unit'] or 'عدد'
        qty_map = {'عدد': 'quantity', 'کیلوگرم': 'weight', 'لیتر': 'volume', 'بسته': 'quantity', 'جفت': 'quantity'}
        qty_field = qty_map.get(unit, 'quantity')
        qty = qty_for(qty_field)
        if qty is None or qty <= 0:
            label = {'quantity': 'تعداد', 'weight': 'وزن', 'volume': 'حجم'}[qty_field]
            return jsonify({'error': f'«{label}» معتبر وارد کنید'}), 400

        price_row = conn.execute('SELECT * FROM product_prices WHERE product_id=?', (product['id'],)).fetchone()
        ref_price = None
        if price_row:
            if price_row['mode'] == 'single':
                ref_price = price_row['price']
            elif price_row['mode'] == 'range' and price_row['min_price'] is not None:
                ref_price = price_row['min_price']
        unit_price = parse_number(data.get('unit_price'))
        if unit_price is None:
            unit_price = ref_price
        if unit_price is None or unit_price <= 0:
            return jsonify({'error': 'قیمت فروش را وارد کنید (برای این کالا قیمتی ثبت نشده است)'}), 400

        credits = []
        for item in (data.get('credit_items') or []):
            amount = parse_number(item.get('amount')) if isinstance(item, dict) else None
            due = str(item.get('due_date') or '').strip() if isinstance(item, dict) else ''
            if amount is None or amount <= 0:
                return jsonify({'error': 'مبلغ اعتباری نامعتبر است'}), 400
            if not due:
                return jsonify({'error': 'تاریخ سررسید هر مبلغ اعتباری الزامی است'}), 400
            credits.append((amount, due))
        cash = parse_number(data.get('cash_amount')) or 0
        if cash < 0:
            return jsonify({'error': 'مبلغ نقدی نمی‌تواند منفی باشد'}), 400
        total_credit = round(sum(a for a, _ in credits), 2)
        final_amount = round(qty * unit_price, 2)

        profile = conn.execute('''SELECT u.name, u.role, d.name AS department_name, r.name AS job_role_name
                                  FROM users u LEFT JOIN departments d ON d.id=u.department_id
                                  LEFT JOIN job_roles r ON r.id=u.job_role_id WHERE u.id=?''', (me['id'],)).fetchone()
        brand_row = conn.execute('SELECT name FROM brands WHERE id=?', (product['brand_id'],)).fetchone()
        lock_for_create(conn)
        code = next_proposal_code(conn)
        cur = conn.execute('''INSERT INTO sale_proposals (proposal_code,creator_id,brand_id,brand_name,job_role,department,
                              customer_id,customer_key,customer_name,is_new_customer,sub_category,product_id,product_code,
                              product_name,unit,quantity,weight,volume,unit_price,final_amount,description,
                              checks_in_collection,credit_balance,cash_amount,cash_date,total_credit,status,created_at)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (code, me['id'], product['brand_id'], brand_row['name'] if brand_row else product['brand_name'],
                            profile['job_role_name'], profile['department_name'], customer['id'], customer['customer_key'],
                            customer['name'], is_new_customer, product['sub_category'], product['id'],
                            product['source_product_id'], product['name'], unit,
                            qty if qty_field == 'quantity' else None,
                            qty if qty_field == 'weight' else None,
                            qty if qty_field == 'volume' else None,
                            unit_price, final_amount, str(data.get('description') or '').strip() or None,
                            parse_number(data.get('checks_in_collection')), parse_number(data.get('credit_balance')),
                            cash, jalali_today_str(), total_credit, 'active', now_ms))
        for amount, due in credits:
            conn.execute('INSERT INTO sale_proposal_credits (proposal_id,amount,due_date) VALUES (?,?,?)',
                         (cur.lastrowid, amount, due))
        conn.commit()
        notify_brand_managers = conn.execute('SELECT manager_id FROM brands WHERE id=?', (product['brand_id'],)).fetchone()
        if notify_brand_managers and notify_brand_managers['manager_id']:
            create_notification(notify_brand_managers['manager_id'], 'پیشنهاد فروش جدید',
                                f'«{profile["name"]}» پیشنهاد فروش {code} را برای مشتری «{customer["name"]}» ثبت کرد.',
                                'info', conn=conn)
        conn.commit()
        return jsonify({'success': True, 'id': cur.lastrowid, 'proposal_code': code,
                        'final_amount': final_amount, 'is_new_customer': bool(is_new_customer),
                        'customer_key': customer['customer_key']})
    finally:
        conn.close()


@app.route('/api/sales-board/proposals/<int:prop_id>', methods=['DELETE'])
@login_required
def delete_sale_proposal(prop_id):
    me = current_user()
    conn = get_db()
    try:
        allowed, brands = sales_board_access(conn, me)
        if not allowed:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        prop = conn.execute('SELECT * FROM sale_proposals WHERE id=?', (prop_id,)).fetchone()
        if not prop:
            return jsonify({'error': 'پیشنهاد پیدا نشد'}), 404
        if me['role'] not in SUPER_ROLES and prop['creator_id'] != me['id'] and \
           not (me['role'] == 'supervisor' and brands is not None and prop['brand_id'] in brands):
            return jsonify({'error': 'فقط سازنده یا سرپرست/مدیر می‌تواند پیشنهاد را حذف کند'}), 403
        if brands is not None and prop['brand_id'] not in brands and prop['creator_id'] != me['id']:
            return jsonify({'error': 'دسترسی غیرمجاز'}), 403
        conn.execute('DELETE FROM sale_proposal_credits WHERE proposal_id=?', (prop_id,))
        conn.execute('DELETE FROM sale_proposals WHERE id=?', (prop_id,))
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    setup_conn = get_db()
    ready = executive_setup_done(setup_conn)
    setup_conn.close()
    if not ready:
        raise SystemExit('ابتدا از همین پوشه اجرا کنید: python configure_executives.py')
    print("=" * 50)
    print("🚀 سرور راه‌اندازی شد!")
    print("📍 آدرس: http://localhost:5000")
    print("ورود با نقش‌های مدیرعامل و Administrator تنظیم‌شده در configure_executives.py")
    print("=" * 50)
    # هشدار: debug=True هرگز نباید در محیط عملیاتی (production) روشن بماند —
    # دیباگر Werkzeug به هر کسی که به یک خطا برسد اجازه اجرای کد دلخواه روی سرور را می‌دهد.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
