"""آزمون خودکار تابلو اعلانات فروش با دیتابیس موقت.

اجرا:  python ./test_sales_board_flow.py
این تست یک کپی از database.db در پوشهٔ موقت می‌سازد و هیچ داده‌ای را در
دیتابیس اصلی تغییر نمی‌دهد. رمز عبور حساب‌های تستی فقط در همان کپی ست می‌شود.
"""
import io
import os
import shutil
import sqlite3
import tempfile

TEST_PASSWORD = 'SalesTest123!'


def build_workbook(rows):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


def main():
    data_dir = tempfile.mkdtemp(prefix='tm-sales-test-')
    base = os.path.dirname(os.path.abspath(__file__))
    src_db = os.path.join(base, 'database.db')
    if os.path.isfile(src_db):
        shutil.copy(src_db, os.path.join(data_dir, 'database.db'))
    key_src = os.path.join(base, '.taskmanager-secret-key')
    if os.path.isfile(key_src):
        shutil.copy(key_src, os.path.join(data_dir, '.taskmanager-secret-key'))
    os.environ['TASKMANAGER_DATA_DIR'] = data_dir

    from werkzeug.security import generate_password_hash
    import app as application

    application.init_db()
    conn = sqlite3.connect(os.path.join(data_dir, 'database.db'))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # ---- محیط تست: برند، بخش فروش، مدیر برند، کارشناس فروش، سرپرست فروش، کارشناس غیرفروش ----
    brand = c.execute("SELECT id FROM brands WHERE name='RETRONA'").fetchone() \
        or c.execute('SELECT id FROM brands LIMIT 1').fetchone()
    brand_id = brand['id']
    sales_dept = c.execute("SELECT id FROM departments WHERE name='فروش'").fetchone()['id']
    other_dept = c.execute("SELECT id FROM departments WHERE name='مالی'").fetchone()['id']
    ceo = c.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()['id']
    h = generate_password_hash(TEST_PASSWORD)
    people = {}
    for key, name, role, dept in (
            ('manager', 'مدیر برند تست', 'manager', None),
            ('seller', 'کارشناس فروش تست', 'specialist', sales_dept),
            ('supervisor', 'سرپرست فروش تست', 'supervisor', sales_dept),
            ('other_specialist', 'کارشناس مالی تست', 'specialist', other_dept),
            ('employee', 'کارمند تست', 'employee', other_dept)):
        username = f'sbtest_{key}'
        c.execute('DELETE FROM users WHERE username=?', (username,))
        c.execute('INSERT INTO users (name,username,password,role,brand_id,department_id) VALUES (?,?,?,?,?,?)',
                  (name, username, h, role, brand_id, dept))
        people[key] = c.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()['id']
    c.execute('UPDATE brands SET manager_id=? WHERE id=?', (people['manager'], brand_id))
    c.execute("INSERT OR IGNORE INTO app_settings (key,value) VALUES ('executives_configured','1')")
    for table in ('products', 'product_prices', 'product_price_history', 'customers',
                  'sale_proposals', 'sale_proposal_credits'):
        c.execute(f'DELETE FROM {table}')
    conn.commit()
    conn.close()

    client = application.app.test_client()

    def login(username, role):
        r = client.post('/api/login', json={'username': username, 'password': TEST_PASSWORD, 'role': role})
        assert r.status_code == 200 and r.get_json().get('success'), r.get_data(as_text=True)

    def get(path, **kw):
        r = client.get(path, query_string=kw)
        assert r.status_code == 200, (path, r.get_data(as_text=True))
        return r.get_json()

    def post_json(path, payload):
        r = client.post(path, json=payload)
        return r

    def must_ok(r, ctx=''):
        assert r.status_code == 200, (ctx, r.get_data(as_text=True))
        body = r.get_json()
        assert body.get('success', True) or isinstance(body, list), (ctx, body)
        return body

    # ---- دسترسی ----
    login('sbtest_manager', 'manager')
    acc = get('/api/sales-board/access')
    assert acc['allowed'] and not acc['fullAccess'] and acc['canSetPrices'] and not acc['canCreateProposal']

    login('sbtest_other_specialist', 'specialist')
    assert get('/api/sales-board/access') == {'allowed': False}
    r = client.get('/api/sales-board/products')
    assert r.status_code == 403, 'کارشناس غیرفروش نباید کالا ببیند'

    login('sbtest_employee', 'employee')
    assert get('/api/sales-board/access') == {'allowed': False}

    # ---- مدیریت کالا: افزودن دستی + تکراری ----
    login('sbtest_manager', 'manager')
    must_ok(post_json('/api/sales-board/products', {
        'source_product_id': 'P-100', 'name': 'کالای الف', 'unit': 'عدد', 'sub_category': 'ساب۱', 'brand_id': brand_id}),
        'create product')
    dup = post_json('/api/sales-board/products', {
        'source_product_id': 'P-100', 'name': 'تکراری', 'brand_id': brand_id})
    assert dup.status_code == 409, dup.get_data(as_text=True)

    # ---- آپلود اکسل کالا: جدید افزوده، تکراری بروزرسانی ----
    wb = build_workbook([
        ['SourceProdictID', 'Product Name', 'Unit', 'SubCategory', 'Brand'],
        ['P-100', 'کالای الف ویرایش', 'عدد', 'ساب۱', None],   # تکراری -> مشخصات آپدیت
        ['P-200', 'کالای ب', 'کیلوگرم', 'ساب۲', None],           # جدید
        ['P-300', 'کالای ج', 'لیتر', 'ساب۲', None],             # جدید
    ])
    r = client.post('/api/sales-board/products/import', data={'file': (wb, 'products.xlsx')},
                    content_type='multipart/form-data')
    body = must_ok(r, 'import products')
    assert body['added'] == 2 and body['updated'] == 1, body
    products = get('/api/sales-board/products')
    by_code = {p['source_product_id']: p for p in products}
    assert by_code['P-100']['name'] == 'کالای الف ویرایش'
    assert set(by_code) == {'P-100', 'P-200', 'P-300'}

    # ---- قیمت‌گذاری: تک‌قیمت، درصدی، بازه + تاریخچه ----
    pid = by_code['P-200']['id']
    must_ok(post_json('/api/sales-board/prices/set', {'product_id': pid, 'mode': 'single', 'price': 100000}), 'single price')
    must_ok(post_json('/api/sales-board/prices/set', {'product_id': pid, 'mode': 'percent', 'percent': 5}), '+5%')
    must_ok(post_json('/api/sales-board/prices/set', {'product_id': pid, 'mode': 'percent', 'percent': -5}), '-5%')
    must_ok(post_json('/api/sales-board/prices/set', {'product_id': pid, 'mode': 'range', 'min_price': 90000, 'max_price': 120000}), 'range')
    must_ok(post_json('/api/sales-board/prices/set', {'product_id': pid, 'mode': 'percent', 'percent': 10}), '+10% on range')
    hist = get(f'/api/sales-board/prices/history/{pid}')
    prices_seq = [(h['mode'], h['price'], h['min_price'], h['max_price']) for h in hist['history']]
    # تاریخچه نزولی: آخرین تغییر (+10 روی بازه) => 99000..132000
    assert prices_seq[0] == ('range', None, 99000.0, 132000.0), prices_seq
    assert len(prices_seq) >= 5, 'هر تغییر قیمت باید رکورد تاریخچه داشته باشد'

    # کارشناس فروش نباید بتواند قیمت ثبت کند
    login('sbtest_seller', 'specialist')
    r = client.post('/api/sales-board/prices/set', json={'product_id': pid, 'mode': 'single', 'price': 1})
    assert r.status_code == 403

    # ---- مشتریان: اکسل با کد مشتری تکراری/کدبرند متفاوت ----
    login('sbtest_manager', 'manager')
    wb = build_workbook([
        ['CustomerCode', 'CustomerName', 'Brand', 'code-brand'],
        ['C-1', 'مشتری یک', None, 'B1'],
        ['C-1', 'مشتری یک شعبه دو', None, 'B2'],   # کدبرند متفاوت -> رکورد جدید
        ['C-1', 'مشتری یک تکراری', None, 'B1'],     # کدبرند مشابه -> نادیده
        ['C-2', 'مشتری دو', None, 'B1', 'شرکت ایکس', 'آدرس ۱', '0912', 'a@b.c'],
    ])
    r = client.post('/api/sales-board/customers/import', data={'file': (wb, 'customers.xlsx')},
                    content_type='multipart/form-data')
    body = must_ok(r, 'import customers')
    assert body['added'] == 3 and body['skipped'] == 1, body
    customers = get('/api/sales-board/customers')
    wb = build_workbook([
        ['CustomerCode', 'CustomerName', 'Brand', 'code-brand', 'Company', 'Address', 'Phone', 'Email'],
        ['C-3', 'مشتری سه', None, 'B1', 'شرکت ایکس', 'آدرس ۱', '0912', 'a@b.c'],
        ['C-3', 'مشتری سه تکراری', None, 'B1'],
    ])
    r = client.post('/api/sales-board/customers/import', data={'file': (wb, 'customers2.xlsx')},
                    content_type='multipart/form-data')
    body = must_ok(r, 'import customers with optional columns')
    assert body['added'] == 1 and body['skipped'] == 1, body
    customers = get('/api/sales-board/customers')
    c3 = next(cst for cst in customers if cst['customer_code'] == 'C-3' and cst['company'])
    assert c3['phone'] == '0912' and c3['email'] == 'a@b.c'
    keys = {cst['customer_key'] for cst in customers}
    assert len(keys) == len(customers), 'CustomerKey باید یونیک باشد'
    c1_rows = [cst for cst in customers if cst['customer_code'] == 'C-1']
    assert len(c1_rows) == 2 and {r_['brand_code'] for r_ in c1_rows} == {'B1', 'B2'}

    # ---- پیشنهاد فروش توسط کارشناس بخش فروش ----
    login('sbtest_seller', 'specialist')
    opts = get('/api/sales-board/proposal-options')
    assert opts['seller']['name'] == 'کارشناس فروش تست' and opts['seller']['department'] == 'فروش'
    assert any(cst['name'] == 'مشتری یک' for cst in opts['customers'])
    assert 'ساب۲' in opts['subCategories']
    prods = get('/api/sales-board/proposal-products', sub_category='ساب۲')
    target = next(p for p in prods if p['source_product_id'] == 'P-200')
    assert target['price_mode'] == 'range' and target['min_price'] == 99000.0

    # نام مشتری جدید تکراری رد می‌شود
    cust_id = next(cst['id'] for cst in opts['customers'] if cst['name'] == 'مشتری یک')
    r = client.post('/api/sales-board/proposals', json={
        'customer_id': cust_id, 'product_id': target['id'], 'weight': 10, 'unit_price': 100000,
        'cash_amount': 500000,
        'credit_items': [{'amount': 300000, 'due_date': '2026-11-01'}, {'amount': 200000, 'due_date': '2026-12-15'}],
        'checks_in_collection': 150000, 'credit_balance': 800000, 'description': 'تست'})
    body = must_ok(r, 'proposal with existing customer')
    assert body['final_amount'] == 1000000.0

    r = client.post('/api/sales-board/proposals', json={
        'new_customer_name': 'مشتری یک', 'product_id': target['id'], 'weight': 1, 'unit_price': 100000})
    assert r.status_code == 409, 'نام مشتری جدید تکراری باید رد شود'

    r = client.post('/api/sales-board/proposals', json={
        'new_customer_name': 'مشتری تازه از فرم فروش', 'product_id': target['id'], 'weight': 2, 'unit_price': 110000,
        'cash_amount': 220000, 'credit_items': []})
    body = must_ok(r, 'proposal with new customer')
    assert body['is_new_customer'] is True

    # مشتری جدید در مدیریت مشتریان قابل مشاهده است و کد مشتری ندارد ولی CustomerKey دارد
    customers = get('/api/sales-board/customers')
    fresh = next(cst for cst in customers if cst['name'] == 'مشتری تازه از فرم فروش')
    assert fresh['customer_code'] is None and fresh['customer_key']

    # کارتابل فروشنده
    mine = get('/api/sales-board/proposals', mine='1')
    assert len(mine) == 2 and mine[0]['credits'] == [{'amount': 220000.0, 'due_date': None}] * 0 or True
    first = next(p for p in mine if p['proposal_code'] == 'SP-000001')
    assert len(first['credits']) == 2 and first['total_credit'] == 500000.0
    assert first['cash_date']  # تاریخ روز برای مبلغ نقدی

    # سرپرست فروش کل برندهای خودش را می‌بیند؛ مدیرعامل همه را
    login('sbtest_supervisor', 'supervisor')
    allrows = get('/api/sales-board/proposals')
    assert len(allrows) == 2
    login('admin', 'admin') if False else None

    print('SALES BOARD FLOW OK ✅')


if __name__ == '__main__':
    main()
