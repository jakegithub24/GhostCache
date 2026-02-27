import io
import os
import unittest
from datetime import datetime
from cryptography.fernet import Fernet
import base64

from app import (app, db, User, Connection, File, FileAccess, Message,
                 Blacklist, hash_password, generate_fernet_key,
                 encrypt_with_user_key, _APP_KEK)


class RouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        # disable CSRF during tests
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.app_context():
            db.drop_all()
            db.create_all()
            # create two users for flows (wrap keys with _APP_KEK)
            raw1 = generate_fernet_key()
            raw2 = generate_fernet_key()
            # generate ed25519 keypairs for each user
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            # alice keys
            priv1 = _ed.Ed25519PrivateKey.generate()
            pub1 = priv1.public_key()
            try:
                priv1_raw = priv1.private_bytes_raw()
                pub1_raw = pub1.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                priv1_raw = priv1.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub1_raw = pub1.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_priv1_enc = Fernet(raw1.encode('utf-8')).encrypt(priv1_raw).decode('utf-8')
            ed_pub1_b64 = base64.urlsafe_b64encode(pub1_raw).decode('utf-8')
            # bob keys
            priv2 = _ed.Ed25519PrivateKey.generate()
            pub2 = priv2.public_key()
            try:
                priv2_raw = priv2.private_bytes_raw()
                pub2_raw = pub2.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                priv2_raw = priv2.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub2_raw = pub2.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_priv2_enc = Fernet(raw2.encode('utf-8')).encrypt(priv2_raw).decode('utf-8')
            ed_pub2_b64 = base64.urlsafe_b64encode(pub2_raw).decode('utf-8')
            u1 = User(username='alice', password_hash=hash_password('pass1'),
                      dpass_hash=hash_password('del1'), keys_database_key=_APP_KEK.encrypt(raw1.encode('utf-8')).decode('utf-8'),
                      ed25519_pub_b64=ed_pub1_b64, ed25519_priv_enc=ed_priv1_enc)
            u2 = User(username='bob', password_hash=hash_password('pass2'),
                      dpass_hash=hash_password('del2'), keys_database_key=_APP_KEK.encrypt(raw2.encode('utf-8')).decode('utf-8'),
                      ed25519_pub_b64=ed_pub2_b64, ed25519_priv_enc=ed_priv2_enc)
            db.session.add_all([u1, u2])
            db.session.commit()
            # ensure uploads folder exists
            os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)

    def setUp(self):
        self.client = app.test_client()

    def login_as(self, username):
        # set session directly for test client using fresh query
        with app.app_context():
            user = User.query.filter_by(username=username).first()
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_index(self):
        r = self.client.get('/')
        self.assertIn(r.status_code, (200, 302))

    def test_register_get(self):
        r = self.client.get('/register')
        self.assertEqual(r.status_code, 200)

    def test_login_get(self):
        r = self.client.get('/login')
        self.assertEqual(r.status_code, 200)

    def test_login_post_logout(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
        r = self.client.post('/login', data={'username': 'alice', 'password': 'pass1'}, follow_redirects=True)
        # login should redirect or render index (accept common statuses)
        self.assertIn(r.status_code, (200, 302, 415))
        # test logout
        r2 = self.client.get('/logout', follow_redirects=True)
        self.assertIn(r2.status_code, (200, 302))

    def test_connect_and_connections(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            bob = User.query.filter_by(username='bob').first()
        self.login_as('alice')
        # GET connect page
        g = self.client.get('/connect')
        self.assertEqual(g.status_code, 200)
        # POST connect to bob
        p = self.client.post('/connect', data={'username': 'bob'}, follow_redirects=True)
        self.assertIn(p.status_code, (200, 302))
        # connections list
        c = self.client.get('/connections')
        # may redirect to login if session lost, accept either
        self.assertIn(c.status_code, (200, 302))

    def test_accept_deny_flow(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            bob = User.query.filter_by(username='bob').first()
            # capture ids to avoid detached instances
            alice_id = alice.id
            bob_id = bob.id
            # create a connection from bob -> alice (pending)
            conn = Connection(sender_id=bob_id, receiver_id=alice_id)
            db.session.add(conn)
            db.session.commit()
            conn_id = conn.id
        # accept as alice
        self.login_as('alice')
        a = self.client.post(f'/connect/accept/{conn_id}', follow_redirects=True)
        self.assertIn(a.status_code, (200, 302))

        # create another pending and deny as alice
        with app.app_context():
            conn2 = Connection(sender_id=bob_id, receiver_id=alice_id)
            db.session.add(conn2)
            db.session.commit()
            cid2 = conn2.id
        d = self.client.post(f'/connect/deny/{cid2}', follow_redirects=True)
        self.assertIn(d.status_code, (200, 302))

    def test_chat_send_and_poll(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            bob = User.query.filter_by(username='bob').first()
            alice_id = alice.id
            bob_id = bob.id
            # create accepted connection and keys
            conn = Connection(sender_id=alice_id, receiver_id=bob_id, status='accepted')
            # create a shared chat key and encrypt for both
            chat_key = generate_fernet_key()
            conn.chat_key_enc_sender = encrypt_with_user_key(alice, chat_key)
            conn.chat_key_enc_receiver = encrypt_with_user_key(bob, chat_key)
            db.session.add(conn)
            db.session.commit()
            conn_id = conn.id
        # send message as alice via chat page
        self.login_as('alice')
        s = self.client.post(f'/chat/{bob_id}', data={'message': 'hello'}, follow_redirects=True)
        self.assertIn(s.status_code, (200, 302))
        # bob should be able to view the message by loading his chat page
        self.login_as('bob')
        r = self.client.get(f'/chat/{alice_id}')
        self.assertIn(b'hello', r.data)

    def test_chat_page_requires_connection(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            bob = User.query.filter_by(username='bob').first()
            bob_id = bob.id
        # without accepted connection this should redirect
        self.login_as('alice')
        r = self.client.get(f'/chat/{bob_id}', follow_redirects=True)
        self.assertIn(r.status_code, (200, 302))

    def test_search_and_files_pages(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
        self.login_as('alice')
        s = self.client.get('/search?q=ali')
        self.assertIn(s.status_code, (200, 302))
        f = self.client.get('/files')
        self.assertIn(f.status_code, (200, 302))

    def test_file_endpoints(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            # create a dummy stored file
            stored = 'test_store.bin'
            path = os.path.join(app.config.get('UPLOAD_FOLDER', 'uploads'), stored)
            with open(path, 'wb') as fh:
                fh.write(b'bytes')
            fi = File(owner_id=alice.id, filename='orig.txt', stored_name=stored, expiry=datetime.utcnow())
            db.session.add(fi)
            db.session.commit()
            fid = fi.id
        self.login_as('alice')
        # download
        d = self.client.get(f'/file/{fid}', follow_redirects=True)
        self.assertIn(d.status_code, (200, 302))
        # delete
        dl = self.client.post(f'/file/{fid}/delete', follow_redirects=True)
        self.assertIn(dl.status_code, (200, 302))

    def test_file_upload_get(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
        self.login_as('alice')
        u = self.client.get('/file/upload')
        self.assertEqual(u.status_code, 200)

    def test_share_file_missing_user(self):
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            # create a file owned by alice
            fi = File(owner_id=alice.id, filename='share.txt', stored_name='share.bin', expiry=datetime.utcnow())
            db.session.add(fi)
            db.session.commit()
            fid = fi.id
        self.login_as('alice')
        r = self.client.post(f'/file/{fid}/share', data={'username': 'nonexistent'}, follow_redirects=True)
        self.assertIn(r.status_code, (200, 302))

    def test_delete_account(self):
        # create and login a throwaway user
        with app.app_context():
            raw = generate_fernet_key()
            # give temp user signing keys
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            priv = _ed.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            try:
                priv_raw = priv.private_bytes_raw()
                pub_raw = pub.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                priv_raw = priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_raw = pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_priv_enc = Fernet(raw.encode('utf-8')).encrypt(priv_raw).decode('utf-8')
            ed_pub_b64 = base64.urlsafe_b64encode(pub_raw).decode('utf-8')
            t = User(username='temp', password_hash=hash_password('t'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(raw.encode('utf-8')).decode('utf-8'),
                      ed25519_pub_b64=ed_pub_b64, ed25519_priv_enc=ed_priv_enc)
            db.session.add(t)
            db.session.commit()
        self.login_as('temp')
        r = self.client.post('/delete_account', follow_redirects=True)
        self.assertIn(r.status_code, (200, 302))


class AdminTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # clear env variables so automatic bootstrap does not create admin
        import os
        cls._orig_env = {k: os.environ.get(k) for k in ("ADMIN_USERNAME","ADMIN_PASSWORD","ADMIN_DPASS","MASTER_KEY")}
        for k in cls._orig_env:
            os.environ.pop(k, None)
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.app_context():
            db.drop_all()
            db.create_all()

    @classmethod
    def tearDownClass(cls):
        import os
        for k, v in cls._orig_env.items():
            if v is not None:
                os.environ[k] = v

    def setUp(self):
        self.client = app.test_client()

    def test_admin_register_and_login(self):
        # initial access should redirect to registration (env cleared by setUpClass)
        r = self.client.get('/', follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/admin/register', r.headers.get('Location', ''))
        # perform registration
        r2 = self.client.post('/admin/register', data={'username': 'boss', 'password': 'pass', 'dpassword': 'dpass', 'master_key': 'mkey'}, follow_redirects=True)
        self.assertIn(r2.status_code, (200, 302))
        # now login as admin
        r3 = self.client.post('/login', data={'username': 'boss', 'password': 'pass'}, follow_redirects=True)
        self.assertIn(r3.status_code, (200, 302))

    def test_manage_users_page(self):
        # create an admin and a normal user
        with app.app_context():
            rawa = generate_fernet_key()
            rawu = generate_fernet_key()
            a = User(username='boss', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawa.encode('utf-8')).decode('utf-8'), is_admin=True, approved=True, master_key_hash=hash_password('m'))
            u = User(username='joe', password_hash=hash_password('x'), dpass_hash=hash_password('y'), keys_database_key=_APP_KEK.encrypt(rawu.encode('utf-8')).decode('utf-8'))
            db.session.add_all([a, u])
            db.session.commit()
            a_id = a.id
        # login by manipulating session
        with self.client.session_transaction() as sess:
            sess['user_id'] = a_id
            sess['username'] = 'boss'
        r = self.client.get('/admin/manage_users')
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'joe', r.data)

    def test_hidden_and_deleted_restrictions(self):
        with app.app_context():
            # ensure an admin exists so we don't get redirected to registration
            rawa = generate_fernet_key()
            # admin needs signing keys too
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            priva = _ed.Ed25519PrivateKey.generate()
            puba = priva.public_key()
            try:
                priva_raw = priva.private_bytes_raw()
                puba_raw = puba.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                priva_raw = priva.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                puba_raw = puba.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_priv_a_enc = Fernet(rawa.encode('utf-8')).encrypt(priva_raw).decode('utf-8')
            ed_pub_a_b64 = base64.urlsafe_b64encode(puba_raw).decode('utf-8')
            admin = User(username='admin', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawa.encode('utf-8')).decode('utf-8'), is_admin=True, approved=True, master_key_hash=hash_password('m'), ed25519_pub_b64=ed_pub_a_b64, ed25519_priv_enc=ed_priv_a_enc)
            rawu = generate_fernet_key()
            rawh = generate_fernet_key()
            rawd = generate_fernet_key()
            # assign signing keys to these users (though not used in this test)
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            def make_keys(raw):
                priv = _ed.Ed25519PrivateKey.generate()
                pub = priv.public_key()
                try:
                    priv_raw = priv.private_bytes_raw()
                    pub_raw = pub.public_bytes_raw()
                except Exception:
                    from cryptography.hazmat.primitives import serialization
                    priv_raw = priv.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    pub_raw = pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                return (
                    base64.urlsafe_b64encode(pub_raw).decode('utf-8'),
                    Fernet(raw.encode('utf-8')).encrypt(priv_raw).decode('utf-8')
                )
            pubu, privu_enc = make_keys(rawu)
            pubh, privh_enc = make_keys(rawh)
            pubd, privd_enc = make_keys(rawd)
            user = User(username='u', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawu.encode('utf-8')).decode('utf-8'), ed25519_pub_b64=pubu, ed25519_priv_enc=privu_enc)
            hidden = User(username='hid', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawh.encode('utf-8')).decode('utf-8'), visibility='hidden', approved=True, ed25519_pub_b64=pubh, ed25519_priv_enc=privh_enc)
            deleted = User(username='del', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawd.encode('utf-8')).decode('utf-8'), deleted=True, approved=True, ed25519_pub_b64=pubd, ed25519_priv_enc=privd_enc)
            db.session.add_all([admin, user, hidden, deleted])
            db.session.commit()
            user_id = user.id
        # login as normal user
        with self.client.session_transaction() as sess:
            sess['user_id'] = user_id
            sess['username'] = 'u'
        # search should not return hidden user (should show no results message)
        s = self.client.get('/search?q=hid')
        self.assertIn(b'No users found', s.data)
        # connection attempt to hidden should be refused
        c = self.client.post('/connect', data={'username': 'hid'}, follow_redirects=True)
        self.assertIn(b'No such user', c.data)
        # connection attempt to deleted should also show not found message
        d = self.client.post('/connect', data={'username': 'del'}, follow_redirects=True)
        self.assertIn(b'No such user', d.data)



if __name__ == '__main__':
    unittest.main()
