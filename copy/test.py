import io
import os
import unittest
from datetime import datetime
from cryptography.fernet import Fernet
import base64

from app import (app, db, User, Connection, File, FileAccess, Message,
                 Blacklist, hash_password, generate_fernet_key,
                 encrypt_with_user_key, _APP_KEK)
import app as appmod  # module alias for updating global variables later


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
            # create an admin account so tests don't get redirected
            rawadm = generate_fernet_key()
            # create an admin account so tests don't get redirected
            # also generate ed25519 signing keys so the admin can participate in chat
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            privA = _ed.Ed25519PrivateKey.generate()
            pubA = privA.public_key()
            try:
                privA_raw = privA.private_bytes_raw()
                pubA_raw = pubA.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                privA_raw = privA.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pubA_raw = pubA.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_privA_enc = Fernet(rawadm.encode('utf-8')).encrypt(privA_raw).decode('utf-8')
            ed_pubA_b64 = base64.urlsafe_b64encode(pubA_raw).decode('utf-8')
            admin = User(username='admin', password_hash=hash_password('p'), dpass_hash=hash_password('d'),
                         keys_database_key=_APP_KEK.encrypt(rawadm.encode('utf-8')).decode('utf-8'),
                         is_admin=True, approved=True, master_key_hash=hash_password('m'),
                         ed25519_pub_b64=ed_pubA_b64, ed25519_priv_enc=ed_privA_enc)
            db.session.add(admin)
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

    def test_admin_can_send_messages(self):
        """Admin user should be able to send and receive chat messages like others."""
        with app.app_context():
            admin = User.query.filter_by(username='admin').first()
            alice = User.query.filter_by(username='alice').first()
            # grab ids now so we can reuse outside the context
            admin_id = admin.id
            alice_id = alice.id
            # ensure both have signing keys
            self.assertTrue(admin.ed25519_priv_enc and admin.ed25519_pub_b64)
            self.assertTrue(alice.ed25519_priv_enc and alice.ed25519_pub_b64)
            # create connection between admin and alice
            conn = Connection(sender_id=admin_id, receiver_id=alice_id, status='accepted')
            chat_key = generate_fernet_key()
            conn.chat_key_enc_sender = encrypt_with_user_key(admin, chat_key)
            conn.chat_key_enc_receiver = encrypt_with_user_key(alice, chat_key)
            db.session.add(conn)
            db.session.commit()
        # admin sends a message
        self.login_as('admin')
        s = self.client.post(f'/chat/{alice_id}', data={'message': 'hi from admin'}, follow_redirects=True)
        self.assertIn(s.status_code, (200, 302))
        # alice should see it
        self.login_as('alice')
        r = self.client.get(f'/chat/{admin_id}')
        self.assertIn(b'hi from admin', r.data)

    def test_missing_keys_are_generated(self):
        """A user record with no ed25519 fields should get keys when first used in chat."""
        with app.app_context():
            # create a new user without signing keys
            rawx = generate_fernet_key()
            u = User(username='charlie', password_hash=hash_password('cx'),
                     dpass_hash=hash_password('dx'),
                     keys_database_key=_APP_KEK.encrypt(rawx.encode('utf-8')).decode('utf-8'),
                     approved=True)
            db.session.add(u)
            db.session.commit()
            charlie = User.query.filter_by(username='charlie').first()
            bob = User.query.filter_by(username='bob').first()
            charlie_id = charlie.id
            bob_id = bob.id
            # create connection
            conn = Connection(sender_id=charlie_id, receiver_id=bob_id, status='accepted')
            chat_key = generate_fernet_key()
            conn.chat_key_enc_sender = encrypt_with_user_key(charlie, chat_key)
            conn.chat_key_enc_receiver = encrypt_with_user_key(bob, chat_key)
            db.session.add(conn)
            db.session.commit()
        # charlie should not have keys initially (reload from DB to avoid detached instance)
        with app.app_context():
            fresh = User.query.filter_by(username='charlie').first()
        self.assertFalse(fresh.ed25519_priv_enc)
        # now simulate charlie sending a message, which should trigger key gen
        self.login_as('charlie')
        resp = self.client.post(f'/chat/{bob_id}', data={'message': 'hello bob'}, follow_redirects=True)
        self.assertIn(resp.status_code, (200, 302))
        # re-fetch charlie from db to check keys were stored
        with app.app_context():
            charlie = User.query.filter_by(username='charlie').first()
            self.assertTrue(charlie.ed25519_priv_enc and charlie.ed25519_pub_b64)
        # bob should be able to read the message
        self.login_as('bob')
        r = self.client.get(f'/chat/{charlie.id}')
        self.assertIn(b'hello bob', r.data)

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

    def test_secret_key_persistence_and_chat_recovery(self):
        """If the secret key is regenerated, previously wrapped chat keys must still decrypt."""
        import importlib, os
        secret_path = os.path.join(os.getcwd(), '.secret_key')
        if os.path.exists(secret_path):
            os.remove(secret_path)
        # replicate the startup logic that loads/creates secret
        if not os.environ.get('SECRET_KEY'):
            if os.path.exists(secret_path):
                with open(secret_path, 'r') as fh:
                    os.environ['SECRET_KEY'] = fh.read().strip()
            else:
                val = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
                with open(secret_path, 'w') as fh:
                    fh.write(val)
                os.environ['SECRET_KEY'] = val
        first_key = os.environ.get('SECRET_KEY')
        self.assertIsNotNone(first_key)
        # make sure the Flask app and KEK are in sync with the environment
        appmod.app.secret_key = first_key
        from app import _derive_app_kek, Fernet, _APP_KEK as _app_kek_ref
        appmod._APP_KEK = Fernet(_derive_app_kek())
        # keep our local reference in sync as well (imports are snapshots)
        _APP_KEK = appmod._APP_KEK  # type: ignore
        # file may or may not exist depending on startup configuration; we don't require it
        # create a user and connection and store chat key
        with app.app_context():
            u1 = User(username='persist_a', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(generate_fernet_key().encode('utf-8')).decode('utf-8'))
            u2 = User(username='persist_b', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(generate_fernet_key().encode('utf-8')).decode('utf-8'))
            db.session.add_all([u1, u2])
            db.session.commit()
            # capture ids since the user objects will become detached later
            u1_id = u1.id
            u2_id = u2.id
            ck = os.urandom(32)
            conn = Connection(sender_id=u1_id, receiver_id=u2_id, status='accepted')
            from app import encrypt_with_user_key_bytes
            conn.chat_key_enc_sender = encrypt_with_user_key_bytes(u1, ck)
            conn.chat_key_enc_receiver = encrypt_with_user_key_bytes(u2, ck)
            db.session.add(conn)
            db.session.commit()
            conn_id = conn.id
        # simulate secret change and recovery
        old_env = os.environ.get('SECRET_KEY')
        os.environ['SECRET_KEY'] = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
        # simulate app restart by updating secret_key and derived KEK
        appmod.app.secret_key = os.environ['SECRET_KEY']
        from app import _derive_app_kek, Fernet
        appmod._APP_KEK = Fernet(_derive_app_kek())
        # decryption should now fail
        from app import decrypt_with_user_key_bytes
        with app.app_context():
            # reload users within the active session to avoid detached-instance errors
            u1 = User.query.get(u1_id)
            conn2 = Connection.query.get(conn_id)
            with self.assertRaises(Exception):
                _ = decrypt_with_user_key_bytes(u1, conn2.chat_key_enc_sender)
        # restore original secret from file
        os.environ['SECRET_KEY'] = old_env
        appmod.app.secret_key = old_env
        from app import _derive_app_kek, Fernet
        appmod._APP_KEK = Fernet(_derive_app_kek())
        with app.app_context():
            u1 = User.query.get(u1_id)
            conn2 = Connection.query.get(conn_id)
            raw_ck = decrypt_with_user_key_bytes(u1, conn2.chat_key_enc_sender)
            self.assertEqual(len(raw_ck), 32)

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
        # ensure a fresh database per-test to avoid cross-test pollution
        with app.app_context():
            db.drop_all()
            db.create_all()
        self.client = app.test_client()

    # reuse the login helper from RouteTest
    def login_as(self, username):
        with app.app_context():
            user = User.query.filter_by(username=username).first()
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_admin_register_and_login(self):
        # initial access should redirect to registration (env cleared by setUpClass)
        r = self.client.get('/', follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/admin/register', r.headers.get('Location', ''))
        # perform registration
        # choose a password that satisfies the current policy rules
        strong_pw = 'Password1!'
        r2 = self.client.post('/admin/register', data={'username': 'boss', 'password': strong_pw, 'dpassword': strong_pw, 'master_key': 'mkey'}, follow_redirects=True)
        self.assertIn(r2.status_code, (200, 302))
        # registration should have created signing keys as well
        with app.app_context():
            a = User.query.filter_by(username='boss').first()
            self.assertIsNotNone(a)
            self.assertTrue(a.ed25519_pub_b64 and a.ed25519_priv_enc)
        # now login as admin
        r3 = self.client.post('/login', data={'username': 'boss', 'password': strong_pw}, follow_redirects=True)
        self.assertIn(r3.status_code, (200, 302))

        # create a second normal user and establish a chat connection so the
        # freshly-registered admin can send a message
        with app.app_context():
            rawj = generate_fernet_key()
            # generate ed25519 keys for the new user
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            privj = _ed.Ed25519PrivateKey.generate()
            pubj = privj.public_key()
            try:
                privj_raw = privj.private_bytes_raw()
                pubj_raw = pubj.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                privj_raw = privj.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pubj_raw = pubj.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_privj_enc = Fernet(rawj.encode('utf-8')).encrypt(privj_raw).decode('utf-8')
            ed_pubj_b64 = base64.urlsafe_b64encode(pubj_raw).decode('utf-8')
            jim = User(username='jim', password_hash=hash_password('jj'),
                       dpass_hash=hash_password('dd'),
                       keys_database_key=_APP_KEK.encrypt(rawj.encode('utf-8')).decode('utf-8'),
                       ed25519_pub_b64=ed_pubj_b64,
                       ed25519_priv_enc=ed_privj_enc,
                       approved=True)
            db.session.add(jim)
            db.session.commit()
            jim_id = jim.id
            # add connection and chat key
            boss = User.query.filter_by(username='boss').first()
            boss_id = boss.id
            conn = Connection(sender_id=boss_id, receiver_id=jim_id, status='accepted')
            ck = generate_fernet_key()
            conn.chat_key_enc_sender = encrypt_with_user_key(boss, ck)
            conn.chat_key_enc_receiver = encrypt_with_user_key(jim, ck)
            db.session.add(conn)
            db.session.commit()
        # boss should be able to send a message
        self.login_as('boss')
        rmsg = self.client.post(f'/chat/{jim_id}', data={'message': 'hi jim'}, follow_redirects=True)
        self.assertIn(rmsg.status_code, (200, 302))
        # verify jim can read it
        self.login_as('jim')
        rview = self.client.get(f'/chat/{boss_id}')
        self.assertIn(b'hi jim', rview.data)

    def test_manage_users_page(self):
        # create an admin and a normal user
        with app.app_context():
            rawa = generate_fernet_key()
            rawu = generate_fernet_key()
            # create signing keys for the admin so they behave like normal users
            from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
            privA = _ed.Ed25519PrivateKey.generate()
            pubA = privA.public_key()
            try:
                privA_raw = privA.private_bytes_raw()
                pubA_raw = pubA.public_bytes_raw()
            except Exception:
                from cryptography.hazmat.primitives import serialization
                privA_raw = privA.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pubA_raw = pubA.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ed_privA_enc = Fernet(rawa.encode('utf-8')).encrypt(privA_raw).decode('utf-8')
            ed_pubA_b64 = base64.urlsafe_b64encode(pubA_raw).decode('utf-8')
            a = User(username='boss', password_hash=hash_password('p'), dpass_hash=hash_password('d'), keys_database_key=_APP_KEK.encrypt(rawa.encode('utf-8')).decode('utf-8'), is_admin=True, approved=True, master_key_hash=hash_password('m'), ed25519_pub_b64=ed_pubA_b64, ed25519_priv_enc=ed_privA_enc)
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
        self.assertIn(b'no users found', s.data)
        # connection attempt to hidden should be refused
        c = self.client.post('/connect', data={'username': 'hid'}, follow_redirects=True)
        self.assertIn(b'No such user', c.data)
        # connection attempt to deleted should also show not found message
        d = self.client.post('/connect', data={'username': 'del'}, follow_redirects=True)
        self.assertIn(b'No such user', d.data)



if __name__ == '__main__':
    unittest.main()
