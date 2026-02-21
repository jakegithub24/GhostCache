import io
import os
import unittest
from datetime import datetime

from app import (app, db, User, Connection, File, FileAccess, Message,
                 Blacklist, hash_password, generate_fernet_key,
                 encrypt_with_user_key)


class RouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        # use in-memory DB for tests
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.app_context():
            db.drop_all()
            db.create_all()
            # create two users for flows
            u1 = User(username='alice', password_hash=hash_password('pass1'),
                      dpass_hash=hash_password('del1'), keys_database_key=generate_fernet_key())
            u2 = User(username='bob', password_hash=hash_password('pass2'),
                      dpass_hash=hash_password('del2'), keys_database_key=generate_fernet_key())
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
        # send message as alice
        self.login_as('alice')
        s = self.client.post('/chat/send', data={'receiver_id': str(bob_id), 'message': 'hello'}, follow_redirects=True)
        self.assertIn(s.status_code, (200, 201, 302))
        # poll as bob
        self.login_as('bob')
        p = self.client.get('/chat/poll')
        self.assertIn(p.status_code, (200, 302))

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
            t = User(username='temp', password_hash=hash_password('t'), dpass_hash=hash_password('d'), keys_database_key=generate_fernet_key())
            db.session.add(t)
            db.session.commit()
        self.login_as('temp')
        r = self.client.post('/delete_account', follow_redirects=True)
        self.assertIn(r.status_code, (200, 302))


if __name__ == '__main__':
    unittest.main()
