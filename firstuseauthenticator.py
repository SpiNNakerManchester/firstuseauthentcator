"""
JupyterHub Authenticator that lets users set password on first use.

When users first log in, the password they use becomes their
password for that account. It is hashed with bcrypt & stored
locally in a dbm file, and checked next time they log in.
"""
import dbm
import os
import uuid
import smtplib

from jinja2 import ChoiceLoader, FileSystemLoader
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.orm import User
from jupyterhub.utils import url_path_join

from tornado import gen, web
from traitlets.traitlets import Unicode, Bool

import bcrypt


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
_loaded = False

def _register_template_path(handler):
    global _loaded
    if _loaded:
        return

    handler.log.debug('Adding %s to template path', TEMPLATE_DIR)
    loader = FileSystemLoader([TEMPLATE_DIR])

    env = handler.settings['jinja2_env']
    previous_loader = env.loader
    env.loader = ChoiceLoader([previous_loader, loader])

    _loaded = True


class ResetPasswordHandler(BaseHandler):
    """Render the reset password page."""

    @web.authenticated
    async def get(self):
        _register_template_path(self)
        html = self.render_template('reset.html')
        self.finish(html)

    @web.authenticated
    async def post(self):
        user = self.get_current_user()
        new_password = self.get_body_argument('password', strip=False)
        self.authenticator.reset_password(user.name, new_password)

        html = self.render_template(
            'reset.html',
            result=True,
            result_message='your password has been changed successfully',
        )
        self.finish(html)
        

class RegisterHandler(BaseHandler):

    def get(self):
        _register_template_path(self)
        html = self.render_template('register.html')
        self.finish(html)
    
    def post(self):
        _register_template_path(self)
        error = None
        try:
            username = self.get_body_argument('username')
            password = self.get_body_argument('password')
            email = self.get_body_argument('email')
            code = uuid.uuid4().hex
            with dbm.open(self.authenticator.first_use_auth.dbm_path, 'c', 0o600) as db:
                if username in db:
                    with dbm.open(self.authenticator.first_use_auth.registration_path, 'c', 0o600) as reg_db:
                        if username not in reg_db:
                            raise KeyError("Username already in use!")
                db[username] = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with dbm.open(self.authenticator.first_use_auth.registration_path, 'c', 0o600) as db:
                db[username] = code
            with dbm.open(self.authenticator.first_use_auth.email_path, 'c', 0o600) as db:
                db[username] = email
            sender = smtplib.SMTP(self.authenticator.first_use_auth.smtp_server)
            sender.sendmail(self.authenticator.first_use_auth.from_address, email, 
                            "Subject: Registration to JupyterHub\n\n"
                            "Please confirm your email address by clicking on the following link:\n"
                            "{}?code={}&username={}".format(
                                self.authenticator.first_use_auth.register_confirm_address, 
                                code, username)
            )
        except Exception as e:
            error = "{}".format(e)
        if error is not None:
            html = self.render_template('register.html', error=True, error_message="Registration Failed: {}".format(error))
        else:
            html = self.render_template('register.html', result=True, result_message="Registration successful.  Please check your email to complete the process")
        
        self.finish(html)


class RegisterConfirmHandler(BaseHandler):

    def get(self):
        _register_template_path(self)
        username = self.get_query_argument("username")
        code = self.get_query_argument('code')
        with dbm.open(self.authenticator.first_use_auth.registration_path, 'w') as db:
            if db[username].decode() != code:
                raise KeyError("Code does not match {}".format(db[username]))
            del db[username]
        html = self.render_template('register_confirm.html')
        self.finish(html)
        

class FirstUseAuthenticator(Authenticator):
    """
    JupyterHub authenticator that lets users set password on first use.
    """
    dbm_path = Unicode(
        'passwords.dbm',
        config=True,
        help="""
        Path to store the db file with username / pwd hash in
        """
    )
    
    registration_path = Unicode(
        'registration.dbm',
        config=True,
        help="""
        Path to store the db file with username / registration code hash in
        """
    )
    
    email_path = Unicode(
        'email.dbm',
        config=True,
        help="""
        Path to store the db file with username / email hash in
        """
    )
    
    smtp_server = Unicode(
        'mailrouter.man.ac.uk',
        config=True,
        help="""
        Email server
        """
    )
    
    from_address = Unicode(
        'no-reply@spinn-20.cs.man.ac.uk',
        config=True,
        help="""
        Email from address
        """
    )
    
    register_confirm_address = Unicode(
        'https://spinn-20.cs.man.ac.uk/hub/confirm',
        config=True,
        help="""
        URL to confirm email address
        """
    )

    create_users = Bool(
        False,
        config=True,
        help="""
        Create users if they do not exist already.

        When set to false, users would have to be explicitly created before
        they can log in. Users can be created via the admin panel or by setting
        whitelist / admin list.
        """
    )

    def _user_exists(self, username):
        """
        Return true if given user already exists.

        Note: Depends on internal details of JupyterHub that might change
        across versions. Tested with v0.9
        """
        with dbm.open(self.dbm_path, 'c', 0o600) as db:
            return username in db

    def validate_username(self, name):
        invalid_chars = [',', ' ']
        if any((char in name) for char in invalid_chars):
            return False
        return super().validate_username(name)

    @gen.coroutine
    def authenticate(self, handler, data):
        username = data['username']

        if not self.create_users:
            if not self._user_exists(username):
                return None
                
        with dbm.open(self.registration_path, 'c', 0o600) as db:
            if username in db:
                self.log.info("User {} has not verified their email address".format(username))

        password = data['password']
        with dbm.open(self.dbm_path, 'c', 0o600) as db:
            stored_pw = db.get(username.encode(), None)
            if stored_pw is not None:
                if bcrypt.hashpw(password.encode(), stored_pw) != stored_pw:
                    return None
            else:
                db[username] = bcrypt.hashpw(password.encode(),
                                             bcrypt.gensalt())
        return username

    def delete_user(self, user):
        """
        When user is deleted, remove their entry from password db.

        This lets passwords be reset by deleting users.
        """
        try:
            with dbm.open(self.dbm_path, 'c', 0o600) as db:
                del db[user.name]
        except KeyError as k:
            pass

    def reset_password(self, username, new_password):
        """
        This allow to change password of a logged user.
        """
        with dbm.open(self.dbm_path, 'c', 0o600) as db:
            db[username] = bcrypt.hashpw(new_password.encode(),
                                         bcrypt.gensalt())
        return username

    def get_handlers(self, app):
        h = [(r'/auth/change-password', ResetPasswordHandler),
             (r'/auth/register', RegisterHandler),
             (r'/confirm', RegisterConfirmHandler)]
        return super().get_handlers(app) + h
                     
