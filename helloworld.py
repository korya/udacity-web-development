import webapp2
import re
import os
import jinja2
import hashlib
import hmac
import random
import string
import json
import time
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape=True)

class MyMemcache:
    @staticmethod
    def __key(key):
	return 'MyMemcache::' + key
    @staticmethod
    def get(key):
	res = memcache.get(MyMemcache.__key(key))
	if res is None:
	    return None, 0.0
	value, setTime = res
	return value, time.time() - setTime
    @staticmethod
    def set(key, value):
	setTime = time.time()
	memcache.set(MyMemcache.__key(key), (value, setTime))
    @staticmethod
    def invalidate(key):
	memcache.delete(MyMemcache.__key(key))
    @staticmethod
    def flush():
	memcache.flush_all()

class SaltyHMAC:
    @staticmethod
    def __make_salt(length=5):
	return ''.join(random.choice(string.letters) for x in xrange(length))
    @staticmethod
    def new(name, pw, salt=None):
	if not salt:
	    salt=SaltyHMAC.__make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)
    @staticmethod
    def get_salt(hpass):
	return hpass.split(",", 1)[1]

class User(db.Model):
    username = db.StringProperty(required = True)
    passwd_salt = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    registered_date = db.DateTimeProperty(auto_now_add = True)

class Renderer():
    def render(self, template, **params):
	1/0 # XXX implement me
class JinjaRenderer(Renderer):
    def render(self, template, **params):
	t = jinja_env.get_template(template)
	return (None, t.render(params))
class JsonRenderer(Renderer):
    def render(self, template, **params):
	content = ''
	for p in params:
	    content += json.dumps(json.loads(str(params[p])))
	return ('application/json; charset=UTF-8', content)

class BaseTemplateHandler(webapp2.RequestHandler):
    MEMCACHE_LAST_10 = 'ListHandler::last-10-posts'
    RENDERER_FIELD = 'my__renderer'
    def __init__(self, request, response):
	webapp2.RequestHandler.__init__(self, request, response)
	self.renderers = {}
	self.renderers['json'] = JsonRenderer()
	self.renderers['default'] = JinjaRenderer()
    def write(self, *a, **kw):
	self.response.out.write(*a, **kw)
    def render(self, template, **params):
	renderer = self.renderer_get()
	(content_type, content) = renderer.render(template, **params)
	if content_type:
	    self.response.headers['Content-Type'] = content_type;
	self.write(content)
    def renderer_set(self, name):
	if hasattr(self.request, BaseTemplateHandler.RENDERER_FIELD):
	    1/0 # XXX PANIC!!!
	setattr(self.request, BaseTemplateHandler.RENDERER_FIELD, name)
    def renderer_get(self):
	if hasattr(self.request, BaseTemplateHandler.RENDERER_FIELD):
	    if getattr(self.request, BaseTemplateHandler.RENDERER_FIELD) in self.renderers:
		return self.renderers[getattr(self.request, BaseTemplateHandler.RENDERER_FIELD)]
	return self.renderers['default']

class AuthorizeHandler(BaseTemplateHandler):
    AUTH_COOKIE='UID'
    AUTH_SECRET='0yaeb00'
    DATE_IN_PAST='Thu, 01 Jan 1970 00:00:00 GMT'
    def make_token(self, username):
	sig = hmac.new(AuthorizeHandler.AUTH_SECRET, username, hashlib.sha256)
	return "%s|%s" % (username, sig.hexdigest())
    def extract_username(self, token):
	username = token.split("|", 1)[0]
	if token == self.make_token(username):
	    return username
    def makeAuthorized(self, username):
	token = str(self.make_token(username))
	self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %
		(AuthorizeHandler.AUTH_COOKIE, token))
    def authorize(self):
	token = self.request.cookies.get(AuthorizeHandler.AUTH_COOKIE)
	if token:
	    return self.extract_username(token)
    def unauthorize(self):
	self.response.headers.add_header('Set-Cookie', '%s=; Path=/; expires=%s' %
		(AuthorizeHandler.AUTH_COOKIE, AuthorizeHandler.DATE_IN_PAST))

class Param:
    def __init__(self, value="", err_msg="", rexp=None):
	self.error = ""
	self.value = value
	self.err_msg = err_msg
	if rexp:
	    self.rexp = re.compile(rexp)
    def isValid(self):
	return not self.error
    def validate(self):
	if not self.rexp.match(self.value):
	    self.error = self.err_msg
class UserParam(Param):
    def __init__(self, value=""):
	Param.__init__(self, value=value,
		rexp=r"^[a-zA-Z0-9_-]{3,20}$",
		err_msg="That's not a valid username.")
    def is_exists(self):
	cursor = User.gql("WHERE username = '%s'" % self.value)
	return cursor.count() > 0
    def validate(self):
	Param.validate(self)
	if self.isValid():
	    if self.is_exists():
		self.error = "User exists"
class PassParam(Param):
    def __init__(self, value=""):
	Param.__init__(self, value=value,
		rexp=r"^.{3,20}$",
		err_msg="That wasn't a valid password.")
class VerifyParam(Param):
    ERR_MSG = "Your passwords didn't match."
    def __init__(self, p="", v=""):
	Param.__init__(self, value=p)
	self.p = p
	self.v = v
    def validate(self):
	if not (self.p == self.v):
	    self.error = VerifyParam.ERR_MSG
class ExistingUserParam(UserParam):
    def __init__(self, value=""):
	UserParam.__init__(self, value=value)
    def validate(self):
	Param.validate(self)
	if self.isValid():
	    if not self.is_exists():
		self.error = "User does not exists"
class ExistingPassParam(PassParam):
    def __init__(self, value="", username=""):
	PassParam.__init__(self, value=value)
	self.username = username
    def __get_pass_info(self):
	cursor = User.gql("WHERE username = '%s'" % self.username)
	# XXX:
	for u in cursor.fetch(limit=1):
	    salt = SaltyHMAC.get_salt(u.passwd_salt)
	    return (salt, u.passwd_salt)
	return ("", "")
    def validate(self):
	Param.validate(self)
	if self.isValid():
	    (salt, passwd_salt) = self.__get_pass_info()
	    if passwd_salt != SaltyHMAC.new(self.username, self.value, salt=salt):
		self.error = "Password incorrect"
class EmailParam(Param):
    def __init__(self, value=""):
	Param.__init__(self, value=value,
		rexp=r"^[\S]+@[\S]+\.[\S]+$",
		err_msg="That's not a valid email.")
    def validate(self):
	if self.value:
	    Param.validate(self)
class UserValidate():
    def __init__(self):
	self.username = UserParam()
	self.password = PassParam()
	self.verify = VerifyParam()
	self.email = EmailParam()
    def __all_params(self):
	return [getattr(self, a) for a in dir(self)
		if not a.startswith('__') and
		isinstance(getattr(self, a), Param)]
    def validate(self):
	all([p.validate() for p in self.__all_params()])
    def isValid(self):
	return all([p.isValid() for p in self.__all_params()])
    def toUser(self):
	if self.isValid():
	    hpass = SaltyHMAC.new(self.username.value, self.password.value)
	    return User(
		    username=self.username.value,
		    passwd_salt=hpass,
		    email=self.email.value)

class SignupHandler(AuthorizeHandler):
    def get(self):
	self.render("signup.html", user_data=UserValidate())
    def post(self):
	u = UserValidate()
	u.username = UserParam(self.request.get("username"))
	u.password = PassParam(self.request.get("password"))
	u.verify = VerifyParam(u.password.value, self.request.get("verify"))
	u.email = EmailParam(self.request.get("email"))
	u.validate()
	if u.isValid():
	    user = u.toUser()
	    user.put()
	    self.makeAuthorized(user.username)
	    self.redirect("/welcome")
	else:
	    self.render("signup.html", user_data=u)

class WelcomeHandler(AuthorizeHandler):
    def get(self):
	username = self.authorize()
	if username:
	    self.render("welcome.html", username=username)
	else:
	    self.redirect("/signup");

class LoginHandler(AuthorizeHandler):
    def get(self):
	self.render("login.html")
    def post(self):
	u = UserValidate()
	u.username = ExistingUserParam(self.request.get("username"))
	u.password = ExistingPassParam(self.request.get("password"), u.username.value)
	u.validate()
	if u.isValid():
	    self.makeAuthorized(u.username.value)
	    self.redirect("/welcome")
	else:
	    self.render("login.html", error="Invalid login")

class LogoutHandler(AuthorizeHandler):
    def get(self):
	self.unauthorize()
	self.redirect("/signup");

class Post(db.Model):
    subject = db.StringProperty(required = False)
    content = db.TextProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    def toJson(self):
	return {
		'subject': str(self.subject),
		'content': str(self.subject),
		'created': str(self.created),
		'last_modified': str(self.last_modified),
		};
    def __repr__(self):
	return json.dumps(self.toJson())

class ListHandler(BaseTemplateHandler):
    def get(self):
	posts, age = MyMemcache.get(BaseTemplateHandler.MEMCACHE_LAST_10)
	if posts is None:
	    posts = list(Post.gql("ORDER BY created DESC LIMIT 10"))
	    MyMemcache.set(BaseTemplateHandler.MEMCACHE_LAST_10, posts)
	self.render("list.html", posts=posts, time=age)

class AddHandler(BaseTemplateHandler):
    def get(self):
	self.render("newpost.html")
    def post(self):
	subject = self.request.get("subject") 
	content = self.request.get("content")
	if not subject or not content:
	    self.render("newpost.html", subject=subject, content=content, error = "Fuck you!")
	else:
	    p = Post(subject=subject, content=content)
	    p.put()
	    self.redirect("/show/%s" % p.key().id())
	    MyMemcache.invalidate(BaseTemplateHandler.MEMCACHE_LAST_10)

class ShowHandler(BaseTemplateHandler):
    MEMCACHE_PERM_PREFIX = 'ShowHandler::permalink::'
    def get(self, post_id):
	post, age = MyMemcache.get(ShowHandler.MEMCACHE_PERM_PREFIX + post_id)
	if post is None:
	    post = Post.get_by_id(int(post_id))
	    if not post:
		self.redirect("/")
		return
	    MyMemcache.set(ShowHandler.MEMCACHE_PERM_PREFIX + post_id, post)
	self.render("show.html", post=post, time=age)

class JsonListHandler(ListHandler):
    def get(self):
	self.renderer_set('json')
	ListHandler.get(self)

class JsonShowHandler(ShowHandler):
    def get(self, post_id):
	self.renderer_set('json')
	ShowHandler.get(self, post_id)

class CacheFlushHandler(BaseTemplateHandler):
    def get(self):
	MyMemcache.flush()
	self.redirect("/")

application = webapp2.WSGIApplication([
    ('/welcome', WelcomeHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/', ListHandler),
    ('/.json', JsonListHandler),
    ('/newpost', AddHandler),
    ('/show/(\d+)', ShowHandler),
    ('/show/(\d+).json', JsonShowHandler),
    ('/flush', CacheFlushHandler),
    ], debug=True)
