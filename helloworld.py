import webapp2
import re
import os
import jinja2
import hashlib
import hmac
import random
import string
import json
from jinja2 import Markup
from urlparse import urlparse
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape=True)

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
    RENDERER_FIELD = 'my__renderer'
    def __init__(self, request, response):
	self.initialize(request, response)
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

class EasyCookieHandler(BaseTemplateHandler):
    DATE_IN_PAST='Thu, 01 Jan 1970 00:00:00 GMT'
    def addCookie(self, name, value):
	value = value.encode('ascii', 'ignore')
	self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %
		(name, value))
    def remCookie(self, name):
	self.response.headers.add_header('Set-Cookie', '%s=; Path=/; expires=%s' %
		(name, EasyCookieHandler.DATE_IN_PAST))
    def getCookie(self, name):
	return self.request.cookies.get(name)

class SafeCookieHandler(EasyCookieHandler):
    AUTH_SECRET='0yaeb00'
    def __sign_msg(self, msg):
	sig = hmac.new(SafeCookieHandler.AUTH_SECRET, msg, hashlib.sha256)
	return "%s|%s" % (msg, sig.hexdigest().encode('ascii', 'ignore'))
    def addCookie(self, name, value):
	EasyCookieHandler.addCookie(self, name, self.__sign_msg(value))
    def getCookie(self, name):
	signed_val = EasyCookieHandler.getCookie(self, name)
	if signed_val:
	    val = signed_val.split("|", 1)[0]
	    if signed_val == self.__sign_msg(val):
		return val

class AuthorizeHandler(SafeCookieHandler):
    AUTH_COOKIE='UID'
    def makeAuthorized(self, username):
	self.addCookie(AuthorizeHandler.AUTH_COOKIE, username)
    def authorize(self):
	return self.getCookie(AuthorizeHandler.AUTH_COOKIE)
    def unauthorize(self):
	self.remCookie(AuthorizeHandler.AUTH_COOKIE)

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

class GetBackHandler(AuthorizeHandler):
    PATH_COOKIE = 'LastPath'
    def getRequestRefererPath(self):
	ref = self.request.headers.get('Referer')
	if ref:
	    return urlparse(ref).path
	return '/'
    def popBackPath(self):
	path = self.getCookie(GetBackHandler.PATH_COOKIE) or '/'
	self.remCookie(GetBackHandler.PATH_COOKIE)
	return path
    def saveBackPath(self):
	if self.getCookie(GetBackHandler.PATH_COOKIE):
	    return # Avoid overriding
	path = self.getRequestRefererPath()
	if not path or path == '' or path == '/':
	    return
	self.addCookie(GetBackHandler.PATH_COOKIE, path)

class SignupHandler(GetBackHandler):
    def get(self):
	self.saveBackPath()
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
	    self.redirect(self.popBackPath())
	else:
	    self.render("signup.html", user_data=u)

class LoginHandler(GetBackHandler):
    def get(self):
	self.saveBackPath()
	self.render("login.html")
    def post(self):
	u = UserValidate()
	u.username = ExistingUserParam(self.request.get("username"))
	u.password = ExistingPassParam(self.request.get("password"), u.username.value)
	u.validate()
	if u.isValid():
	    self.makeAuthorized(u.username.value)
	    self.redirect(self.popBackPath())
	else:
	    self.render("login.html", error="Invalid login")

class LogoutHandler(GetBackHandler):
    def get(self):
	path = self.getRequestRefererPath()
	self.unauthorize()
	self.redirect(path)

class Page(db.Model):
    created = db.DateTimeProperty(auto_now_add = True)
    nversions = db.IntegerProperty(default=0)
    def toJson(self):
	return {
		'id': str(self.key().id_or_name()),
		'created': str(self.created),
		'nversions': self.nversions,
		};
    def __repr__(self):
	return json.dumps(self.toJson())

class PageVersion(db.Model):
    """
    Each page-version is stored under the page it belongs to.
    """
    content = db.TextProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    def setSpecified(self):
	self.__specified__ = True
    def isSpecified(self):
	return hasattr(self, '__specified__') and self.__specified__
    def getPath(self, full=False):
	page_path = self.parent_key().id_or_name()
	if not full and not self.isSpecified():
	    return page_path
	return "%s?v=%s" % (page_path, self.key().id_or_name())
    def toJson(self):
	return {
		'path': self.getPath(full=True),
		'version': int(self.key().id_or_name()),
		'created': str(self.created),
		'content': str(self.content),
		};
    def __repr__(self):
	return json.dumps(self.toJson())

class BaseWikiPage(GetBackHandler):
    def getDebugStr(self, page, user):
	if not page:
	    page = PageVersion(key_name='-1', parent=self.getKey('???'))
	d = "authorizedUser='%s'\n" % user
	d += "pageId='%s'\n" % page.key().id_or_name()
	d += "req headers = {\n"
	for h in sorted(self.request.headers):
	    d += "  '%s': '%s'\n" % (h, self.request.headers[h])
	d += "}\n"
	d += "page = " + repr(page)
	return d
    def __init__(self, request, response):
	GetBackHandler.__init__(self, request, response)
	self.authorizedUser = self.authorize()
    def getKey(self, pageId=None):
	if pageId:
	    return db.Key.from_path('WikiPage', 'Root', 'Page', pageId)
	return db.Key.from_path('WikiPage', 'Root')
    def getPageVersions(self, pageId):
	q = PageVersion.all()
	q.ancestor(self.getKey(pageId))
	q.order('-__key__')
	return list(q)
    def getPageLatestVersion(self, pageId):
	res = self.getPageVersions(pageId)
	if res:
	    return res[0]
    def getPageSpecificVersion(self, pageId, version):
	pageVersion = PageVersion.get_by_key_name(str(version), self.getKey(pageId))
	if pageVersion:
	    return pageVersion
    def getPageVersion(self, pageId, version=None):
	pageVersion = None
	if version:
	    pageVersion = self.getPageSpecificVersion(pageId, version)
            # Remember that this specific version was requested
	    pageVersion.setSpecified()
	if not pageVersion:
	    pageVersion = self.getPageLatestVersion(pageId)
	if pageVersion:
            # Should be the same as pageId
	    pageVersion.path = pageVersion.parent_key().id_or_name()
	return pageVersion
    def addPageVersion(self, pageId, content):
        # Page and PageVersion are not in the same entity group, thus cannot
	# be updated atomically. Hence:
        # (1) allocate version
        # (2) add the version itself
	page = Page.get_or_insert(key_name=pageId, parent=self.getKey())
	page.nversions += 1
	version = page.nversions
	page.put()
	pageVersion = PageVersion(key_name=str(version), content=content, parent=page)
	pageVersion.put()
    def render(self, template, page, user, *a, **kw):
	GetBackHandler.render(self, template, page=page, user=user, *a, **kw)

class EditWikiPage(BaseWikiPage):
    def get(self, pageId):
	self.popBackPath()
	username = self.authorize()
	if not username:
	    self.redirect(pageId)
	    return
	version = self.request.get("v")
	pageVersion = self.getPageVersion(pageId, version)
	self.render("edit.html", pageVersion, username, edit=True)
    def post(self, pageId):
	self.popBackPath()
	username = self.authorize()
	if not username:
	    self.redirect(pageId)
	    return
	newPageContent = Markup(self.request.get("content")).unescape()
	self.addPageVersion(pageId, newPageContent)
	self.redirect(pageId)

class ShowWikiPage(BaseWikiPage):
    def get(self, pageId):
	self.popBackPath()
	username = self.authorize()
	version = self.request.get("v")
	pageVersion = self.getPageVersion(pageId, version)
	if username and not pageVersion:
	    self.redirect('/_edit' + pageId)
	    return
	self.render("show.html", pageVersion, username)

class HistoryWikiPage(BaseWikiPage):
    def get(self, pageId):
	self.popBackPath()
	username = self.authorize()
	page_versions = self.getPageVersions(pageId)
	self.render("history.html", None, username, versions=page_versions)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
application = webapp2.WSGIApplication([
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/_edit' + PAGE_RE, EditWikiPage),
    ('/_history' + PAGE_RE, HistoryWikiPage),
    (PAGE_RE, ShowWikiPage),
    ], debug=True)
