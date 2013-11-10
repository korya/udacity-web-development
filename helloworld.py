import webapp2
import re
import os
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape=True)

class BaseTemplateHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
	self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)
    def render(self, template, **kw):
	self.write(self.render_str(template, **kw))

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

class SignupHandler(BaseTemplateHandler):
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
	    self.redirect("/greetings")
	else:
	    self.render("signup.html", user_data=u)

application = webapp2.WSGIApplication([
    ('/signup', SignupHandler),
    ], debug=True)
