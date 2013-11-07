import webapp2
import cgi
import re

def rot13(c):
    if ord('a') <= ord(c) and ord(c) <= ord('z'):
	shift = ord(c) - ord('a')
	shift = (shift + 13) % 26
	return chr(ord('a') + shift)
    if ord('A') <= ord(c) and ord(c) <= ord('Z'):
	shift = ord(c) - ord('A')
	shift = (shift + 13) % 26
	return chr(ord('A') + shift)
    return c

def escape_html(s):
    return cgi.escape(s, quote = True)

class Rot13Handler(webapp2.RequestHandler):
    def form(self):
	return """
	<form method="post">
	    <label>
		<h2>Switch text to ROT13:<h2>
		<textarea name="text" rows="10" cols="80">%(text)s</textarea>
	    </label>
	    <br>
	    <input type="submit">
	</form>
	"""
    def write_form(self, text=""):
	self.response.out.write(self.form() % { "text": escape_html(text) })
    def get(self):
	self.write_form()
    def post(self):
	utext = self.request.get("text")
	self.write_form(''.join(map(rot13, utext)))

class Param:
    def __init__(self, value=""):
	self.value = value
	self.error = ""
    def isValid(self):
	return not self.error
    def validate(self):
	1/0 # XXX
class UserParam(Param):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    ERR_MSG = "That's not a valid username."
    def validate(self):
	if not UserParam.USER_RE.match(self.value):
	    self.error = UserParam.ERR_MSG
class PassParam(Param):
    PASS_RE = re.compile(r"^.{3,20}$")
    ERR_MSG = "That wasn't a valid password."
    def validate(self):
	if not PassParam.PASS_RE.match(self.value):
	    self.error = PassParam.ERR_MSG
class VerifyParam(Param):
    ERR_MSG = "Your passwords didn't match."
    def __init__(self, p, v):
	Param.__init__(self, p)
	self.p = p
	self.v = v
    def validate(self):
	if not (self.p == self.v):
	    self.error = VerifyParam.ERR_MSG
class EmailParam(Param):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    ERR_MSG = "That's not a valid email."
    def validate(self):
	if self.value and not EmailParam.EMAIL_RE.match(self.value):
	    self.error = EmailParam.ERR_MSG

class SignupHandler(webapp2.RequestHandler):
    def form(self):
	return """
	<form method="post">
	    <h2>Signup:<h2>
	    <label>
	        Username:
		<input type="text" name="username" value="%(username)s">
		<span style="color: red">%(usernameErr)s</span>
	    </label>
	    <br>
	    <label>
	        Password:
		<input type="password" name="password">
		<span style="color: red">%(passwordErr)s</span>
	    </label>
	    <br>
	    <label>
	        Verify Password:
		<input type="password" name="verify">
		<span style="color: red">%(verifyErr)s</span>
	    </label>
	    <br>
	    <label>
		Email:
		<input type="text" name="email" value="%(email)s">
		<span style="color: red">%(emailErr)s</span>
	    </label>
	    <br>
	    <input type="submit">
	</form>
	"""
    def write_form(self, u, p, v, e):
	self.response.out.write(self.form() % {
	    "username": escape_html(u.value),
	    "usernameErr": u.error,
	    "passwordErr": p.error,
	    "verifyErr": v.error,
	    "email": escape_html(e.value),
	    "emailErr": e.error
	    })
    def get(self):
	empty = Param()
	self.write_form(empty, empty, empty, empty)
    def post(self):
	u = UserParam(self.request.get("username"))
	p = PassParam(self.request.get("password"))
	v = VerifyParam(p.value, self.request.get("verify"))
	e = EmailParam(self.request.get("email"))

	for param in (u, p, v, e): param.validate()

	if u.isValid() and p.isValid() and v.isValid() and e.isValid():
	    self.redirect("/greetings?username=%s" % u.value)
	else:
	    self.write_form(u, p, v, e)

class GreetingsHandler(webapp2.RequestHandler):
    def get(self):
	username = self.request.get("username")
	self.response.out.write("Welcome, %s!" % escape_html(username))

application = webapp2.WSGIApplication([
    ('/rot13', Rot13Handler),
    ('/signup', SignupHandler),
    ('/greetings', GreetingsHandler),
], debug=True)
