import webapp2
import os
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
	autoescape=True)

class Post(db.Model):
    subject = db.StringProperty(required = False)
    content = db.TextProperty(required = False)
    date = db.DateTimeProperty(auto_now_add = True)

class BaseTemplateHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
	self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)
    def render(self, template, **kw):
	self.write(self.render_str(template, **kw))

class ListHandler(BaseTemplateHandler):
    def get(self):
	self.render("list.html", posts=Post.gql("ORDER BY date DESC"))

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

class ShowHandler(BaseTemplateHandler):
    def get(self, post_id):
	p = Post.get_by_id(int(post_id))
	if not p:
	    self.redirect("/")
	self.render("show.html", post=p)

application = webapp2.WSGIApplication([
    ('/', ListHandler),
    ('/newpost', AddHandler),
    ('/show/(\d+)', ShowHandler),
], debug=True)
