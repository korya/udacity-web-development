import webapp2
import cgi

form = """
<form method="post">
    What is your birthday?
    <br>
    <label>
	Day
	<input type="text" name="day" value="%(day)s">
    </label>
    <label>
	Month
	<input type="text" name="month" value="%(month)s">
    </label>
    <label>
	Year
	<input type="text" name="year" value="%(year)s">
    </label>
    <div style="color: red">%(error)s</div>
    <br><br>
    <input type="submit">
</form>
"""
months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
	'September', 'October', 'November', 'December']

def escape_html(s):
    return cgi.escape(s, quote = True)

def valid_day(day):
    if day and day.isdigit():
	day = int(day)
	if day < 32 and day > 0:
	    return day

def valid_month(month):
    if month:
	month = month.capitalize()
	if(month in months):
	    return month

def valid_year(year):
    if year and year.isdigit():
	year = int(year)
	if(year < 2020 and year > 1880):
	    return year

class MainPage(webapp2.RequestHandler):
    def write_form(self, error="", day="", month="", year=""):
	self.response.out.write(form %{
	    "error": error,
	    "day": escape_html(day),
	    "month": escape_html(month),
	    "year": escape_html(year)
	    })
    def get(self):
	self.write_form()
    def post(self):
	uday   = self.request.get("day")
	umonth = self.request.get("month")
	uyear  = self.request.get("year")
	print "  -- user:", uday, umonth, uyear
	if not (valid_day(uday) and valid_month(umonth) and valid_year(uyear)):
	    self.write_form("Illegal input", uday, umonth, uyear)
	else:
	    self.redirect("/thanks")

class ThanksHandler(webapp2.RequestHandler):
    def get(self):
	self.response.headers['Content-Type'] = 'text/plain'
	self.response.write("Thanks!")

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/thanks', ThanksHandler),
], debug=True)
