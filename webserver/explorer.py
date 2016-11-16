#!/usr/bin/env python2.7

"""
Columbia W4111 Intro to databases
Maya Anand and Hollis Mills
mva2112 and hm2602
To run locally

    python explorer.py

MAYA: Go to http://104.196.182.25:8111 in your browser
HOLLIS: Go to http://104.196.194.224:8111 in your browser

A debugger such as "pdb" may be helpful for debugging.
Read about it online.
"""

import os
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response, session, url_for, escape, flash
from hashlib import md5
from flask_bootstrap import Bootstrap
from flask_nav import Nav
from flask_nav.elements import *
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email
from functools import wraps

#Create app and configure boostrap
def create_app():
    tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    app = Flask(__name__, template_folder=tmpl_dir)
    app.config['SECRET_KEY'] = 'apple-pineapple-cle'
    Bootstrap(app)
    return app

app = create_app()

#Create navbar
topbar = Navbar('', View('Home', 'index'), View('Groups', 'groups'), View('Search', 'search'), View('Login', 'login'), View('Log Out', 'logout'), View('Sign Up', 'signup'), )

nav = Nav()
nav.register_element('top', topbar)
nav.init_app(app)

DATABASEURI = "postgres://mva2112:n3dek@104.196.175.120/postgres"
engine = create_engine(DATABASEURI)

class ServerError(Exception):pass

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Email()])
    password = PasswordField('Password', validators=[Required()])
    institution = StringField('Institution (optional)')
    submit = SubmitField('Sign Up')

@app.before_request
def before_request():
  """
  setup a database connection that can be used throughout the request
  The variable g is globally accessible
  """
  try:
    g.conn = engine.connect()
  except:
    print "problem connecting to database"
    import traceback; traceback.print_exc()
    g.conn = None

@app.teardown_request
def teardown_request(exception):
  """
  At the end of the web request, this makes sure to close the database connection.
  """
  try:
    g.conn.close()
  except Exception as e:
    pass

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'username' in session:
        username_session = escape(session['username']).capitalize()
    else:
        username_session = ""
    return render_template("index.html", session_user_name=username_session)
@app.route('/search')
def search():
    ids = []
    cursor = g.conn.execute("SELECT rsid FROM variant ORDER BY rsid::bytea;")
    for result in cursor:
       ids.append(result['rsid']) 
    cursor.close()
    context = dict(data = ids)
    return render_template("search2.html", **context)

@app.route('/groups')
@login_required
def groups():
  groups = []
  cursor = g.conn.execute("SELECT DISTINCT category FROM relational_groups;")
  for result in cursor:
    groups.append(result['category'])  
  cursor.close()
  context = dict(data = groups)
  return render_template("groupsTry1.html", **context)

@app.route('/group/<category>')
def singleGroup(category):
  cmd = 'SELECT * FROM relational_groups WHERE category LIKE :category1'
  cursor = g.conn.execute(text(cmd), category1 = category)
  rsid = []
  for result in cursor:
    rsid.append(result['rsid'])
  cursor.close()
  context = dict(data = rsid)
  return render_template("groupRSID.html", **context)

@app.route('/<rsid>')
def variant(rsid):
  variant = []
  cmd = 'SELECT * FROM variant, article WHERE variant.rsid Like :rsid1 AND variant.rsid = article.rsid'
  cursor = g.conn.execute(text(cmd), rsid1 = rsid)
  result = cursor.fetchone()
  if result is None:
    cmd = 'SELECT * FROM variant where variant.rsid Like :rsid1'
    cursor = g.conn.execute(text(cmd), rsid1 = rsid)
    result = cursor.fetchone()
    if result is None:
       flash("This variant is not in our database. Please try something else")
       return redirect(url_for('search'))
  variant.append(result['rsid'])
  variant.append(result['chrom'])
  variant.append(result['pos'])
  variant.append(result['ref'])
  variant.append(result['alt'])
  variant.append(result['cid'])
  gid = result['gid']
  cmd = 'SELECT gene_name FROM gene where gid = :gid1'
  cursorGene = g.conn.execute(text(cmd), gid1 = str(gid))
  resultGene = cursorGene.fetchone()
  variant.append(resultGene['gene_name'])
  variant.append(result['gid'])
  if 'title' in result:
    variant.append(result['title']) 
    variant.append(result['first_author'])                                                                                    
    variant.append(result['link'])
    if (cursor.rowcount == 2):
      result2 = cursor.fetchone()
      variant.append(result2['title'])
      variant.append(result2['first_author'])                                                                                                                      
      variant.append(result2['link'])                                                                                
  cursor.close()
  context = dict(data = variant)
  return render_template("variantTry2.html", **context)

@app.route('/gene/<gid>')
def gene(gid):
    cmd = 'SELECT * FROM gene where gid = :gid1'
    cursor = g.conn.execute(text(cmd), gid1 = gid)
    geneInfo = []
    result = cursor.fetchone()
    geneInfo.append(result['gene_name'])
    geneInfo.append(result['chrom'])
    geneInfo.append(result['start_pos'])
    geneInfo.append(result['end_pos'])
    geneInfo.append(result['phenotype'])
    cursor.close()
    context = dict(data = geneInfo)
    return render_template("gene.html", **context)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()    
    if 'username' in session:
        return redirect(url_for('index'))
    
    error = None
    try:
        if request.method == 'POST':
            username_form = '%'+ form.email.data + '%'
            cmd = 'SELECT COUNT(1) FROM users WHERE email like :email1'
            cursor = g.conn.execute(text(cmd), email1 = username_form)
        
            if not cursor.fetchone()[0]:
                raise ServerError('Invalid username')
                flash('USER NOT FOUND')
        
            password_form = form.password.data            
            cmd = 'SELECT password_hash FROM users where email like :email1'
            cursor = g.conn.execute(text(cmd), email1 = username_form)
        
            for row in cursor.fetchall():
                if md5(password_form).hexdigest() == row[0]:
                    session['username'] = form.email.data
                    return redirect(url_for('index'))
            raise ServerError('Invalid password')

    except ServerError as e:
        error = str(e)
    flash(error)    
    return render_template('login.html', form=form, error=error)
 
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if 'username' in session:
        return redirect(url_for('index'))

    error = None
    try:
        if request.method == 'POST':
            researcher = False
            username_form = '%'+ form.email.data + '%'
            password = md5(form.password.data).hexdigest()
            if len(form.institution.data) > 1:
                institution = form.institution.data[0]
                researcher = True

           
           

            if researcher == True:
                cmd = 'INSERT into users VALUES (:email1, :pw, True, False)'
                cursor = g.conn.execute(text(cmd), email1 = username_form, pw = password)

                cmd = 'INSERT into researcher VALUES (:email1, :inst)'
                cursor = g.conn.execute(text(cmd), email1 = username_form, inst = institution)
            if researcher == False:
                cmd = 'INSERT into users VALUES (:email1, :pw, False, True)'
                cursor = g.conn.execute(text(cmd), email1 = username_form, pw = password)           
                cmd = 'INSERT into casual VALUES (:email1)'
                cursor = g.conn.execute(text(cmd), email1 = username_form)

            session['username'] = form.email.data
            flash('Account Created')
            return redirect(url_for('index'))
            
    except ServerError as e:
        error = str(e)
    return render_template('signup.html', form=form, error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == "__main__":
  import click

  @click.command()
  @click.option('--debug', is_flag=True)
  @click.option('--threaded', is_flag=True)
  @click.argument('HOST', default='0.0.0.0')
  @click.argument('PORT', default=8111, type=int)
  def run(debug, threaded, host, port):
    """
    This function handles command line parameters.
    Run the server using

        python server.py

    Show the help text using

        python server.py --help

    """

    HOST, PORT = host, port
    print "running on %s:%d" % (HOST, PORT)
    app.run(host=HOST, port=PORT, debug=debug, threaded=threaded)


  run()
