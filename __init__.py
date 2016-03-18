from flask import Flask, render_template, request, redirect
from flask import url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
import database_setup
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
import httplib2
import requests
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
from flask import make_response
from math import ceil
import re
import os

engine = create_engine('postgresql://catalog:catalogLinuxWebServer@localhost/categorieitems')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
import data
app = Flask(__name__)
app.db = session
# Loging in and loging out with google plus anf facebook functionality
here = os.path.dirname(__file__)
full_path_to_secrets_file = os.path.join('/var/www/catalogApp/catalogApp/', 'client_secrets.json')
CLIENT_ID = json.loads(
    open(full_path_to_secrets_file, 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

# Create anti-forgery state token
# Login page
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    categories = app.db.query(Category.name, Category.id).all()
    itemsByCategory = app.db.query(Item.name,Category.name).\
                      filter(Item.category_id==Category.id).\
                      order_by(Item.timestmp.desc()).limit(9)
    return render_template('login.html', categories = categories,
                           items = itemsByCategory, STATE=state,
                           login_session = login_session)


# Connect with facebook

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        print('get inside the if')
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    full_path_to_fb_secrets_file = os.path.join('/var/www/catalogApp/catalogApp/', 'fb_client_secrets.json')
    app_id = json.loads(open(full_path_to_fb_secrets_file, 'r').read())['web']['app_id']
    app_secret = json.loads(
        open(full_path_to_fb_secrets_file, 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print(result)
    # print('this is result')
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<p class="logginMessage">Welcome, '
    output += login_session['username']
    output += '</p>'

    flash("Now logged in as %s" % login_session['username'])
    return output

# Disconnect with facebook

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    categories = app.db.query(Category).all()
    itemsByCategory = app.db.query(Item.name,Category.name).\
                      filter(Item.category_id==Category.id).\
                      order_by(Item.timestmp.desc()).limit(10)
    return render_template('main.html', categories = categories,
                           items = itemsByCategory,
                           login_session=login_session)

# Connect with google

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
       #oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow = flow_from_clientsecrets(full_path_to_secrets_file, scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'% access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        print('this is the error')
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is'
                                            'already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    print('picture')
    print (login_session['picture'])
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<p class="logginMessage">Welcome, '
    output += login_session['username']
    output += '!</p>'

    flash("you are now logged in as %s" % login_session['username'])
    return output

# disconnect with google

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    """if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response"""
    categories = app.db.query(Category).all()
    itemsByCategory = app.db.query(Item.name,Category.name).\
                      filter(Item.category_id==Category.id).\
                      order_by(Item.timestmp.desc()).limit(10)
    return render_template('main.html', categories = categories,
                           items = itemsByCategory,
                           login_session=login_session)

# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    app.db.add(newUser)
    app.db.commit()
    users = app.db.query(User).all()
    user = app.db.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = app.db.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = app.db.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Disconnect - Revoke a current user's token and reset their login_session
# Check if google or facebook and call the accordinf function

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
        if login_session['provider'] == 'facebook':
            fbdisconnect()
        login_session.clear()
        flash("You have been successfully logged out")
    else:
        flash('You were not logged in to begin with!')
    return redirect(url_for('allCategories'))

# The app functionality

# The main page of the app
# Presents all the categories and the recents added items
@app.route('/')
@app.route('/main/')
def allCategories():
    categories = app.db.query(Category).all()
    itemsByCategory = app.db.query(Item.name, Category.name).\
                      filter(Item.category_id==Category.id).\
                      order_by(Item.timestmp.desc()).limit(10)
    users = app.db.query(User).all()
    for user in users:
        print(user.name,user.id, user.email, user.picture)
    return render_template('main.html', categories = categories,
                           items = itemsByCategory,
                           login_session = login_session)

# Displays all the items of this category

@app.route('/categories/<string:category_name>/')
def categoryItems(category_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    categories = app.db.query(Category).all()
    items = app.db.query(Item.id, Item.name).\
            filter(Item.category_id==category.id).all()
    numOfItems = app.db.query(func.count('*')).\
                 select_from(Item).\
                 filter(Item.category_id==category.id).scalar()
    return render_template('categoryitems.html',
                           category_user_id = category.user_id,
                           category_name = category.name,
                           items=items, category=category,
                           categories = categories,
                           numOfItems = numOfItems,
                           login_session = login_session)

# Edit category details

@app.route('/categories/<string:category_name>/edit/', methods=['POST','GET'])
def editCategory(category_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    if request.method == 'POST':
      if login_session:
        if login_session['user_id'] == category.user_id:
          category.name=request.form['name']
          app.db.commit()
          flash("The category was edited successfully!")
        else:
          flash ("You are not authorized to edit this category!")
      else:
        flash("You are not authorized to edit categories!")
      return allCategories()
    else:
        return render_template('categoryeditmenu.html',
                               category=category,
                               login_session = login_session)

# Delete a category - this will delete the items in the categoru as well

@app.route('/categories/<string:category_name>/delete/', methods=['POST','GET'])
def deleteCategory(category_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    items = app.db.query(Item).filter(Item.category_id==category.id).all()
    if request.method == 'POST':
      if login_session:
        if login_session['user_id'] == category.user_id:
          for item in items:
              app.db.delete(item)
              app.db.commit()
          app.db.delete(category)
          app.db.commit()
          flash("The category and the items were deleted successfully!")
        else:
          flash("You are not authorized to delete this category!")
      else:
        flash("You are not authorized to delete categories!")
      categories = app.db.query(Category).all()
      return allCategories()
    else:
        return render_template('categoryideletemenu.html',
                               category = category,
                               login_session = login_session)

# Add a new category to the system

@app.route('/categories/new/', methods=['POST','GET'])
def newCategory():
    if request.method == 'POST':
      inputName = request.form['name'].strip()
      if login_session:
        if not inputName:
          flash("Please enter the catgoery name")
          return render_template('newcategoriemenu.html',
                                  login_session = login_session)
        if app.db.query(Category).filter(Category.name == inputName).all():
          flash("This category allready exist!")
          return render_template('newcategoriemenu.html',
                                  login_session = login_session)
        else:
          newCategory = Category(
            name=inputName, user_id = login_session['user_id'])
          app.db.add(newCategory)
          app.db.commit()
          flash("A new category was created successfully!")
          return allCategories()
      else:
          flash('You are not authorized to create new categories!')
          return allCategories()
    else:
      return render_template('newcategoriemenu.html',
                              login_session = login_session)

# Display details of a specific item

@app.route('/categories/<string:category_name>/<string:item_name>/')
def categoryItemDetails(category_name,item_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    items = app.db.query(Item).\
            filter(Item.name==item_name, Item.category_id == category.id).one()
    categories = app.db.query(Category).all()
    return render_template('categorieitemmenu.html',
                           categories=categories,
                           items=items,category_name=category.name,
                           login_session = login_session)

# Edit item details

@app.route('/categories/<string:category_name>/<string:item_name>/edit',
           methods=['POST','GET'])
def editCategoryItem(category_name, item_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    item = app.db.query(Item).\
           filter(Item.name==item_name, Item.category_id==category.id).one()
    categories = app.db.query(Category).all()
    if request.method == 'POST':
        if login_session:
          if login_session['user_id'] == item.user_id:
            if(request.form['name']<>''):
                item.name=request.form['name']
            if(request.form['description']<>''):
                item.description=request.form['description']
            if(request.form['picture']<>''):
                item.picture=request.form['picture']
            if(request.form['category']<>''):
                category_name_new=request.form['category']
                categoryNew = app.db.query(Category).\
                              filter(Category.name==category_name_new).one()
                item.category = categoryNew
                app.db.commit()
                flash("The item was edited successfully!")
          else:
            flash ("You are not authorized to edit this item!")
        else:
          flash("You are not authorized to edit items!")
        items = app.db.query(Item).filter(Item.category_id==category.id).all()
        return render_template('categoryitems.html',
                               category_name=category.name,
                               items=items,
                               categories=categories, category=category
                               ,login_session=login_session)
    else:
        return render_template('editcategorieitemmenu.html',
                               category_name=category_name,
                               item=item, categories=categories,
                               login_session = login_session)

# Delete item

@app.route('/categories/<string:category_name>/<string:item_name>/delete',
           methods=['POST','GET'])
def deleteCategoryItem(category_name, item_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    item = app.db.query(Item).\
           filter(Item.name==item_name, Item.category_id==category.id).one()
    categories = app.db.query(Category).all()
    if request.method == 'POST':
      if login_session:
          if login_session['user_id'] == item.user_id:
            app.db.delete(item)
            app.db.commit()
            flash("The item was deleted successfully!")
          else:
            flash ("You are not authorized to delete this item!")
      else:
          flash("You are not authorized to delete items!")
      items = app.db.query(Item).filter(Item.category_id==category.id).all()
      return render_template('categoryitems.html',category_name=category.name,
                               items=items, categories=categories,
                               category=category, login_session=login_session)
    else:
        return render_template('deletecategorieitemmenu.html',
                               category_name = category_name,
                               item=item, login_session=login_session)

# Add a new item

@app.route('/categories/<string:category_name>/new/', methods=['POST','GET'])
def newItemInCategory(category_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    if request.method == 'POST':
        inputName = request.form['name'].strip()
        inputDescription = request.form['description'].strip()
        inputPicture = request.form['picture'].strip()
        if login_session:
          if app.db.query(Item).filter(Item.name == inputName, Item.category_id == category.id).all():
              flash("This item allready exist in this category!")
              return render_template('newitemincategoriemenu.html',
                                  category = category,
                                  login_session=login_session)
          if not inputName or not inputDescription:
              flash("Please enter the item name and description")
              return render_template('newitemincategoriemenu.html',
                                  category = category,
                                  login_session=login_session)
          else:
              newItem = Item(
                  name=inputName,
                  description=inputDescription,
                  picture=inputPicture,
                  category_id=category.id,
                  user_id = login_session['user_id'])
              app.db.add(newItem)
              app.db.commit()
              items = app.db.query(Item.id, Item.name).\
                      filter(Item.category_id==category.id).all()
              categories = app.db.query(Category).all()
              flash("The items was created successfully!")
              return render_template('categoryitems.html',
                                     items=items, category_name=category_name,
                                     categories = categories,
                                     login_session=login_session)
        else:
          items = app.db.query(Item.id, Item.name).\
                      filter(Item.category_id==category.id).all()
          categories = app.db.query(Category).all()
          flash("You are not authorized to create new items!")
          return render_template('categoryitems.html',
                                     items=items, category_name=category_name,
                                     categories = categories,
                                     login_session=login_session)
    else:
        return render_template('newitemincategoriemenu.html',
                                 category = category,
                                 login_session=login_session)



# API
# JSON APIs to view Categories and Items Information

# View all categories
@app.route('/main/JSON')
@app.route('/JSON')
def categoriesJSON():
    categories = app.db.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])

# View all items in a specific category
@app.route('/categories/<string:category_name>/JSON')
def categoriesItemsJSON(category_name):
    category = app.db.query(Category).filter(Category.name==category_name).one()
    items = app.db.query(Item).filter(Item.category_id==category.id).all()
    return jsonify(items=[i.serialize for i in items])

# View a specific item
@app.route('/categories/<string:category_name>/<string:item_name>/JSON')
def itemJSON(category_name, item_name):
    item = app.db.query(Item).filter(Category.name==category_name,
                                     Item.name==item_name).one()
    return jsonify(item=item.serialize)


if __name__ == '__main__':
    # Flash uses the secret key to create sessions for the users.
    app.secret_key = 'super_secret_key'
    # If debug is enabled, the server will reload itself each time it notices a
    # code change.
    app.debug = True
    #app.run(host='0.0.0.0', port=5000)
