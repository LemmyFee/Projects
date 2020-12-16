from flask import Blueprint,Flask,render_template,request,session,redirect,url_for,flash
from wtforms import form,TextField,PasswordField,validators,StringField,IntegerField,DateField
from flask_login import login_user, logout_user, current_user, login_required,LoginManager
from wtforms.validators import InputRequired, Email, DataRequired, optional
from flask_wtf import FlaskForm,Form
from flask_bcrypt import bcrypt
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail
import bcrypt
import os
import pymongo
import datetime

# app = Blueprint('app', __name__)
app = Flask(__name__)
#csrf = CSRFProtect(app)
app.config["SECRET_KEY"]='\x90\xa4L\xf06WE\x8b\x14\xd3V#\xcdm<\x9e\x9fN\x89.1\xb0\xee#'

client=pymongo.MongoClient(os.environ['MONGO_URI'])
user_collection = client.Eni400L.Practices
books_collection = client.Eni400L.Books

lm   = LoginManager(   ) #flask-loginmanager
#bc   = bcrypt      (app) #flask-bcrypt

lm.init_app(app) # init the login manager



#     matricnumber = StringField('matric number', [validators.Length(min=9, max=9)] )
#     email= StringField('Email Address', [validators.Length(min=12, max=50)])

#     # password = b'SecretPassword55'
#     # hashed = bcrypt.hashpw(password, bcrypt.gensalt()) 
#     # if bcrypt.checkpw(password, hashed):
#     #         print("It Matches!")
#     # else:
#     #         print("It Does not Match :(")
#     password = PasswordField('Password', [validators.DataRequired()])
                                  # validators.EqualTo('confirm', message="Passwords must match")])
                              
    # confirm = PasswordField('Repeat Password')   

# @app.route('/<password>')       
# def index(password):

#     hashed_value = generate_password_hash(password)

#     #stored_password = 'pbkdf2:sha256:150000$6EfLgGyU$64dd0cbd46aef5c34cba727d14d97f24dd295b403b3f493cce69bc2d1162f77e'
#     return hashed_value

# @app.route('/',methods=["GET","POST"])
# def index():
#     if 'matricnumber' in session:
#         return 'You are logged in as' + session['matricnumber']

#     return render_template('index.html')


class LoginForm(FlaskForm):
   matricnumber    = StringField  ('matric_number'    , validators=[DataRequired()])
   password    = PasswordField('password'    , validators=[DataRequired()])


class RegisterForm(FlaskForm):
	matricnumber    = StringField  ('matric_number'  , validators=[DataRequired()])
	password    = PasswordField ('password'  , validators=[DataRequired()])
	email       = StringField  ('email'     , validators=[DataRequired(), Email()])

# BOOK ENTRY

class BookEntry(FlaskForm):
    projecttitle = StringField ('projecttitle'  , validators=[DataRequired()])
    yearwritten = DateField ('year', format='%m/%d/%Y', validators=(validators.Optional(),))
    author = StringField ('author'  , validators=[DataRequired()])
    department = StringField ('department'  , validators=[DataRequired()])
    keywords = StringField ('keywords'  , validators=[DataRequired()])
    link = StringField ('link'  , validators=[DataRequired()])
    
    

	


    
client=pymongo.MongoClient(os.environ['MONGO_URI'])
user_collection = client.Eni400L.Practices
books_collection = client.Eni400L.Books

# provide login manager with load_user callback
@lm.user_loader
def load_user(_id):
        return user_collection.find_one(int(_id))

#     # authenticate user
# @app.route('/logout.html')
# def logout():
#     logout_user()
#     return redirect(url_for('index'))






# authenticate user
@app.route('/login', methods=['GET', 'POST'])
def login():
    
#     # define login form here
    form = LoginForm(request.form)

#     # Flask message injected into the page, in case of any errors
#     msg = None


#     # check if both http method is POST and form is valid on submit
    if request.method == "POST":
        

#         # assign form data to variables
        matricnumber = request.form.get('matricnumber')

        print(matricnumber)
        password = request.form.get('password') 
        
    

#         # filter User out of database through username
        user = user_collection.find_one({'matricnumber' : request.form['matricnumber']})

        if user:
            if bcrypt.checkpw(user.password, password):
                 login_user(user)
                 return redirect(url_for('index'))
            else:
                 flash("Wrong password. Please try again.")
        else:
             flash("Unknown user")



        return 'Invalid username or password combination' 
    
    return render_template("login.html",form=form)


@app.route('/register',methods=["GET","POST"])
def register():
    form = RegisterForm(request.form)
    
    if request.method == "POST":

        matricnumber=request.form.get("matricnumber")
        print(matricnumber)

        email=request.form.get("email")
        print(email)

        password = b'SecretPassword55'
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        if bcrypt.checkpw(password, hashed):
            password=request.form.get("password")
            print(hashed)
        
        # filter User out of database through username
        user = user_collection.find_one({'matricnumber' : request.form['matricnumber']})

        # filter User out of database through username
        user_by_email = user_collection.find_one({'email' : request.form['email']})

        if user or user_by_email:
             flash('Error: User exists!')
        
        else:  

          user_info={
            "matric_number":matricnumber,
            "Email":email,
            "Password":hashed,
            "created_at":datetime.datetime.now()
          }
       
          user_collection.insert_one(user_info)
          print("successfully inserted")

          #flash('User created, please <a href="' + url_for('login') + '">login</a>')

   
    return render_template("register.html",form=form)



@app.route('/books', methods = ["GET","POST"])
def books():
    form = BookEntry(request.form)

    if request.method == "POST" :

        projecttitle = request.form.get('projecttitle')
        print(projecttitle)

        yearwritten = request.form.get('yearwritten')
        print(yearwritten)

        author = request.form.get('author')
        print(author)

        department = request.form.get('department')
        print(department)

        keywords = request.form.get('keywords')
        print(keywords)

        link = request.form.get('link')
        print(link)





    
        book_info ={

            "Title":projecttitle,
            "Year":yearwritten,
            "Author":author,
            "Department":department,
            "Keywords":keywords,
            "url":link,
            "Added at":datetime.datetime.now()

        }

        books_collection.insert_one(book_info)
        print('sucessfully added')
    


    return render_template("book.html",form=form)







if __name__ == "__main__":
   app.config["SECRET_KEY"]='\x90\xa4L\xf06WE\x8b\x14\xd3V#\xcdm<\x9e\x9fN\x89.1\xb0\xee#'
   app.run(use_reloader=True)

