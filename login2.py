from flask import Flask, render_template,request, session, redirect,url_for, flash, json, make_response, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length
import mysql.connector
from inspect import currentframe, getframeinfo
from flask_login import login_required
import jwt
import datetime
import auth
from jwt import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
from simplecrypt import encrypt, decrypt
import sqlalchemy
import base64
import io
from functools import wraps
import requests
from flask_jwt import jwt_required, jwt, JWT
from flask_security import auth_required, auth_token_required
from flask_jwt_extended import *
from twilio.rest import Client
import os
import random
import smtplib
import uuid 
#from sqlalchemy.orm.exc import UnmappedInstanceError
  


#Your new Phone Number is +19852140955



global state,district,pincode







UPLOAD_FOLDER = 'C:/Users/AVIK/PycharmProjects/Search_project/static/Uploaded/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'JPG', 'PNG', 'JPEG','GIF'}




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:' '@localhost/serachproject'
app.config['SECRET_KEY'] = 'thisissecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

'''login_manager = LoginManager()
login_manager.init_app(app)'''






class Registration(db.Model):
    '''def __init__(self, cname, gender, birthdate, address, email, mobile, password):
        self.nid = nid
        self.cname = cname
        self.gender = gender
        self.birthdate = birthdate
        self.address = address
        self.email = email
        self.mobile = mobile
        self.password = password'''


    nid = db.Column(db.Integer, primary_key = True)
    cname = db.Column(db.String(50), nullable=True, unique=False)
    '''gender = db.Column(db.String(10), nullable=True, unique=False)
    birthdate = db.Column(db.String(15), nullable=True, unique=False)
    address = db.Column(db.String(50), nullable=True, unique=False)'''
    email = db.Column(db.String(25), nullable=True, unique=False)
    mobile = db.Column(db.String(15),  nullable=False)
    password = db.Column(db.String(10), nullable=True, unique=False)
    date_time = db.Column(db.String(100),nullable=True, unique=False)



class Store_details(db.Model):
    st_id =  db.Column(db.Integer, primary_key = True)
    typ = db.Column(db.String(100), nullable=True, unique=False)
    st_name =db.Column(db.String(500), nullable=True, unique=False)
    description = db.Column(db.String(500), nullable=True, unique=False)
    street_name = db.Column(db.String(500), nullable=True, unique=False)
    pincode = db.Column(db.String(50), nullable=True, unique=False)
    place = db.Column(db.String(500), nullable=True, unique=False)
    locality = db.Column(db.String(300), nullable=True, unique=False)
    dist = db.Column(db.String(100), nullable=True, unique=False)
    state = db.Column(db.String(50), nullable=True, unique=False)
    phone = db.Column(db.String(50), nullable=True, unique=False)
    opening = db.Column(db.String(50), nullable=True, unique=False)
    closing = db.Column(db.String(50), nullable=True, unique=False)
    category = db.Column(db.String(50), nullable=True, unique=False)
    date_time = db.Column(db.String(100),nullable=True, unique=False)
    



class State(db.Model):
    state_id = db.Column(db.String(5), primary_key = True)
    state_name = db.Column(db.String(25), nullable=True, unique=False)


class District(db.Model):
    dist_id = db.Column(db.String(5), primary_key = True)
    dist_name = db.Column(db.String(25), nullable=True, unique=False)
    state_id = db.Column(db.String(5), nullable=True, unique=False)

class Pincode(db.Model):
    pin = db.Column(db.String(10), primary_key = True)
    dist_id = db.Column(db.String(5), nullable=True, unique=False)



class LoginForm(FlaskForm):
    mobile = StringField('mobile', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    remember = BooleanField('remember me')


class Admin_gram(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    paswrd = PasswordField('paswrd', validators=[InputRequired()])
    remember = BooleanField('remember me')

class Img_details(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    img = db.Column(db.Text, unique=True, nullable=False)
    name = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.Text, nullable=False)


class Otp_verification(db.Model):
    otp_id = db.Column(db.String(100), primary_key = True)
    otp_val = db.Column(db.String(10), nullable=True)
    created = db.Column(db.String(100),nullable=True)


class Contributor_temporary_data(db.Model):

    __tablename__ = "Contributor_temporary_data"

    ctrid = db.Column(db.Integer, primary_key = True)
    ctrname = db.Column(db.String(10), nullable=True)
    ctrmobile = db.Column(db.String(100),nullable=True)
    ctremail = db.Column(db.String(10), nullable=True)
    ctrgender = db.Column(db.String(100),nullable=True)
    ctraddress = db.Column(db.String(10), nullable=True)
    ctrpincode = db.Column(db.String(100),nullable=True)
    ctrdist = db.Column(db.String(10), nullable=True)
    ctrstate = db.Column(db.String(100),nullable=True)


class Contributor_data(db.Model):
    __tablename__ = "contributor_data"
    cid  = db.Column(db.Integer, primary_key = True)
    cname = db.Column(db.String(10), nullable=True)
    cmobile = db.Column(db.String(100),nullable=True)
    cemail = db.Column(db.String(10), nullable=True)
    cgender = db.Column(db.String(100),nullable=True)
    caddress = db.Column(db.String(10), nullable=True)
    cpincode = db.Column(db.String(100),nullable=True)
    cdistrict = db.Column(db.String(10), nullable=True)
    cstate = db.Column(db.String(100),nullable=True)

@app.route("/")
def home():

    return render_template('Home.html')


@app.route("/about_us", methods = ['GET', 'POST'])
def about_us():
    return render_template("about us.html")

@app.route("/registration", methods = ['GET', 'POST'])
def registration():
    if request.method == 'POST':
        uname = request.form.get('uname')
        '''gender = request.form.get('gender')
        dob = request.form.get('dob')
        address = request.form.get('address')'''
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        pw_hash1 = generate_password_hash(password, "sha256")
        


        
        
        try:
            otp_id = uuid.uuid1()
            print(otp_id)
            otp = random.randint(1000,9999)
            print(otp)

            
            
            ''' url = "http://2factor.in/API/V1/{0}/SMS/{1}/{2}/{3}".format(api_Key,mobile,otp,msg)
            r = requests.get(url=url) #https://2factor.in/API/V1/{api_key}/SMS/VERIFY/{session_id}/{otp_input}     +"?sid="+r.json()["Details"]
            sid = r.json()["Details"]'''
            
            
            '''server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login('avikrakshit78@gmail.com', 'ixcidpqqmtwpwcaq')
            msg = " Your OTP for Search Project is " +str(otp)
            server.sendmail('avikrakshit78@gmail.com', email, msg)
            server.quit()'''

            otp_data = Otp_verification(otp_id=otp_id, otp_val=otp)
            db.session.add(otp_data)
            db.session.commit()

            '''reg = Registration(cname=uname, email=email, mobile=mobile, password=pw_hash1)
            db.session.add(reg)
            db.session.commit()'''
            return render_template('otp verification.html', otp_id=otp_id)

        except:
            return("Mobile No or Email is already registered")

        

    return render_template('registration_new.html')

@app.route("/otp_verification", methods=['GET','POST'])
def otp_verification():
    if request.method == 'POST':
        otp_id_recv = request.form.get('otp_id')
        otp_recv = request.form.get('user_otp')


        otp_data = Otp_verification.query.filter_by(otp_val=otp_recv, otp_id=otp_id_recv).first()
        
        return"<h1>success</h1>"
        


        '''if 
            return "<h1> enter correct OTP</h1>"
        
        else:
            return"<h1> Thank you for registerd to our website. </h1>"'''
        
        '''verify = "https://2factor.in/API/V1/{0}/SMS/VERIFY/{1}/{2}".format(api_Key,sid,otp)
        r = requests.get(url=verify)
        if r.json()["Status"] == "Success":
            return "<h1> otp has been verified</h1>"'''
        
        
    return render_template('otp verification.html')


@app.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        print('coming')
        mobile = request.form.get('mobile')
        password2 =request.form.get('password')
        remember = True if request.form.get('remember') else False

        
        data = Registration.query.all()
        for i in data:
            if i.mobile == mobile:
                if check_password_hash(i.password, password2) == True:
                    session['user_id'] = mobile
                    return render_template("After_login.html")

    return render_template('login_new.html')






    


@app.route('/result', methods=['POST','GET'])
def result():
    if request.method=='POST':
        if 'user_id' in session:
            global state, district, pincode
       
        
        
            state = request.form.get('state')
            district = request.form.get('district')
            pincode = request.form.get('pincode')


       

        
            if not state or not district or not pincode:
                return render_template('result_error_page.html')

            else:
                ''' beauty = Store_details.query.filter_by(category='1', pincode =pincode)
                food = Store_details.query.filter_by(category='2', pincode =pincode)
                grocery = Store_details.query.filter_by(category='3',pincode =pincode)
                hotel = Store_details.query.filter_by(category='4',pincode =pincode)
                medical = Store_details.query.filter_by(category='5',pincode =pincode)
                places =  Store_details.query.filter_by(category='6',pincode =pincode)
                shopping =Store_details.query.filter_by(category='7',pincode =pincode)
                services =Store_details.query.filter_by(category='8',pincode =pincode)
                education =Store_details.query.filter_by(category='9',pincode =pincode)
                law =Store_details.query.filter_by(category='10',pincode =pincode)'''
                return render_template('result_all.html')
        else:
            return redirect(url_for('home'))
        
    
        return render_template('After_login.html')
    return "<h1> OOPS!.. Your are an Unauthorised User. </h1>"








@app.route("/logout", methods=['POST', 'GET'])
def logout():
    if 'user_id' in session:
        session.pop('user_id', None)
    
    return redirect(url_for('home'))

@app.route('/beauty_data', methods=['POST', 'GET'])
def beauty_data():
    global state,district,pincode
    if 'user_id' in session:
        image_names = os.listdir('C:/Users/AVIK/PycharmProjects/Search_project/static/Uploaded')
        beauty = Store_details.query.filter_by(category='1', pincode = pincode).all()

        for i in beauty:
            locality_data = i.locality 


        return render_template('beauty_data.html', beauty=beauty, locality=locality_data, image_name=image_names)

    else:
        return "<h1>unauthorised users</h1>"
        
@app.route('/beauty_data_details/<st_id>', methods=['POST', 'GET'])
def beauty_data_details(st_id):
    global state,district,pincode
    if 'user_id' in session:
        image_names = os.listdir('C:/Users/AVIK/PycharmProjects/Search_project/static/Uploaded')
        beauty = Store_details.query.filter_by(category='1', pincode = pincode,st_id=st_id).all()

        for i in beauty:
            locality_data = i.locality 
            store_name = i.st_name


        return render_template('beauty_data_details.html', beauty=beauty, locality=locality_data, image_name=image_names, st_name=store_name)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/food_data', methods=['POST', 'GET'])
def food_data():
    global state,district,pincode

    if 'user_id' in session:
        food = Store_details.query.filter_by(category='2', pincode = pincode)
        for i in food:
            locality_data = i.locality


        return render_template('food_data.html', food=food, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"



@app.route('/education_data', methods=['POST', 'GET'])
def education_data():
    global state,district,pincode
    
    if 'user_id' in session:
        education = Store_details.query.filter_by(category='9', pincode = pincode)
        for i in education:
            locality_data = i.locality

        return render_template('education_data.html', education=education, locality=locality_data)
    
    else:
        return "<h1>unauthorised users</h1>"



@app.route('/grocery_data', methods=['POST', 'GET'])
def grocery_data():
    global state,district,pincode
    
    if 'user_id' in session:
        grocery = Store_details.query.filter_by(category='3', pincode = pincode)
        for i in grocery:
            locality_data = i.locality

        return render_template('grocery_data.html', grocery=grocery, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/hotel_data', methods=['POST', 'GET'])
def hotel_data():
    global state,district,pincode

    if 'user_id' in session:
        hotel = Store_details.query.filter_by(category='4', pincode = pincode)
        for i in hotel:
            locality_data = i.locality

        return render_template('hotel_data.html', hotel=hotel, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/law_data', methods=['POST', 'GET'])
def law_data():
    global state,district,pincode
    
    if 'user_id' in session:
        law = Store_details.query.filter_by(category='10', pincode = pincode)
        for i in law:
            locality_data = i.locality

        return render_template('law_data.html', law=law, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/medical_data', methods=['POST', 'GET'])
def medical_data():
    global state,district,pincode
    
    if 'user_id' in session:
        medical = Store_details.query.filter_by(category='5', pincode = pincode)
        for i in medical:
            locality_data = i.locality

        return render_template('medical_data.html', medical=medical, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/places_data', methods=['POST', 'GET'])
def places_data():
    global state,district,pincode
    
    if 'user_id' in session:
        places = Store_details.query.filter_by(category='6', pincode = pincode)
        for i in places:
            locality_data = i.locality

        return render_template('places_data.html', places=places, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/shopping_data', methods=['POST', 'GET'])
def shopping_data():
    global state,district,pincode
    
    if 'user_id' in session:
        shopping = Store_details.query.filter_by(category='7', pincode = pincode)
        for i in shopping:
            locality_data = i.locality

        return render_template('shopping_data.html', shopping=shopping, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"


@app.route('/services_data', methods=['POST', 'GET'])
def services_data():
    global state,district,pincode
    
    if 'user_id' in session:
        services = Store_details.query.filter_by(category='8', pincode = pincode)
        for i in services:
            locality_data = i.locality
        return render_template('services_data.html', services=services, locality=locality_data)

    else:
        return "<h1>unauthorised users</h1>"
        
        


@app.route('/contributer', methods=['GET', 'POST'])
def contributer():
    global state,district,pincode

    if request.method == 'POST':
        if 'user_name' in session:
            fname = request.form.get('fname')
            mobile = request.form.get('mobile')
            email = request.form.get('email')
            gender = request.form.get('gender')
            address = request.form.get('address')
            pincode = request.form.get('pincode')
            district = request.form.get('district')
            state = request.form.get('state')
            #print(fname,mobile,email,gender,address,pincode,district,state)

            ctr_data = Contributor_temporary_data(ctrname=fname, ctrmobile=mobile, ctremail=email, ctrgender=gender, ctraddress=address, ctrpincode=pincode, ctrdist=district, ctrstate=state)

            db.session.add(ctr_data)
            db.session.commit()
            return render_template('Become a Contributer.html')
        else:
            return "<h1> You are not allowed to enter.</h1>"
    return render_template('Become a Contributer.html')

    

    

    

# admin panel srarts here
@app.route('/admin_gram', methods=['GET','POST'])
def admin_gram():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('paswrd')

        if username == 'radeonuser' and password == 'inteli5user':
            session['user_name'] = username
            return render_template('admin_entry.html')
        
        else:
            return render_template('result_error_page.html')


    return render_template("admin_login.html")


#entry for admin main menu
@app.route('/admin_users_entry', methods=['GET','POST'])
def admin_users_entry():
    if 'user_name' in session:
        
        return render_template('admin_user_main_menu.html')
    
    else:
        return "<h1> You are not allowed to enter.</h1>"

#list of users
@app.route('/admin_user_table_show')
def admin_user_table_show():
    if 'user_name' in session:
        return render_template(" admin_user_table_show.html")
    
    else:
        return "<h1> You are not allowed to enter.</h1>"

    
#modification for users
@app.route('/admin_user_edit')
def admin_user_edit():
    if 'user_name' in session:
        gram_val = Registration.query.all()
        return render_template("search_admin.html", gram_val = gram_val)
    
    else:
        return "<h1> You are not allowed to enter.</h1>"


#graph representation for users
@app.route('/admin_user_graph')
def admin_user_graph():
    if 'user_name' in session:
        mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="serachproject"
            )

        mycursor = mydb.cursor()
        sql = "SELECT MONTHNAME(date_time) AS MNAME, COUNT(nid) AS TOTAL FROM registration GROUP BY MONTH(date_time)"
        mycursor.execute(sql)
        saved = mycursor.fetchall()
        for i in saved:
            date = i[0]
            val = i[1] 
        
        return render_template('admin_users_graph.html')
    
    else:
        return "<h1> You are not allowed to enter.</h1>"



#this is for adding user data from admin_user pannel
@app.route('/insert', methods=['GET','POST'])
def insert():
    if request.method == 'POST':
        if 'username' in session:
            name = request.form.get('cname')
            '''gender = request.form.get('gender')
            dob = request.form.get('dob')
            address = request.form.get('address')'''
            email = request.form.get('email')
            phone = request.form.get('phone')
            password = request.form.get('password')
            pw_hash2 = generate_password_hash(password, "sha256")
            my_data = Registration(cname=name, email=email, mobile=phone, password=pw_hash2)
            db.session.add(my_data)
            db.session.commit()

            flash("Record inserted Successfully")
            return redirect(url_for('admin_user_edit'))
        
        else:
            return "<h1> You are not allowed to enter.</h1>"

    return render_template("admin_login.html")



#this is for update data in admin_user pannel
@app.route('/edit/<int:nid>', methods=['POST','GET'])
def edit(nid):
    data = '0'
    if request.method == 'POST':
        if 'username' in session:
            name = request.form.get('cname')
            '''gender = request.form.get('gender')
            dob = request.form.get('birthdate')
            address = request.form.get('address')'''
            email = request.form.get('email')
            phone = request.form.get('mobile')
            

        

            data = Registration.query.filter_by(nid=nid).first()

            data.cname = name
            '''data.gender = gender
            data.birthdate = dob
            data.address = address'''
            data.email = email
            data.mobile = phone
            db.session.commit()
            flash("Data has been Edited Successfully")
            return redirect(url_for('admin_user_edit'))
        
        

    return render_template('search_admin.html', nid=nid, gram_val=data)



       

#this is for delete data from admin_user pannel          
@app.route("/delete/<int:nid>", methods = ['GET','POST'])
def delete(nid):
    if request.method == 'POST':
        if 'user_name' in session:
            mydb = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                database="serachproject"
                )

            mycursor = mydb.cursor()
            sql = "DELETE FROM registration WHERE nid = '%d' "% (nid)
            mycursor.execute(sql,(nid))
            mydb.commit()
    
            flash("Data has been deleted Successfully")
            return redirect(url_for('admin_user_edit'))
        
        else:
            return "<h1> You are not allowed to enter.</h1>"



#approval from admin
@app.route('/admin_approval', methods=['GET','POST'])
def admin_approval():
    if 'user_name' in session:

        temp_data = Contributor_temporary_data.query.all()
        

        strd_data = Contributor_data.query.all()
        

        return render_template('admin_approve_request.html', temp_data = temp_data, strd_data=strd_data)
        
            
    else:
        return "<h1> You are not allowed to enter.</h1>"


#approving request from admin
@app.route('/approve_request/<int:ctrid>', methods=['GET', 'POST'])
def approve_request(ctrid):
    if 'user_name' in session:
        val = Contributor_temporary_data.query.filter_by(ctrid=ctrid).all()
        for i in val:
            ctrname = i.ctrname
            ctrmobile = i.ctrmobile
            ctremail = i.ctremail
            ctrgender = i.ctrgender
            ctraddress = i.ctraddress
            ctrpincode = i.ctrpincode
            ctrdist = i.ctrdist
            ctrstate = i.ctrstate


        

        data = Contributor_data(cname=ctrname, cmobile=ctrmobile, cemail=ctremail, cgender=ctrgender, caddress=ctraddress, cpincode=ctrpincode, cdistrict=ctrdist, cstate=ctrstate)
        db.approvalsession.add(data)
        db.session.commit()


        
        

        return redirect(url_for('admin_approval')) 
    else:
        return"<h1>You are not allowed to enter.</h1>"


#deleting  from admin
@app.route('/delete_request/<int:ctrid>', methods=['GET', 'POST'])
def delete_request(ctrid):
    if 'user_name' in session:
        d = Contributor_temporary_data.query.get(ctrid)
        db.session.delete(d)
        db.session.commit()
    
        return redirect(url_for('admin_approval')) 


    else:
        return"<h1>You are not allowed to enter.</h1>"


#deleting approval from admin
@app.route('/delete_approve_request/<int:cid>', methods=['GET', 'POST'])
def delete_approve_request(cid):
    if 'user_name' in session:
        d = Contributor_temporary_data.query.get(cid)
        db.session.delete(d)
        db.session.commit()
    
        return redirect(url_for('admin_approval')) 


    else:
        return"<h1>You are not allowed to enter.</h1>"   


#entry for handling data
@app.route('/admin_data_entry', methods=['GET','POST'])
def admin_data_entry():
    if 'user_name' in session:
        return render_template("admin_data_value.html")
    
    else:
            return "<h1> You are not allowed to enter.</h1>"




#admin panel for data
@app.route('/admin_data_main_menu', methods=['GET', 'POST'])
def admin_data_main_menu():
    if 'user_name' in session:
        pincode = request.args.get('pincode')
        return render_template('admin_data_menu.html', pincode=pincode)
    
    else:
            return "<h1> You are not allowed to enter.</h1>"


@app.route('/admin_data_graph', methods=['GET', 'POST'])
def admin_data_graph():
    if 'user_name' in session:
        pincode = request.args.get('pincode')
        total_data = Store_details.query.filter_by(pincode=pincode).count()
        return render_template('admin_data_graph.html', pincode=pincode, total_data=total_data)

    else:
            return "<h1> You are not allowed to enter.</h1>"

#admin panel for data
@app.route('/admin_data_table_show', methods=['GET', 'POST'])
def admin_data_table_show():
    if 'user_name' in session:
        return render_template('admin_data_table_show.html')

    else:
            return "<h1> You are not allowed to enter.</h1>"


@app.route('/admin_data2', methods=['GET','POST'])
def admin_data2():
    if 'user_name' in session:
        pincode = request.args.get('pincode')

        val = Store_details.query.filter_by(pincode=pincode).first()
        locality = val.locality

        beauty = Store_details.query.filter_by(category='1', pincode =pincode)
        food = Store_details.query.filter_by(category='2', pincode =pincode)
        grocery = Store_details.query.filter_by(category='3',pincode =pincode)
        hotel = Store_details.query.filter_by(category='4',pincode =pincode)
        medical = Store_details.query.filter_by(category='5',pincode =pincode)
        places =  Store_details.query.filter_by(category='6',pincode =pincode)
        shopping =Store_details.query.filter_by(category='7',pincode =pincode)
        services =Store_details.query.filter_by(category='8',pincode =pincode)
        education = Store_details.query.filter_by(category='9',pincode =pincode)
        law = Store_details.query.filter_by(category='10',pincode =pincode)
        return render_template('admin_data_beauty_edit.html', beauty=beauty, food=food, grocery=grocery, hotel=hotel, medical=medical, shopping=shopping, services=services, places=places, education=education, law=law, pincode=pincode, locality=locality)


    else:
            return "<h1> You are not allowed to enter.</h1>"
    
    

#this is for adding data from admin_data panel
@app.route('/admin_data_add', methods=['GET','POST'])
def admin_data_add():
    if request.method == 'POST':
        if 'user_name' in session:
            typ = request.form.get('typ')
            st_name = request.form.get('st_name')
            description = request.form.get('description')
            street_name = request.form.get('street_name')
            pincode = request.form.get('pincode')
            place = request.form.get('place')
            locality = request.form.get('locality')
            dist = request.form.get('dist')
            state = request.form.get('state')
            phone = request.form.get('phone')
            opening = request.form.get('opening')
            closing = request.form.get('closing')
            category = request.form.get('category')
        

      

            admin_data = Store_details(typ=typ, st_name=st_name, description=description, street_name=street_name, pincode=pincode, place=place, locality=locality, dist=dist, state=state, phone=phone, opening=opening, closing=closing, category=category)
            db.session.add(admin_data)
            db.session.commit()
        
        
            return "data Added Successfully"
        
        else:
            return "<h1> You are not allowed to enter.</h1>"
            


#this is for update data in admin_data pannel
@app.route('/admin_data_edit/<int:st_id>', methods=['POST','GET'])
def admin_data_edit(st_id):
    if 'user_name' in session:
        data = '0'
        typ = request.form.get('typ')
        st_name = request.form.get('st_name')
        description = request.form.get('description')
        street_name = request.form.get('street_name')
        pincode = request.form.get('pincode')
        place = request.form.get('place')
        locality = request.form.get('locality')
        dist = request.form.get('dist')
        state = request.form.get('state')
        phone = request.form.get('phone')
        opening = request.form.get('opening')
        closing = request.form.get('closing')
        category = request.form.get('category')
        

        

        data = Store_details.query.filter_by(st_id=st_id)
        
        for i in data:
            i.typ = typ
            i.st_name = st_name
            i.description = description
            i.street_name = street_name
            i.pincode = pincode
            i.place = place
            i.locality = locality
            i.dist = dist
            i.street_name = street_name
            i.state = state
            i.phone = phone
            i.opening = opening
            i.closing = closing
            i.category = category
        


        db.session.commit()
        '''return render_template('admin_data_beauty_edit.html', st_id=st_id, beauty=data, food=data, grocery=data, hotel=data, medical=data, places=data, shopping=data, services=data, education=data, law=data )'''
        return "data edited Successfully"
       
    
    else:
        return "<h1> You are not allowed to enter.</h1>"
    
    

#this is for delete data from admin_data pannel          
@app.route("/admin_data_delete/<int:st_id>", methods = ['GET','POST'])
def admin_data_delete(st_id):
    if 'user_name' in session:
        data = Store_details.query.get(st_id)
        db.session.delete(data)
        db.session.commit()
        '''mydb = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="serachproject"
        )

        mycursor = mydb.cursor()
        sql = "DELETE FROM store_details WHERE  st_id= '%d' "% (st_id)
        mycursor.execute(sql,(st_id))
        mydb.commit()'''
    
        return "<h1>data has been deleted succcessfully.</h1>" 

    else:
        return "<h1> You are not allowed to enter.</h1>"
    



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS



#this is for upload images from admin section
@app.route('/admin_image_upload/<int:st_id>', methods=['GET', 'POST'])
def admin_image_upload(st_id):
    if 'user_name' in session:

        
        # check if the post request has the file part
        if 'file' not in request.files:
            print('No file part')
            return redirect(request.url)


        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename

        if file.filename == '':
            print('No selected file')
            return redirect(request.url)
        print("Filename bfore validation: ", file.filename)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.filename = st_id
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], str(st_id)))
            print(filename)
            return ('Uploaded Successfully')
        else:
            print("File Allowed", allowed_file(file.filename))
            return ('Upload Failed')
            
    

    else:
        return "<h1> You are not allowed to enter.</h1>"

    return render_template('upload.html')


@app.route('/admin_user_logout')
def admin_user_logout():
    session.pop('user_name', None)
    return redirect(url_for('admin_gram'))


@app.route('/admin_data_logout')
def admin_data_logout():
    session.pop('user_name', None)
    return redirect(url_for('admin_gram'))



if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
