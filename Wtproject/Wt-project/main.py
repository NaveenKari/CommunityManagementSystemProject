
from sqlite3 import Time
from flask import Flask,render_template,request,session,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import false
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager,login_required,current_user
import datetime

local_server = True
app= Flask(__name__)
app.secret_key='akash'


app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:@localhost/cms'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Owner(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(100))
    communityname=db.Column(db.String(100))
    phoneno=db.Column(db.String(10))
    password=db.Column(db.String(1000))

class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    communityname=db.Column(db.String(100))
    phoneno=db.Column(db.String(10))
    password=db.Column(db.String(1000))
    flatno=db.Column(db.Integer)
    username=db.Column(db.String(100))

class Theatre(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    communityname=db.Column(db.String(100))
    date=db.Column(db.String(50),nullable=False)
    name=db.Column(db.String(50))
    purpose=db.Column(db.String(1000))

class Banquet(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    communityname=db.Column(db.String(100))
    date=db.Column(db.String(50),nullable=False)
    name=db.Column(db.String(50))
    purpose=db.Column(db.String(1000))

class Dance(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    communityname=db.Column(db.String(100))
    date=db.Column(db.String(50),nullable=False)
    name=db.Column(db.String(50))
    purpose=db.Column(db.String(1000))

class Postrequest(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50))
    occupation=db.Column(db.String(100))
    visit=db.Column(db.String(1000))
    flatno=db.Column(db.Integer)
    date=db.Column(db.String(50))
    time=db.Column(db.String(50))

class Dailyservice(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50))
    area=db.Column(db.String(200))
    work=db.Column(db.String(1000))
    phoneno=db.Column(db.String(12))

class Security(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(100))
    gateno=db.Column(db.String(11))
    email=db.Column(db.String(100))
    password=db.Column(db.String(200))

class Notice(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(1000))
    description=db.Column(db.String(2000))

class requests(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50))
    visit=db.Column(db.String(1000))
    flatno=db.Column(db.Integer)
    date=db.Column(db.String(50))
    time=db.Column(db.String(50))
    status=db.Column(db.String(100))

class Userrequests(db.Model):
    pid=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(50))
    purpose=db.Column(db.String(100))
    flatno=db.Column(db.Integer)
    date=db.Column(db.String(50))
    time=db.Column(db.String(50))
    status=db.Column(db.String(100))

@app.route('/')
def introduction():
    return render_template('introduction.html')
@app.route('/ownerregister',methods=['POST','GET'])
def ownerregister():
    if request.method=="POST":
        email=request.form.get('Email')
        number=request.form.get('number')
        cname=request.form.get('Cname')
        pas=request.form.get('Password')
        user=Owner.query.filter_by(email=email).first()
        if user:
            flash("email already exists","Warning" )
            return render_template('ownerregister.html')
        new=db.engine.execute(f"INSERT INTO `owner`(`email`,`phoneno`,`communityname`,`password`) VALUES ('{email}','{number}','{cname}','{pas}');")
        return render_template('ownerlogin.html')
    else:
        return render_template('ownerregister.html')
@app.route('/memberlogin',methods=['POST','GET'])
def login():
    if request.method=="POST":
        email=request.form.get('username')
        pas=request.form.get('pass')
        fno=request.form.get('fno')
        cm=request.form.get('cm')
        user=User.query.filter_by(username=email).first()
        if user and user.password==pas and user.flatno==int(fno) and user.communityname==cm:
            session['p']=fno
            login_user(user)
            return redirect(url_for('residenthome',email=email))
        else:
            flash("Enter correct credentials")
            return render_template('memberlogin.html')
    return render_template('memberlogin.html')
@app.route('/ownerlogin',methods=['GET','POST'])
def ownerlogin():
    if request.method=="POST":
        email=request.form.get('username')
        pas=request.form.get('pass')
        user=Owner.query.filter_by(email=email).first()
        if user and user.password==pas:
            p=int(user.pid)
            session['user']=user.communityname
            return redirect(url_for("ownerhomepage"))
        else:
            flash("enter correct credentials")
            return render_template('ownerlogin.html')
    return render_template('ownerlogin.html')
@app.route('/residenthome')
@login_required
def residenthome():
    e=current_user.flatno
    query=db.engine.execute(f"SELECT * FROM `user` WHERE `flatno`={e}")
    return render_template('login.html',query=query)

@app.route('/booking',methods=['POST','GET'])
@login_required
def booking():
    if request.method=="POST":
        amenity=request.form.get('amenity')
        date=request.form.get('date')
        name=request.form.get('name')
        phoneno=request.form.get('no')
        user=User.query.filter_by(phoneno=phoneno).first()
        purpose=request.form.get('purpose')
        k=db.engine.execute(f"SELECT `name` from `{amenity.lower()}` WHERE `date`={date} and `communityname`='{user.communityname}'")
        t=None
        if k==None:
            flash("Booking confirmed")
            db.engine.execute(f"INSERT INTO `{amenity.lower()}`(`name`,`communityname`,`date`,`purpose`) VALUES('{name}','{user.communityname}','{date}','{purpose}');")
            return render_template('booking.html')
        else:
            flash("Book another date")
    return render_template('booking.html')
@app.route('/postrequest',methods=['POST','GET'])
def postrequest():
    if 'security' in session:
        if request.method=="POST":
            name=request.form.get('name')
            occupation=request.form.get('occupation')
            visit=request.form.get('visitpurpose')
            fno=request.form.get('flatnumber')
            k=datetime.datetime.now()
            r=k.strftime("%d-%m-%Y")
            x=k.strftime("%H:%M:%S")
            db.engine.execute(f"INSERT INTO `postrequest`(`name`,`occupation`,`visit`,`flatno`,`date`,`time`) VALUES('{name}','{occupation}','{visit}','{fno}','{r}','{x}');")
            return render_template('postrequest.html')
    else:
        return(redirect(url_for('securitylogin')))
    return render_template('postrequest.html')
@app.route('/userrequests',methods=['POST','GET'])
@login_required
def userrequests():
    em=current_user.flatno
    query=db.engine.execute(f"SELECT * FROM `postrequest` WHERE flatno='{em}' ORDER BY `pid` DESC")
    #t=db.engine.execute(f"Select Convert('{time}','CURTIME')")
    return render_template('userrequests.html',query=query)
@app.route('/dailyvendorsupload',methods=['POST','GET'])
def dailyvendorsupload():
    if 'user' in session: 
        if request.method=="POST":
            name=request.form.get('name')
            area=request.form.get('area')
            work=request.form.get('work')
            number= request.form.get('number')
            cmname=request.form.get('cmname')
            db.engine.execute(f"INSERT INTO `dailyservice`(`name`,`area`,`work`,`phoneno`,`cmname`) VALUES('{name}','{area}','{work}','{number}','{cmname}');")
            return render_template('dailyvendorsupload.html')
    else:
        return redirect(url_for('ownerlogin'))
    return render_template('dailyvendorsupload.html')

@app.route('/residentupload',methods=['POST','GET'])
def residentupload():
    if 'user' in session: 
        if request.method=="POST":
            #print(session)
            name=request.form.get('name')
            username=request.form.get('username')
            flatno=request.form.get('flatno')
            pas=request.form.get('pass')
            cmname=request.form.get('cmname')
            number=request.form.get('number')
            db.engine.execute(f"INSERT INTO `user`(`username`,`flatno`,`password`,`communityname`,`phoneno`) VALUES('{username}','{flatno}','{pas}','{cmname}','{number}');")
            return render_template('residentupload.html')
    else:
        return redirect(url_for('ownerlogin'))
    return render_template('residentupload.html')

@app.route('/securityupload',methods=['POST','GET'])
def securityupload():
    if 'user' in session:
        if request.method=="POST":
            name=request.form.get('name')
            gate=request.form.get('gate')
            email=request.form.get('email')
            pas=request.form.get('pass')
            db.engine.execute(f"INSERT INTO `security`(`name`,`gateno`,`email`,`password`) VALUES ('{name}','{gate}','{email}','{pas}');")
            return render_template('securityupload.html')
    else:
        return redirect(url_for('ownerlogin'))
    return render_template('securityupload.html')

@app.route('/ownerhomepage',methods=['POST',"GET"])
def ownerhomepage():
    if 'user' in session:
        if request.method=="POST":
            f=request.form.get('dailyvendors')
            if f=="boy":
                return redirect(url_for('dailyvendorsupload'))
            elif request.form.get('resident')=="hi":
                return redirect(url_for('residentupload'))
            elif request.form.get('security')=="bye":
                return redirect(url_for('securityupload'))
            elif request.form.get('logout')=="lol":
                return redirect(url_for('ownerlogout'))
        return render_template('ownerhomepage.html')
    else:
        return redirect(url_for('ownerlogin'))
    
@app.route('/notice')
@login_required
def notice():
    query=db.engine.execute(f"SELECT * FROM `notice` ORDER BY pid DESC;")
    return render_template('notice.html',query=query)

@app.route('/requests/<string:pid>',methods=['POST','GET'])
@login_required
def requests(pid):
    post=Postrequest.query.filter_by(pid=pid).first()
    s="accepted"
    db.engine.execute(f"INSERT INTO `requests`(`name`,`flatno`,`visit`,`time`,`date`,`status`) VALUES ('{post.name}','{post.flatno}','{post.visit}','{post.time}','{post.date}','{s}');")
    db.engine.execute(f"DELETE FROM `postrequest` WHERE `postrequest`.`pid`={post.pid}")
    query=db.engine.execute(f"SELECT * FROM `requests` WHERE `flatno`={post.flatno}")
    return render_template('requests.html',query=query)
        
@app.route('/requests1/<string:pid>',methods=['POST','GET'])
@login_required
def requests1(pid):
    post=Postrequest.query.filter_by(pid=pid).first()
    s="rejected"
    db.engine.execute(f"INSERT INTO `requests`(`name`,`flatno`,`visit`,`time`,`date`,`status`) VALUES ('{post.name}','{post.flatno}','{post.visit}','{post.time}','{post.date}','{s}');")
    db.engine.execute(f"DELETE FROM `postrequest` WHERE  `postrequest`.`pid`={post.pid}")
    query=db.engine.execute(f"SELECT * FROM `requests` WHERE `flatno`={post.flatno}")
    return render_template('requests.html',query=query)

@app.route('/requests')
@login_required
def requests4():
    query=db.engine.execute(f"SELECT * FROM `requests` WHERE `flatno`='{current_user.flatno}' ORDER BY `pid` DESC")
    return render_template('requests.html',query=query)    
@app.route('/profile')
@login_required
def profile():
    e=current_user.flatno
    query=db.engine.execute(f"SELECT * FROM `user` WHERE `flatno`={e}  ")
    return render_template('profile.html',query=query)

@app.route('/securitylogin',methods=['POST','GET'])
def securitylogin():
    if request.method=="POST":
        email=request.form.get('username')
        pas=request.form.get('pass')
        user=Security.query.filter_by(email=email).first()
        if user and user.password==pas:
            session['security']=user.name
            return redirect(url_for('securityhome'))
        else:
            flash("enter correct credentials")
            return render_template('securitylogin.html')
    return render_template('securitylogin.html')

@app.route('/securityhome',methods=['POST','GET'])
def securityhome():
    if 'security' in session:
        if request.method=="POST":
            if request.form.get('pr')=="pr":
                return redirect(url_for('postrequest'))
            elif request.form.get('re')=="re":
                return redirect(url_for('request3'))
            elif request.form.get('lg')=='lg':
                return redirect(url_for('securitylogout'))
            elif request.form.get('res')=='res':
                return redirect(url_for('requests5'))
            
        return render_template('securityhome.html')
    else:
        return redirect(url_for('securitylogin'))

@app.route('/requests3')
def request3():
    if 'security' in session:
        k=datetime.datetime.now()
        r=k.strftime("%d-%m-%Y")
        query=db.engine.execute(f"SELECT * FROM `requests` WHERE `date`='{r}' ORDER BY `pid` DESC")
        return render_template('requests3.html',query=query)
    else:
        redirect(url_for('securitylogin'))

@app.route('/dailyservices',methods=['POST','GET'])
@login_required
def dailyservices():
    if request.method=="POST":
        k=request.form.get('s1')
        query=db.engine.execute(f"SELECT * FROM `dailyservice` WHERE `cmname`='{current_user.communityname}' AND `work`='{k}';")
        return render_template('dailyservices1.html',query=query,work=k)
    return render_template('dailyservices.html')
@app.route('/dailyservices1')
@login_required
def dailyservices1():
    return render_template('dailyservices1.html')
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/ownerlogout')
def ownerlogout():
    session.pop("user",None)
    return redirect(url_for('ownerlogin'))
    
@app.route('/securitylogout')
def securitylogout():
    session.pop('security',None)
    return redirect(url_for('securitylogin'))

@app.route('/residentrequest',methods=['GET','POST'])
@login_required
def residentrequest():
    if request.method=="POST":
        name=request.form.get('name')
        fno=session['p']
        purpose=request.form.get('purpose')
        date=request.form.get('date')
        time=request.form.get('time')
        status="aceepted"
        query=db.engine.execute(f"INSERT INTO `userrequests`(`name`,`flatno`,`purpose`,`date`,`time`,`status`) VALUES('{name}','{fno}','{purpose}','{date}','{time}','{status}')")
        db.engine.execute(f"INSERT INTO `requests`(`name`,`flatno`,`visit`,`time`,`date`,`status`) VALUES ('{name}','{fno}','{purpose}','{time}','{date}','{status}');")
        flash("Updated succesfully")
    return render_template('residentrequest.html')

@app.route('/requests5')
def requests5():
    if 'security' in session:
        k=datetime.datetime.now()
        r=k.strftime("%Y-%m-%d")
        print(r)
        query=db.engine.execute(f"SELECT * FROM `userrequests` WHERE `date`='{r}' ORDER BY `pid` DESC")
        post=Userrequests.query.filter_by(date=r).first()
        print(post.name)
        return render_template('requests5.html',query=query)
    else:
        redirect(url_for('securitylogin'))


app.run(debug=True)
















