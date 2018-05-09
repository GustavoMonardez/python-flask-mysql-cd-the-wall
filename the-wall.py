from flask import Flask, render_template, redirect, request, flash, session
from flask_bcrypt import Bcrypt  
import re
# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key = "secret"
bcrypt = Bcrypt(app)
# invoke the connectToMySQL function and pass it the name of the database we're using
# connectToMySQL returns an instance of MySQLConnection, which we will store in the variable 'mysql'
mysql = connectToMySQL('walldb')
# now, we may invoke the query_db method
# print("all the users", mysql.query_db("SELECT * FROM users;"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    # capture data
    fname = request.form["fname"]
    lname = request.form["lname"]
    email = request.form["email"]
    password = request.form["password"]
    cpassword = request.form["cpassword"]    
    # check for empty fields
    count = is_blank(fname,lname,email,password,cpassword)    
    if count > 0:
        return redirect("/")
    # validate fields
   
    if not validate_data(fname,lname,email,password,cpassword):
        return redirect("/")
    # check if account already registered
    check_email = "select * from users where email=%(email)s"
    email_data = {"email":email}
    result = mysql.query_db(check_email, email_data)
    print(result)
    if result:
        flash("Account already exists. Did you mean to log in?")
        return redirect("/")
    # hash password
    password = bcrypt.generate_password_hash(password)  
    #insert data in database
    query = "insert into users(first_name,last_name,email,password) values(%(fname)s,%(lname)s,%(email)s,%(password)s);"
    data = {"fname":fname,"lname":lname,"email":email,"password":password}
    result = mysql.query_db(query, data)
    # welcoming messages
    query = "select id from users where email=%(email)s"
    data = {"email":email}
    result = mysql.query_db(query, data)
    print("id: ", result)
    session["userid"] = result[0]["id"]
    session["username"]  = fname
    flash("You've been successfully registered")
    #redirect to success page
    return redirect("/wall")

@app.route("/login", methods=["POST"])
def login():
    # capture data
    email = request.form["email"]
    password = request.form["password"]
    # check if user exists
    query = "select * from users where email = %(email)s;"
    data = { "email" : email }
    result = mysql.query_db(query, data)
    print(result)
    if result:
        if bcrypt.check_password_hash(result[0]["password"], password):
            session["userid"] = result[0]["id"]
            session["username"] = result[0]["first_name"]
            return redirect("/wall")
    # either password or user name is incorrect
    flash("You could not be logged in")
    return redirect("/")

@app.route("/wall")
def wall():
    if "userid" not in session:
        flash("You must be logged in to access this page")
        return redirect("/")
    #query = "select first_name, last_name, messages.id, messages.message, messages.created_at from users join messages on messages.user_id = users.id where users.id=%(user_id)s;"
    data = {"user_id": session["userid"]}
    query = "select first_name, last_name, messages.id, messages.message, date_format(messages.created_at, '%M %D %Y') as created_at from users join messages on messages.user_id = users.id order by messages.created_at desc;"
    result = mysql.query_db(query)

    #query = "select first_name, last_name, messages.id, comments.comment, comments.created_at from users join comments on comments.user_id = users.id join messages on messages.user_id = users.id where users.id=%(user_id)s and messages.id=comments.message_id;"

    query = "select first_name, last_name, messages.id, comments.comment, date_format(comments.created_at, '%%M %%D %%Y') as created_at from users join comments on comments.user_id = users.id join messages on messages.id = comments.message_id;"

    comments =  mysql.query_db(query,data)
    print("comments98:",comments)
    return render_template("wall.html", result=result, comments=comments)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")

@app.route("/message", methods=["POST"])
def message():
    msg = request.form["message"]
    query = "insert into messages(user_id, message) values(%(user_id)s, %(message)s); "
    data = {"user_id":session["userid"], "message":msg}
    mysql.query_db(query, data)
    return redirect("/wall")

@app.route("/comment", methods=["POST"])
def comment():
    comment = request.form["comment"]
    message_id = request.form["message_id"]
    query = "insert into comments(comment,message_id,user_id) values(%(comment)s, %(message_id)s, %(user_id)s);"
    data = {"comment": comment, "message_id":message_id,"user_id":session["userid"]}
    mysql.query_db(query, data)
    #print(comment)
    #print("m_id: ", request.form["message_id"])
    return redirect("/wall")

def validate_data(fname,lname,email,password,cpassword):
    # check first and last names contain only letters
    if not fname.isalpha():
        flash("first name cannot contain numbers")
        return False
    if not lname.isalpha():
        flash("last name cannot contain numbers")
        return False
    # check first and last names are at least 2 characters long
    if len(fname) < 2:
        flash("first name must contain at least  characters")
        return False
    if len(lname) < 2:
        flash("last name must contain at least  characters")
        return False
    # check password length at least 8 characters long
    if len(password) < 8:
        flash("password has to be at least 8 characters long")
        return False
    # email validation
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if len(email) < 1:
        flash("Email cannot be blank!")
        return False
    elif not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!")
        return False
    # password match
    if password != cpassword:
        flash("password must match")
        return False
    return True

def is_blank(fname,lname,email,cpassword,password):
    count = 0
    if len(fname) < 1:
        flash("first name is required")
        count +=1
    if len(lname) < 1:
        flash("last name is required")
        count +=1
    if len(email) < 1:
        flash("email is required")
        count +=1
    if len(password) < 1:
        flash("password is required")
        count +=1
    if len(cpassword) < 1:
        flash("confirm password is required")
        count +=1
    return count

if __name__ == "__main__":
    app.run(debug=True)