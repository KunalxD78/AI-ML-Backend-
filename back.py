from flask import Flask,render_template,request
app = Flask(__name__)

@app.route('/',methods = ["GET"])
def welcome():
    return "<h1>The Flask is Running!!</h1>"

@app.route('/index',methods = ["GET"])
def index():
    return "<h2>Welcome to the Index page!!!</h2>"


@app.route('/success/<int:score>')
def success(score):
    return "The Person has passed and the score is: "+ str(score)

@app.route('/fail/<int:score>')
def fail(score):
    return "The Person has failed and the score is: "+ str(score)

@app.route('/form',methods=["GET","POST"])
def form():
    if request.method=="GET":
        return render_template('form.html')
    else: 
        maths = float(request.form['maths'])
        science = float(request.form['science'])
        history = float(request.form['history'])

        average_marks = (maths+science+history)/3

        return render_template('form.html',scope=average_marks)
    


    


if __name__ == '__main__':
    app.run(debug=True)













