from flask import Flask, render_template, url_for, redirect
from gpiozero import LED
from time import sleep

app=Flask(__name__)

led = LED(14)

@app.route("/")
def hello():
    name = "Semutenga"
    return render_template("index.html", name=name)

@app.route("/yaka")
def yaka():
    led.on()
    return redirect(url_for('hello'))

@app.route("/vaako")
def vaako():
    led.off()
    return redirect(url_for('hello'))

	
