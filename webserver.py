from flask import Flask, render_template, request
from controller import run_startup

app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/inputs", methods=['POST'])
def recv_client_inputs():
    mode = request.form['mode']
    log = request.form['log']
    host = request.form['host']
    arg = None
    if mode == 'i':
        arg = request.form['ip']
    else:
        arg = request.form['file']
    time = request.form['time']
    app = request.form['app']
    out = request.form['out']
    
    #render_template('index.html', arg=arg)
    print(f'received {mode}, {log}, {host}, {arg}, {time}, {app}, {out}')
    run_startup(mode, log, host, arg, time, app, out)

    return render_template('index.html', done='done')