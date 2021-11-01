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
    #host = request.form['host']
    arg = None
    if mode == 'i':
        arg = request.form['ip']
    else:
        arg = request.form['file']
    time = request.form['time']
    out = request.form['out']
    
    #render_template('index.html', arg=arg)
    print(f'received {mode}, {log}, {arg}, {time}, {out}')
    run_startup(mode, log, '10.0.1.22', arg, time, out) # specifies IP of node-02 for hosting agent

    return render_template('index.html', done='done')