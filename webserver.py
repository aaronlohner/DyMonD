from flask import Flask, render_template, request
from flask.helpers import make_response
import requests
from controller import run_startup

app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/inputs", methods=['POST'])
def recv_client_inputs():
    mode = request.form['mode']
    arg = None
    if mode == 'i':
        arg = request.form['ip']
    else:
        arg = request.form['file']
    payload = {'mode':mode,
               'log':request.form['log'],
               'host':'10.0.1.22', # specifies IP of node-02 for hosting agent
               'arg':arg,
               'time':request.form['time'],
               'out':request.form['out']}
    r = requests.get('http://bmj-cluster.cs.mcgill.ca:13680/run', params=payload)
    
    print(r.json())
    #render_template('index.html', arg=arg)

    return render_template('index.html', done='done')

@app.route("/run", methods=['GET'])
def run():
    mode, log, host, arg, time, out = request.args.values()
    time = int(time)
    json_obj = run_startup(mode, log, host, arg, time, out)
    return json_obj
