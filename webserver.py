import os.path as osp
import webbrowser
import json
import requests
from flask import Flask, render_template, request, redirect, url_for
from controller import run_startup

app = Flask(__name__)
app.config["DEBUG"] = True
chrome_path = 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s'

@app.route("/")
def index():
    return redirect(url_for('inputs'))

# UI webserver
@app.route("/inputs", methods=['GET', 'POST'])
def inputs():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        mode = request.form['mode']
        arg = None
        if mode == 'i':
            arg = request.form['ip']
        else:
            arg = request.form['file']
        payload = {'mode':mode,
                'log': '*', #request.form['log'],
                'host':'10.0.1.22', # specifies IP of node-02 for hosting agent
                'arg':arg,
                'time':request.form['time'],
                'out':request.form['out']}
        r = requests.get('http://bmj-cluster.cs.mcgill.ca:13680/run', params=payload)
        import time; time.sleep(2)
        json_str = json.dumps(r.json(), indent = 4)
        with open(osp.join("json", request.form['out']), "w") as output:
            output.write(json_str)
        webbrowser.get(chrome_path).open("file://"+ osp.realpath(osp.join("webvowl1.1.7SE", "index.html")), new=2)
        return render_template('index.html', completed="Sniffing completed.")

# Controller webserver
@app.route("/run", methods=['GET'])
def run():
    mode, log, host, arg, time, out = request.args.values()
    time = int(time)
    json_obj = run_startup(mode, log, host, arg, time, out)
    return json_obj
