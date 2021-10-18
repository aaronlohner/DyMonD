from flask import Flask, render_template, request
#import os.path as osp

# dirname = osp.dirname(__file__)
# html_path = osp.join(dirname, '..', 'web')
app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/inputs", methods=['POST'])
def recv_client_inputs():
    mode = request.form['mode']
    log = request.form['log']
    arg = None
    if mode == 'i':
        arg = request.form['ip']
    else:
        arg = request.form['file']
    time = request.form['time']
    app = request.form['app']
    out = request.form['out']

    print(f'received {mode}, {log}, {arg}, {time}, {app}, {out}')
    return render_template('index.html', arg=arg)

    #PUT THIS BACK INTO INDEX.HTML
    #http://bmj-cluster.cs.mcgill.ca:15490