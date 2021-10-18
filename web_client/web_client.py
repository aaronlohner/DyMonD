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
    ip = request.form['ip']
    time = request.form['time']
    mode = request.form['mode']
    print(f'received {ip}, {time}, {mode}')
    return render_template('index.html', ip=ip)

    #PUT THIS BACK INTO INDEX.HTML
    #http://bmj-cluster.cs.mcgill.ca:15490