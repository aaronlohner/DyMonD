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
    print(f'received {ip}, {time}')
    return render_template('controller.html', ip=ip, time=time)