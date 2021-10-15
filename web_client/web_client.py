from flask import Flask, render_template#, request
#import os.path as osp

# dirname = osp.dirname(__file__)
# html_path = osp.join(dirname, '..', 'web')
app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')