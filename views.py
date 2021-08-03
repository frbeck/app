from flask_cors import cross_origin
from application import app
from flask import jsonify
app.config['CORS_HEADERS'] = 'Content-Type'


@app.route("/")
@cross_origin()
def index():
  return jsonify({"message": "Hello"})
