import jwt
import datetime
from functools import wraps
from flask import Flask, make_response, request, jsonify


app = Flask(__name__)

# this will be used during decoding
app.config['SECRET_KEY'] = 'jwt_secret_key'


def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		# http://127.0.0.1:5000/route?token=<token>
		# http://localhost:5000/protected?token=<token>
		token = request.args.get('token')

		if not token:
			return jsonify({'message': 'Token is missing!'}), 403
		
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'])
		except:
			return jsonify({'message': 'Token is invalid!'}), 403

		return f(*args, **kwargs)

	return decorated

@app.route('/unprotected')
def unproceted():
	return jsonify({'message': 'Anyone can view this!'})

@app.route('/protected')
@token_required
def protected():
	return jsonify({'message': 'This is only available for people with vaid tokesn.'})

@app.route('/login')
def login():
	auth = request.authorization
	if auth and auth.password == 'password':
		token = jwt.encode(
			{
				"user": auth.username,
				"exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # key must be `exp`
			},
			app.config['SECRET_KEY'],
		)
		return jsonify({'token': token.decode('UTF-8')})


	return make_response('Could not verify!', 401, {'WWW-Authenticate': 'BAsic realm="login Required"'})


if __name__ == '__main__':
	app.run(debug=True)