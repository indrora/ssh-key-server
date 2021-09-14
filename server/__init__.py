import flask
from flask.helpers import url_for
from flask import render_template
# commented out since I'm currently on windows
# import pam
import pyotp
import os
import tinydb
import qrcode
from io import BytesIO,StringIO
import datetime
import encodings.utf_8 as utf8

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = flask.Flask(__name__)
app.secret_key = pyotp.random_base32()

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

db_path = os.getenv("SSH_KEY_DB_PATH", "./ssh-key-db.json")

db = tinydb.TinyDB(os.path.realpath(db_path))
user_table = db.table("users")
key_table = db.table("keys")


#
# A very simple homepage. Technically static, but it's useful to have a home route.
#
@app.route("/")
def home():
    return flask.render_template("index.html")


#
# Enroll a user in using OTP/time gated keys.
#
@app.route("/enroll/", methods=["GET", "POST"])
def enroll():
    # if we're just GETing the page, return an empty login form.
    if flask.request.method == "GET":
        return flask.render_template("user_enroll.html")
    # ignore auth since I'm on windows....
    # Otherwise, try and authenticate
    # p = pam.pam()
    # Get the authentication from the user
    username = flask.request.form["username"]
    password = flask.request.form["password"]
    # Verify the credentials are correct
    valid = True # p.authenticate(username, password)
    if valid:
        # Check if the user has already enrolled
        if user_table.contains(tinydb.Query().name == username):
            return flask.abort(403)
        # Generate a secret, save it
        otp_secret = pyotp.random_base32()
        user_table.insert({"name":username, "otp":otp_secret})
        flask.flash(f"{username}:{otp_secret}",'otp')
        return flask.render_template("user_enroll_finish.html",secret=otp_secret)
    else:
        # Tell the user that something happened. 
        return render_template("register.html", error="p.reason")

# This is being lazy
# Return the QR code flashed by the login
@app.route("/enroll/qr.png")
def get_flash_qr():
    otp_flashes = flask.get_flashed_messages(category_filter=['otp'])
    if len(otp_flashes) == 0:
        return flask.abort(404)
    
    user,key = otp_flashes[0].split(":")
    
    t = pyotp.TOTP(key)
    uri = t.provisioning_uri(user, "SSH Keys")
    q = qrcode.make(uri)
    img = BytesIO()
    q.save(img, 'PNG')
    img.seek(0)
    return flask.send_file(img,mimetype="image/PNG")

# Request and generate a key pair, then return it to the client.
@app.route("/keys/get", methods=["GET","POST"])
@limiter.limit("1/minute",exempt_when=lambda: not "application/x-pem-file" in flask.request.accept_mimetypes.values())
def request_key():
    if flask.request.method == "GET":
        return flask.render_template("key_request.html")

    # Get the input values
    username = flask.request.form["username"]
    otp_value = flask.request.form["otp"]

    # Does that user exist?
    if not user_table.contains(tinydb.Query().name == username):
        return flask.abort(403)
    
    # Get the user
    user = user_table.get(tinydb.Query().name == username)
    
    # Verify the TOTP
    otp = pyotp.TOTP(user["otp"])
    if not otp.verify(otp_value):
        if "application/x-pem-file" in flask.request.accept_mimetypes.values():
            return "",403
        else:
            return flask.render_template("key_request.html", error="OTP failed")
    
    # Generate an expiry timestamp
    expires = datetime.datetime.now() + datetime.timedelta(minutes=30)

    # Generate an ECC SSH key
    from Crypto.PublicKey import ECC

    key = ECC.generate(curve='p384')

    # Create the private and public key parts as strings
    key_pem =  key.export_key(format="PEM") 
    key_ssh = key.public_key().export_key(format="OpenSSH").strip()


    # Add the public portion to the table, plus its expiry
    key_table.insert({
        "user": username,
        "expires": expires.timestamp(),
        "line": key_ssh,
    })

    # If we were asked to have a private key sent direct, do so
    if "application/x-pem-file" in flask.request.accept_mimetypes.values():
        return key_pem
    # Otherwise, use flask flash messages to shuffle the private key into the next request
    else:
        flask.flash(key_pem,"keys")

        return render_template("key_request_finish.html", pubkey=key_ssh)

# This just returns the last private key as a file.
@app.route("/keys/finished")
def get_key_flash():
    # Get key to flash
    flash = flask.get_flashed_messages(category_filter=["keys"])[0]
    return flask.send_file(BytesIO(flash.encode("utf-8")),mimetype="text/plain",attachment_filename="id_ecc",as_attachment=True)
    

#  List the keys for a user. 
# When requesting a mimetype of application/x-authorized-keys, return only non-expired keys. 
@app.route("/keys/list")
def list_keys():
    # Are we looking for text or HTML.
    username = flask.request.args.get('username', "")

    if "application/x-authorized-keys" in flask.request.accept_mimetypes.values():
        # return valid keys for the user
        if username == "":
            return "" # Don't bother looking up users, just return an empty string.
        key = tinydb.Query()

        keys = key_table.search(key.user == username)
        # A buffer to hold things in
        ret = StringIO()
        for k in keys:
            # Parse the expiry time, and if it's not expired, put it in the output. 
            expiry = datetime.datetime.fromtimestamp(k["expires"])
            if expiry > datetime.datetime.now():
                ret.write(k["line"]+f" expires {expiry.isoformat()}\n")
        
        return ret.getvalue()

    else:
        # list all keys from that user. 
        # if no username is specified, no keys will be returned
        keys = key_table.search(tinydb.Query().user == username)
        return render_template("user_keys.html", username=username, keys=keys)
