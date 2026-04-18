#Libraries
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for

#Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s') #Logging format


#HTTP Logger
funnel_logger = logging.getLogger('HTTP Logger') #This is capture the username, password, and ip addresses.
funnel_logger.setLevel(logging.INFO) #Will provide the info logger. Different levels of logs will use info to get general information.
funnel_handler = RotatingFileHandler('http_audits.log',maxBytes=2000, backupCount=5) #Set the log file, max size, and backup count.
funnel_handler.setFormatter(logging_format) #Set the format to the funnel handler.
funnel_logger.addHandler(funnel_handler) #Add all this to our funnler_logger object in the beginning.


#Baseline Honeypot

def web_honeypot(input_username='admin', input_password='password'):
    
    app = Flask(__name__)

    @app.route('/') #Default root route

    def index():
        return render_template('wp-admin.html') #Return wp admin html template.

    @app.route('/wp-admin-login', methods=['POST']) #User can only use post method to interact with web page.

    def login():
        username = request.form['username'] #Get username from form.
        password = request.form['password'] #Get password from form.

        ip_address = request.remote_addr #Get IP address of user.

        #When username and password are entered log it.
        funnel_logger.info(f'Client with IP Address: {ip_address} entered\n Username: {username}, Password: {password}')

        #Redirect user

        if username == input_username and password == input_password:
            return 'DEEBOODAH'
        else:
            return 'Invalid username or password. Please try again.'
        
    return app

#Enable capabillity of running the web honeypot.
def run_web_honeypot(port=5000, input_username='admin', input_password='password'):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    run_web_honeypot_app.run(debug=True, port=port, host='0.0.0.0')

    return run_web_honeypot_app
    
#run_web_honeypot(port=5000, input_username='admin', input_password='password')