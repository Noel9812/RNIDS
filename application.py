from flask_socketio import SocketIO, emit
from flask import jsonify  # <-- Add this to existing Flask imports
from flask import Flask, render_template, redirect, url_for, request, session, flash
from random import random
from time import sleep
from threading import Thread, Event
import os
import time
import atexit

import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin.firestore import SERVER_TIMESTAMP
from datetime import datetime, timedelta
from firebase_config import (
    firestore_db, create_user_session, update_global_stats, 
    hash_password, verify_password, get_user_by_username,save_malicious_flow, increment_high_risk_count
)
from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import numpy as np
import pickle
import csv 
import traceback

import json
import pandas as pd

from scipy.stats import norm

import ipaddress
from urllib.request import urlopen

from tensorflow import keras

from lime import lime_tabular

import dill

import joblib

import plotly
import plotly.graph_objs

import warnings
warnings.filterwarnings("ignore")

def ipInfo(addr=''):
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url, timeout=5)  # Added timeout
        data = json.load(res)
        return data.get('country', None)  # Using get() with default
    except Exception:
        return None

__author__ = 'rnids'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'secret!')  # Added env var support
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

# Enable CORS for Flask app
from flask_cors import CORS
CORS(app)




# Turn the Flask app into a SocketIO app
socketio = SocketIO(app, async_mode=None, logger=True, engineio_logger=True, cors_allowed_origins="*")

# Random result Generator Thread
thread = Thread()
thread_stop_event = Event()

f = open("output_logs.csv", 'w')
w = csv.writer(f)
f2 = open("input_logs.csv", 'w')
w2 = csv.writer(f2)

# Add file cleanup
def cleanup_files():
    if not f.closed:
        f.close()
    if not f2.closed:
        f2.close()

atexit.register(cleanup_files)

cols = ['FlowID',
'FlowDuration',
'BwdPacketLenMax',
'BwdPacketLenMin',
'BwdPacketLenMean',
'BwdPacketLenStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets_s',
'MaxPacketLen',
'PacketLenMean',
'PacketLenStd',
'PacketLenVar',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AvgPacketSize',
'AvgBwdSegmentSize',
'InitWinBytesFwd',
'InitWinBytesBwd',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin',
'Src',
'SrcPort',
'Dest',
'DestPort',
'Protocol',
'FlowStartTime',
'FlowLastSeen',
'PName',
'PID',
'Classification',
'Probability',
'Risk']

ae_features = np.array(['FlowDuration',
'BwdPacketLengthMax',
'BwdPacketLengthMin',
'BwdPacketLengthMean',
'BwdPacketLengthStd',
'FlowIATMean',
'FlowIATStd',
'FlowIATMax',
'FlowIATMin',
'FwdIATTotal',
'FwdIATMean',
'FwdIATStd',
'FwdIATMax',
'FwdIATMin',
'BwdIATTotal',
'BwdIATMean',
'BwdIATStd',
'BwdIATMax',
'BwdIATMin',
'FwdPSHFlags',
'FwdPackets/s',
'PacketLengthMax',
'PacketLengthMean',
'PacketLengthStd',
'PacketLengthVariance',
'FINFlagCount',
'SYNFlagCount',
'PSHFlagCount',
'ACKFlagCount',
'URGFlagCount',
'AveragePacketSize',
'BwdSegmentSizeAvg',
'FWDInitWinBytes',
'BwdInitWinBytes',
'ActiveMin',
'IdleMean',
'IdleStd',
'IdleMax',
'IdleMin'])

flow_count = 0
flow_df = pd.DataFrame(columns=cols)

src_ip_dict = {}

current_flows = {}
FlowTimeout = 600

# Load models
try:
    ae_scaler = joblib.load("models/preprocess_pipeline_AE_39ft.save")
    ae_model = keras.models.load_model('models/autoencoder_39ft.hdf5')
    with open('models/model.pkl', 'rb') as f:
        classifier = pickle.load(f)
    with open('models/explainer', 'rb') as f:
        explainer = dill.load(f)
    predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)
except Exception as e:
    print(f"Error loading models: {str(e)}")
    raise

def clean_stale_flows():
    current_time = time.time()
    stale_flow_ids = []
    
    for flow_id, flow in current_flows.items():
        if (current_time - flow.getFlowLastSeen()) > FlowTimeout:
            stale_flow_ids.append(flow_id)
    
    for flow_id in stale_flow_ids:
        classify(current_flows[flow_id].terminated())
        del current_flows[flow_id]

# In application.py - modify the classify function

def classify(features):
    try:
        global flow_count
        feature_string = [str(i) for i in features[39:]]
        record = features.copy()
        features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
        
        if feature_string[0] in src_ip_dict.keys():
            src_ip_dict[feature_string[0]] += 1
        else:
            src_ip_dict[feature_string[0]] = 1

        for i in [0,2]:
            ip = feature_string[i]
            if not ipaddress.ip_address(ip).is_private:
                country = ipInfo(ip)
                if country is not None and country not in ['ano', 'unknown']:
                    img = ' <img src="static/images/blank.gif" class="flag flag-' + country.lower() + '" title="' + country + '">'
                else:
                    img = ' <img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
            else:
                img = ' <img src="static/images/lan.gif" height="11px" style="margin-bottom: 0px" title="LAN">'
            feature_string[i] += img

        if np.nan in features:
            return

        result = classifier.predict([features])
        proba = predict_fn_rf([features])
        proba_score = [proba[0].max()]
        proba_risk = sum(list(proba[0,1:]))
        
        # Determine risk level
        if proba_risk > 0.8:
            risk = ["<p class='risk-badge risk-very_high'>Very High</p>"]
            risk_level = "very_high"
        elif proba_risk > 0.6:
            risk = ["<p class='risk-badge risk-high'>High</p>"]
            risk_level = "high"
        elif proba_risk > 0.4:
            risk = ["<p class='risk-badge risk-medium'>Medium</p>"]
            risk_level = "medium"
        elif proba_risk > 0.2:
            risk = ["<p class='risk-badge risk-low'>Low</p>"]
            risk_level = "low"
        else:
            risk = ["<p class='risk-badge risk-minimal'>Minimal</p>"]
            risk_level = "minimal"

        classification = [str(result[0])]
        if result[0] != 'Benign':
            print(feature_string + classification + proba_score)

        flow_count += 1
        w.writerow(['Flow #'+str(flow_count)])
        w.writerow(['Flow info:'] + feature_string)
        w.writerow(['Flow features:'] + features)
        w.writerow(['Prediction:'] + classification + proba_score)
        w.writerow(['--------------------------------------------------------------------------------------------------'])

        w2.writerow(['Flow #'+str(flow_count)])
        w2.writerow(['Flow info:'] + features)
        w2.writerow(['--------------------------------------------------------------------------------------------------'])
        
        # Create flow data dictionary with the risk_level included
        flow_data = dict(zip(cols, [flow_count] + record + classification + proba_score))
        # Add risk level explicitly - FIXED: This was missing in original code
        flow_data['risk_level'] = risk_level
        
        # Update the dataframe for local tracking
        flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk
        
        # FIXED: Improved condition to store flows - either non-benign or high/very high risk
        should_store = result[0] != 'Benign' or risk_level in ["very_high", "high"]
        
        if should_store and session.get('user_id'):
            try:
                print(f"🔍 Saving flow #{flow_count} to Firestore: Class={result[0]}, Risk={risk_level}")
                
                # Clean flow data for Firestore storage
                clean_flow_data = {}
                for key, value in flow_data.items():
                    if isinstance(value, (np.integer, np.int64)):
                        clean_flow_data[key] = int(value)
                    elif isinstance(value, (np.float64, np.float32)):
                        clean_flow_data[key] = float(value)
                    elif isinstance(value, np.ndarray):
                        clean_flow_data[key] = value.tolist()
                    elif pd.isna(value):
                        clean_flow_data[key] = None
                    else:
                        clean_flow_data[key] = value
                
                # Get session info
                user_id = session.get('user_id', 'anonymous')
                session_id = session.get('session_id', 'default_session')
                
                # FIXED: Save to Firestore with proper data
                flow_id = save_malicious_flow(
                    user_id=user_id,
                    session_id=session_id,
                    flow_data=clean_flow_data
                )
                
                if flow_id:
                    print(f"✅ Saved malicious flow {flow_id} (Risk: {risk_level}, Class: {result[0]})")
                    
                    # FIXED: Also increment the session risk counter directly
                    # This is a backup in case save_malicious_flow's counter update fails
                    increment_high_risk_count(session_id, risk_level)
                    
                    # Update global stats more frequently for high risk flows
                    if risk_level in ["high", "very_high"] or flow_count % 3 == 0:
                        update_global_stats()
                else:
                    print("❌ Failed to save flow to Firestore")
                
            except Exception as e:
                print(f"❌ Firestore save error: {e}")
                traceback.print_exc()

        ip_data = {'SourceIP': list(src_ip_dict.keys()), 'count': list(src_ip_dict.values())}
        ip_data = pd.DataFrame(ip_data)
        ip_data = ip_data.to_json(orient='records')

        socketio.emit('newresult', {
            'result': [flow_count] + feature_string + classification + proba_score + risk,
            'ips': json.loads(ip_data),
            'risk_level': risk_level,
            'classification': classification[0]  # Use first element of classification
        }, namespace='/test')
        
        return [flow_count] + record + classification + proba_score + risk
        
    except Exception as e:
        print(f"Error in classify function: {str(e)}")
        traceback.print_exc()
        return None

def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow

    except AttributeError:
        # Not IP or TCP
        return

    except Exception as e:
        print(f"Error in newPacket function: {str(e)}")
        traceback.print_exc()

def snif_and_detect():
    while not thread_stop_event.isSet():
        print("Begin Sniffing".center(20, ' '))
        clean_stale_flows()  # Added stale flow cleanup
        sniff(prn=newPacket)
        for f in current_flows.values():
            classify(f.terminated())


@app.route('/test-firebase', methods=['GET'])
def test_firebase():
    try:
        if not firestore_db:
            return jsonify({"status": "error", "message": "Firestore not initialized"}), 500

        # Create document reference first
        doc_ref = firestore_db.collection("connection_tests").document()
        
        # Prepare data WITHOUT SERVER_TIMESTAMP for the response
        test_data = {
            "test": "RNIDS Connection Test",
            "status": "success",
            "document_id": doc_ref.id
        }

        # Create separate data for Firestore WITH timestamp
        firestore_data = {
            **test_data,
            "timestamp": SERVER_TIMESTAMP  # Only for Firestore
        }

        # Write to Firestore
        doc_ref.set(firestore_data)
        
        # Return response without the timestamp
        return jsonify({
            "status": "success",
            "data": test_data
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "solution": "Check firebase-adminsdk.json and Firestore rules"
        }), 500

# Route for the landing page (default page)
@app.route('/')
def landing():
    return render_template('landing.html')


# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    try:
        # Get username and password from form or JSON
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        # Add debug logging to track flow
        print(f"Login attempt for username: {username}")
        
        # Check if request is AJAX (XHR)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        # Basic validation
        if not username or not password:
            error_msg = "Username and password are required"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": error_msg}), 400
            flash(error_msg)
            return redirect(url_for('landing'))
            
        # Try multiple lookup strategies
        user_data = None
        user_id = None
        
        # Strategy 1: Check if the input is an email (has @)
        if '@' in username:
            print("Email format detected, trying direct document lookup...")
            user_ref = firestore_db.collection('users').document(username)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = username
                print(f"Found user via direct email lookup: {user_id}")
        
        # Strategy 2: Use the get_user_by_username function
        if not user_data:
            print("Trying username lookup via query...")
            user_data, user_id = get_user_by_username(username)
            if user_data:
                print(f"Found user via username query: {user_id}")
        
        # Strategy 3: Try with @example.com appended if no @ in username
        if not user_data and '@' not in username:
            print("Trying email with default domain...")
            email_to_try = f"{username}@example.com"
            user_ref = firestore_db.collection('users').document(email_to_try)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = email_to_try
                print(f"Found user via default domain email: {user_id}")
        
        # Debug output for troubleshooting
        if user_data:
            print(f"User data retrieved. Has password hash: {'password_hash' in user_data}")
        else:
            print("No user data found with provided username/email")
            
        # Verify user exists and password matches
        if not user_data:
            error_msg = "User not found"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Invalid username or password"}), 401
            flash("Invalid username or password")
            return redirect(url_for('landing'))
            
        # Check if password hash exists
        if 'password_hash' not in user_data:
            error_msg = "Password hash not found in user data"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Account setup incomplete. Please contact admin."}), 401
            flash("Account setup incomplete. Please contact admin.")
            return redirect(url_for('landing'))
            
        # Verify password
        if not verify_password(user_data.get('password_hash'), password):
            error_msg = "Password verification failed"
            print(f"Login error: {error_msg}")
            if is_ajax:
                return jsonify({"success": False, "message": "Invalid username or password"}), 401
            flash("Invalid username or password")
            return redirect(url_for('landing'))
            
        # Authentication successful
        print(f"User {username} authenticated successfully")
        
        # User authenticated, set up session
        session['logged_in'] = True
        session['username'] = user_data.get('username', username)
        session['user_id'] = user_id
        session['email'] = user_data.get('email', user_id if '@' in user_id else f"{user_id}@example.com")
        session['fullname'] = user_data.get('fullname', '')
        session['new_session'] = True

        # Get device info
        user_agent = request.user_agent
        device_info = {
            'os': user_agent.platform if user_agent else 'Unknown',
            'browser': user_agent.browser if user_agent else 'Unknown',
            'ip_address': request.remote_addr or '0.0.0.0'
        }
        
        # Create Firestore session
        session_id = create_user_session(user_id, device_info)
        if session_id:
            session['session_id'] = session_id
            print(f"Created Firestore session: {session_id}")
            
            # Initialize global stats
            update_global_stats()
        else:
            session['session_id'] = 'default_session'
            print("Using default session ID")
        
        # Return appropriate response based on request format
        if is_ajax:
            return jsonify({"success": True, "redirect": url_for('capture')})
        return redirect(url_for('capture'))
        
    except Exception as e:
        print(f"Login error: {e}")
        traceback.print_exc()
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            return jsonify({"success": False, "message": "Login failed. Please try again."}), 500
        flash('Login failed. Please try again.')
        return redirect(url_for('landing'))
    

# Route for the capture page (index.html)
@app.route('/capture')
def capture():
    # Check if the user is logged in
    if not session.get('logged_in'):
        return redirect(url_for('landing'))  # Redirect to landing page if not logged in
    return render_template('index.html')

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    # Check if the request is AJAX
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        # Get form data
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        fullname = request.form.get('fullname', '').strip()
        
        # Validation errors dictionary
        errors = {}
        
        # Validate input
        if not username:
            errors['username'] = 'Username is required'
        if not password:
            errors['password'] = 'Password is required'
        if not email:
            errors['email'] = 'Email is required'
        
        # Handle validation errors
        if errors:
            if is_ajax:
                return jsonify({"success": False, "errors": errors}), 400
            for field, message in errors.items():
                flash(message)
            return render_template('signup.html')
        
        # Check if email contains @ - if not, add default domain
        if '@' not in email:
            email = f"{email}@example.com"
        
        # Check if username already exists
        existing_user, _ = get_user_by_username(username)
        if existing_user:
            if is_ajax:
                return jsonify({"success": False, "errors": {"username": "Username already exists"}}), 400
            flash('Username already exists')
            return render_template('signup.html')
        
        # Check if email already exists as a document ID
        user_ref = firestore_db.collection('users').document(email)
        if user_ref.get().exists:
            if is_ajax:
                return jsonify({"success": False, "errors": {"email": "Email already registered"}}), 400
            flash('Email already registered')
            return render_template('signup.html')
        
        # Hash password
        password_hash = hash_password(password)
        if not password_hash:
            if is_ajax:
                return jsonify({"success": False, "message": "Error creating account. Please try again."}), 500
            flash('Error creating account. Please try again.')
            return render_template('signup.html')
        
        # Create user document
        user_data = {
            'username': username,
            'email': email,
            'fullname': fullname if fullname else username,
            'password_hash': password_hash,
            'created_at': SERVER_TIMESTAMP,
            'last_active': SERVER_TIMESTAMP
        }
        
        # Save to Firestore
        user_ref.set(user_data)
        
        # Log success
        print(f"User created: {email} with username: {username}")
        
        # Automatically log in the user
        session['logged_in'] = True
        session['username'] = username
        session['user_id'] = email
        session['email'] = email
        session['fullname'] = fullname if fullname else username
        session['new_session'] = True
        
        # Create session
        session_id = create_user_session(email)
        if session_id:
            session['session_id'] = session_id
        
        # Return appropriate response
        if is_ajax:
            return jsonify({"success": True, "redirect": url_for('capture')})
        
        flash('Account created successfully!')
        return redirect(url_for('capture'))
        
    except Exception as e:
        print(f"Signup error: {e}")
        traceback.print_exc()
        
        if is_ajax:
            return jsonify({"success": False, "message": "Error creating account. Please try again."}), 500
        
        flash('Error creating account. Please try again.')
        return render_template('signup.html')

# Route for the detail page (Detail.html)
@app.route('/detail')
def detail():
    try:
        flow_id = request.args.get('flow_id', default=-1, type=int)
        flow = flow_df.loc[flow_df['FlowID'] == flow_id]
        
        if flow.empty:
            return "Flow not found", 404
            
        X = [flow.values[0,1:40]]
        choosen_instance = X
        proba_score = list(predict_fn_rf(choosen_instance))
        risk_proba = sum(proba_score[0][1:])
        
        if risk_proba > 0.8:
            risk = "Risk: <p style=\"color:red;\">Very High</p>"
        elif risk_proba > 0.6:
            risk = "Risk: <p style=\"color:orangered;\">High</p>"
        elif risk_proba > 0.4:
            risk = "Risk: <p style=\"color:orange;\">Medium</p>"
        elif risk_proba > 0.2:
            risk = "Risk: <p style=\"color:green;\">Low</p>"
        else:
            risk = "Risk: <p style=\"color:limegreen;\">Minimal</p>"
            
        exp = explainer.explain_instance(choosen_instance[0], predict_fn_rf, num_features=6, top_labels=1)

        X_transformed = ae_scaler.transform(X)
        reconstruct = ae_model.predict(X_transformed)
        err = reconstruct - X_transformed
        abs_err = np.absolute(err)
        
        ind_n_abs_largest = np.argpartition(abs_err, -5)[-5:]
        col_n_largest = ae_features[ind_n_abs_largest]
        err_n_largest = err[0][ind_n_abs_largest]
        
        plot_div = plotly.offline.plot({
            "data": [
                plotly.graph_objs.Bar(x=col_n_largest[0].tolist(), y=err_n_largest[0].tolist())
            ]
        }, include_plotlyjs=False, output_type='div')

        return render_template(
            'detail.html',
            tables=[flow.reset_index(drop=True).transpose().to_html(classes='data')],
            exp=exp.as_html(),
            ae_plot=plot_div,
            risk=risk
        )
    except Exception as e:
        print(f"Error in flow_detail: {str(e)}")
        traceback.print_exc()
        return "Error processing request", 500

# Route for the profile page
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('landing'))
    
    # Fetch user details from the session or database
    username = session.get('username')
    email = session.get('email')  # Ensure email is stored in the session during login/signup
    fullname = session.get('fullname')  # Ensure fullname is stored in the session during signup
    
    return render_template('profile.html', username=username, email=email, fullname=fullname)

@app.route('/clear-local-flows')
def clear_local_flows():
    if not session.get('logged_in'):
        return jsonify({"status": "error", "message": "Not authorized"}), 401
    return jsonify({"status": "success", "message": "Local flows cleared"})

# Add this route to your application.py file
@app.route('/debug_auth', methods=['GET'])
def debug_auth():
    """Debug route for authentication issues (remove in production)"""
    # Only allow on development environment
    if app.config.get('ENV') != 'development':
        return jsonify({"error": "Not available in production"}), 403
    
    try:
        # Check if a username is provided
        test_username = request.args.get('username')
        if not test_username:
            return jsonify({
                "status": "Need username parameter",
                "usage": "/debug_auth?username=your_username"
            })
        
        # Try to find the user
        user_data, user_id = get_user_by_username(test_username)
        
        # If not found by username, try email
        if not user_data and '@' not in test_username:
            email_to_try = f"{test_username}@example.com"
            user_ref = firestore_db.collection('users').document(email_to_try)
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_id = email_to_try
        
        # Prepare response
        if not user_data:
            return jsonify({
                "status": "User not found",
                "username": test_username,
                "lookups_tried": [
                    f"Username match: {test_username}",
                    f"Email direct: {test_username if '@' in test_username else f'{test_username}@example.com'}"
                ]
            })
        
        # Return user info (redact sensitive data)
        safe_data = {
            "status": "User found",
            "username": user_data.get('username'),
            "user_id": user_id,
            "email": user_data.get('email'),
            "has_password_hash": 'password_hash' in user_data,
            "password_hash_length": len(user_data.get('password_hash', '')) if 'password_hash' in user_data else 0,
            "created_at": user_data.get('created_at').strftime('%Y-%m-%d %H:%M:%S') if user_data.get('created_at') else None,
            "last_active": user_data.get('last_active').strftime('%Y-%m-%d %H:%M:%S') if user_data.get('last_active') else None
        }
        
        return jsonify(safe_data)
    except Exception as e:
        return jsonify({
            "status": "Error",
            "error": str(e),
            "traceback": traceback.format_exc()
        })


@app.route('/about')
def about():
    return render_template('about.html')

# Logout route
@app.route('/logout')
def logout():
    try:
        # End Firestore session if exists
        if session.get('user_id') and session.get('session_id') and firestore_db:
            session_ref = firestore_db.collection('sessions').document(session['session_id'])
            session_ref.update({
                'end_time': SERVER_TIMESTAMP,
                'status': 'completed'
            })
    except Exception as e:
        print(f"Error ending session: {e}")
    
    # Clear the session
    session.clear()
    
    # Return a response that will trigger frontend cleanup
    return redirect(url_for('landing'))

@app.route('/check-session')
def check_session():
    if not session.get('logged_in'):
        return "Not logged in"
    return jsonify({
        'username': session.get('username'),
        'user_id': session.get('user_id'),
        'session_id': session.get('session_id')
    })


@socketio.on('connect', namespace='/test')
def test_connect():
    # Need visibility of the global thread object
    global thread
    print('Client connected')

    # Start the random result generator thread only if the thread has not been started before.
    if not thread.is_alive():
        print("Starting Thread")
        thread = socketio.start_background_task(snif_and_detect)

@socketio.on('disconnect', namespace='/test')
def test_disconnect():
    try:
        print('Client disconnected')
    except Exception as e:
        print(f"Error in disconnect handler: {str(e)}")

# Cleanup handler for when the application shuts down
def cleanup_on_shutdown():
    try:
        thread_stop_event.set()
        cleanup_files()
        # Clean up any remaining flows
        for flow_id in list(current_flows.keys()):
            try:
                classify(current_flows[flow_id].terminated())
                del current_flows[flow_id]
            except Exception as e:
                print(f"Error cleaning up flow {flow_id}: {str(e)}")
    except Exception as e:
        print(f"Error during shutdown cleanup: {str(e)}")

# Register the cleanup handler
atexit.register(cleanup_on_shutdown)

if __name__ == '__main__':
    try:
        socketio.run(app)
    except Exception as e:
        print(f"Error starting application: {str(e)}")
        cleanup_on_shutdown()