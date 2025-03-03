from flask_socketio import SocketIO, emit
from flask import Flask, render_template, redirect, url_for, request, session, flash
from random import random
from time import sleep
from threading import Thread, Event
import os
import time
import atexit

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

__author__ = 'hoang'

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

def classify(features):
    try:
        # Preprocess
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
        
        if proba_risk > 0.8:
            risk = ["<p style=\"color:red;\">Very High</p>"]
        elif proba_risk > 0.6:
            risk = ["<p style=\"color:orangered;\">High</p>"]
        elif proba_risk > 0.4:
            risk = ["<p style=\"color:orange;\">Medium</p>"]
        elif proba_risk > 0.2:
            risk = ["<p style=\"color:green;\">Low</p>"]
        else:
            risk = ["<p style=\"color:limegreen;\">Minimal</p>"]

        classification = [str(result[0])]
        if result != 'Benign':
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
        flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk

        ip_data = {'SourceIP': src_ip_dict.keys(), 'count': src_ip_dict.values()}
        ip_data = pd.DataFrame(ip_data)
        ip_data = ip_data.to_json(orient='records')

        print("Emitting newresult event:", {'result': [flow_count] + feature_string + classification + proba_score + risk, "ips": json.loads(ip_data)})
        socketio.emit('newresult', {'result': [flow_count] + feature_string + classification + proba_score + risk, "ips": json.loads(ip_data)}, namespace='/test')
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

# Route for the landing page (default page)
@app.route('/')
def landing():
    return render_template('landing.html')

# Route for handling login form submission
@app.route('/login', methods=['POST'])
def login():
    try:
        # Check if the request contains JSON data
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            # Fallback to form data
            username = request.form.get('username')
            password = request.form.get('password')

        print("Received login request:", username, password)  # Debug

        # Dummy user data for demonstration (replace with database logic)
        users = {
            "user1": "password1",
            "user2": "password2"
        }

        # Check if the username and password are valid
        if username in users and users[username] == password:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('capture'))  # Redirect to the capture page
        else:
            flash('Invalid username or password')  # Flash error message
            return redirect(url_for('landing'))  # Redirect back to landing page
    except Exception as e:
        print("Error in login route:", str(e))  # Debug
        flash('An error occurred. Please try again.')
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
    if request.method == 'POST':
        # Handle signup form submission
        fullname = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Simulate saving user data (replace with database logic)
        print(f"New user: {fullname}, {email}, {username}, {password}")

        # Redirect to landing page after successful signup
        return redirect(url_for('landing'))
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

# Logout route
@app.route('/logout')
def logout():
    # Clear the session to log the user out
    session.clear()
    return redirect(url_for('landing'))

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