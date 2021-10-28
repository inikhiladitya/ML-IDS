#import libs

import streamlit as st
import pandas as pd
import numpy as np
import pickle

#Set title and layout
st.set_page_config(page_title='NIDS V1.0',layout='wide')

#Load model

model = pickle.load(open('knnIDS.sav','rb'))

#Function to use pickled model

def predict_attack(bytes_in,bytes_out,dest_port,entropy,num_pkts_out,
    num_pkts_in,proto,src_port,duration):
    input=np.array[[bytes_in,bytes_out,dest_port,entropy,num_pkts_out,
    num_pkts_in,proto,src_port,duration]].astype(np.float64)                        
    result = model.predict(input)
    return result

#Head

st.write(""" # NIDS for Network Telemetry Data
This NIDS takes in telemetry data extracted from CISCO's Joy tool 
and then predicts if the network activity contains any malicious activity.
""")

# Sidebar
with st.sidebar.header('1. Upload your CSV data'):
    uploaded_file = st.sidebar.file_uploader("Upload your input CSV file", type=["csv"])

# Main

#Displays Logs
st.subheader('Uploaded Logs')

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.markdown('Summary of logs')
    st.write(data)    
    st.write(data.shape) 
    
    #Assign columns to variables 
    bytes_in=df.iloc[:,0]
    bytes_out=df.iloc[:,1]
    dest_port=df.iloc[:,2]
    entropy=df.iloc[:,3]
    num_pkts_out=df.iloc[:,4]
    num_pkts_in=df.iloc[:,5]
    proto=df.iloc[:,6]
    src_port=df.iloc[:,7]
    duration=df.iloc[:,8]

else:
    st.info('Awaiting for CSV file to be uploaded.')

#Button to predict
if st.button("Analyse Logs"):
    predict_attack(bytes_in,bytes_out,dest_port,entropy,num_pkts_out,
    num_pkts_in,proto,src_port,duration)
    
