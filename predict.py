#import libs

import streamlit as st
import pandas as pd
import numpy as np
import pickle
import sys


#Set title and layout
st.set_page_config(page_title='NIDS V1.0',layout='wide')

#Load model

model = pickle.load(open('ensemble.sav','rb'))

#Function to use pickled model

def predict_attack(Dst_Port, Protocol, Flow_Duration, Tot_Fwd_Pkts, Tot_Bwd_Pkts, TotLen_Fwd_Pkts, TotLen_Bwd_Pkts, Fwd_Pkt_Len_Max, Fwd_Pkt_Len_Min, Fwd_Pkt_Len_Mean, Fwd_Pkt_Len_Std, Bwd_Pkt_Len_Max, Bwd_Pkt_Len_Min, Bwd_Pkt_Len_Mean, Bwd_Pkt_Len_Std, Flow_Byts_s, Flow_Pkts_s, Flow_IAT_Mean, Flow_IAT_Std, Flow_IAT_Max, Flow_IAT_Min, Fwd_IAT_Tot, Fwd_IAT_Mean, Fwd_IAT_Std, Fwd_IAT_Max, Fwd_IAT_Min, Bwd_IAT_Tot, Bwd_IAT_Mean, Bwd_IAT_Std, Bwd_IAT_Max, Bwd_IAT_Min, Fwd_PSH_Flags, Fwd_Header_Len, Bwd_Header_Len, Fwd_Pkts_s, Bwd_Pkts_s, Pkt_Len_Min, Pkt_Len_Max, Pkt_Len_Mean, Pkt_Len_Std, Pkt_Len_Var, FIN_Flag_Cnt, SYN_Flag_Cnt, RST_Flag_Cnt, PSH_Flag_Cnt, ACK_Flag_Cnt, URG_Flag_Cnt, ECE_Flag_Cnt, Down_Up_Ratio, Pkt_Size_Avg, Fwd_Seg_Size_Avg, Bwd_Seg_Size_Avg, Subflow_Fwd_Pkts, Subflow_Fwd_Byts, Subflow_Bwd_Pkts, Subflow_Bwd_Byts, Init_Fwd_Win_Byts, Init_Bwd_Win_Byts, Fwd_Act_Data_Pkts, Fwd_Seg_Size_Min, Active_Mean, Active_Std, Active_Max, Active_Min, Idle_Mean, Idle_Std, Idle_Max, Idle_Min
):
    result = []
    for x in range(0,len(Dst_Port)):
        input=np.array([[Dst_Port[x], Protocol[x], Flow_Duration[x], Tot_Fwd_Pkts[x], Tot_Bwd_Pkts[x], TotLen_Fwd_Pkts[x], TotLen_Bwd_Pkts[x], Fwd_Pkt_Len_Max[x], Fwd_Pkt_Len_Min[x], Fwd_Pkt_Len_Mean[x], Fwd_Pkt_Len_Std[x], Bwd_Pkt_Len_Max[x], Bwd_Pkt_Len_Min[x], Bwd_Pkt_Len_Mean[x], Bwd_Pkt_Len_Std[x], Flow_Byts_s[x], Flow_Pkts_s[x], Flow_IAT_Mean[x], Flow_IAT_Std[x], Flow_IAT_Max[x], Flow_IAT_Min[x], Fwd_IAT_Tot[x], Fwd_IAT_Mean[x], Fwd_IAT_Std[x], Fwd_IAT_Max[x], Fwd_IAT_Min[x], Bwd_IAT_Tot[x], Bwd_IAT_Mean[x], Bwd_IAT_Std[x], Bwd_IAT_Max[x], Bwd_IAT_Min[x], Fwd_PSH_Flags[x], Fwd_Header_Len[x], Bwd_Header_Len[x], Fwd_Pkts_s[x], Bwd_Pkts_s[x], Pkt_Len_Min[x], Pkt_Len_Max[x], Pkt_Len_Mean[x], Pkt_Len_Std[x], Pkt_Len_Var[x], FIN_Flag_Cnt[x], SYN_Flag_Cnt[x], RST_Flag_Cnt[x], PSH_Flag_Cnt[x], ACK_Flag_Cnt[x], URG_Flag_Cnt[x], ECE_Flag_Cnt[x], Down_Up_Ratio[x], Pkt_Size_Avg[x], Fwd_Seg_Size_Avg[x], Bwd_Seg_Size_Avg[x], Subflow_Fwd_Pkts[x], Subflow_Fwd_Byts[x], Subflow_Bwd_Pkts[x], Subflow_Bwd_Byts[x], Init_Fwd_Win_Byts[x], Init_Bwd_Win_Byts[x], Fwd_Act_Data_Pkts[x], Fwd_Seg_Size_Min[x], Active_Mean[x], Active_Std[x], Active_Max[x], Active_Min[x], Idle_Mean[x], Idle_Std[x], Idle_Max[x], Idle_Min[x]]]).astype(np.float64)
        #st.write(input.shape)                        
        result.append(model.predict(input))
    return result

#Head
st.write(""" # NIDS for Network Telemetry Anomaly Detection
This NIDS takes in telemetry data extracted from CICFlow Meter 
and then predicts attacks. 
""")

# Sidebar
with st.sidebar.header('1. Upload your CSV data'):
    uploaded_file = st.sidebar.file_uploader("Upload your input CSV file", type=["csv"])

# Main

#Displays Logs
st.subheader('Uploaded Logs')

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    #Organise Features into new columns

    #Print Summary
    st.markdown('Summary of logs')
    st.write(df)
    
    #Assign data columns to variables 
    Dst_Port=df.iloc[:,0]
    Protocol=df.iloc[:,1]
    Flow_Duration=df.iloc[:,2]
    Tot_Fwd_Pkts=df.iloc[:,3]
    Tot_Bwd_Pkts=df.iloc[:,4]
    TotLen_Fwd_Pkts=df.iloc[:,5]
    TotLen_Bwd_Pkts=df.iloc[:,6]
    Fwd_Pkt_Len_Max=df.iloc[:,7]
    Fwd_Pkt_Len_Min=df.iloc[:,8]
    Fwd_Pkt_Len_Mean=df.iloc[:,9]
    Fwd_Pkt_Len_Std=df.iloc[:,10]
    Bwd_Pkt_Len_Max=df.iloc[:,11]
    Bwd_Pkt_Len_Min=df.iloc[:,12]
    Bwd_Pkt_Len_Mean=df.iloc[:,13]
    Bwd_Pkt_Len_Std=df.iloc[:,14]
    Flow_Byts_s=df.iloc[:,15]
    Flow_Pkts_s=df.iloc[:,16]
    Flow_IAT_Mean=df.iloc[:,17]
    Flow_IAT_Std=df.iloc[:,18]
    Flow_IAT_Max=df.iloc[:,19]
    Flow_IAT_Min=df.iloc[:,20]
    Fwd_IAT_Tot=df.iloc[:,21]
    Fwd_IAT_Mean=df.iloc[:,22]
    Fwd_IAT_Std=df.iloc[:,23]
    Fwd_IAT_Max=df.iloc[:,24]
    Fwd_IAT_Min=df.iloc[:,25]
    Bwd_IAT_Tot=df.iloc[:,26]
    Bwd_IAT_Mean=df.iloc[:,27]
    Bwd_IAT_Std=df.iloc[:,28]
    Bwd_IAT_Max=df.iloc[:,29]
    Bwd_IAT_Min=df.iloc[:,30]
    Fwd_PSH_Flags=df.iloc[:,31]
    Fwd_Header_Len=df.iloc[:,32]
    Bwd_Header_Len=df.iloc[:,33]
    Fwd_Pkts_s=df.iloc[:,34]
    Bwd_Pkts_s=df.iloc[:,35]
    Pkt_Len_Min=df.iloc[:,36]
    Pkt_Len_Max=df.iloc[:,37]
    Pkt_Len_Mean=df.iloc[:,38]
    Pkt_Len_Std=df.iloc[:,39]
    Pkt_Len_Var=df.iloc[:,40]
    FIN_Flag_Cnt=df.iloc[:,41]
    SYN_Flag_Cnt=df.iloc[:,42]
    RST_Flag_Cnt=df.iloc[:,43]
    PSH_Flag_Cnt=df.iloc[:,44]
    ACK_Flag_Cnt=df.iloc[:,45]
    URG_Flag_Cnt=df.iloc[:,46]
    ECE_Flag_Cnt=df.iloc[:,47]
    Down_Up_Ratio=df.iloc[:,48]
    Pkt_Size_Avg=df.iloc[:,49]
    Fwd_Seg_Size_Avg=df.iloc[:,50]
    Bwd_Seg_Size_Avg=df.iloc[:,51]
    Subflow_Fwd_Pkts=df.iloc[:,52]
    Subflow_Fwd_Byts=df.iloc[:,53]
    Subflow_Bwd_Pkts=df.iloc[:,54]
    Subflow_Bwd_Byts=df.iloc[:,55]
    Init_Fwd_Win_Byts=df.iloc[:,56]
    Init_Bwd_Win_Byts=df.iloc[:,57]
    Fwd_Act_Data_Pkts=df.iloc[:,58]
    Fwd_Seg_Size_Min=df.iloc[:,59]
    Active_Mean=df.iloc[:,60]
    Active_Std=df.iloc[:,61]
    Active_Max=df.iloc[:,62]
    Active_Min=df.iloc[:,63]
    Idle_Mean=df.iloc[:,64]
    Idle_Std=df.iloc[:,65]
    Idle_Max=df.iloc[:,66]
    Idle_Min=df.iloc[:,67]

else:
    st.info('Awaiting for CSV file to be uploaded.')

#Button to predict
if st.button("Analyse Logs"):
    f_result=predict_attack(Dst_Port, Protocol, Flow_Duration, Tot_Fwd_Pkts, Tot_Bwd_Pkts, TotLen_Fwd_Pkts, TotLen_Bwd_Pkts, Fwd_Pkt_Len_Max, Fwd_Pkt_Len_Min, Fwd_Pkt_Len_Mean, Fwd_Pkt_Len_Std, Bwd_Pkt_Len_Max, Bwd_Pkt_Len_Min, Bwd_Pkt_Len_Mean, Bwd_Pkt_Len_Std, Flow_Byts_s, Flow_Pkts_s, Flow_IAT_Mean, Flow_IAT_Std, Flow_IAT_Max, Flow_IAT_Min, Fwd_IAT_Tot, Fwd_IAT_Mean, Fwd_IAT_Std, Fwd_IAT_Max, Fwd_IAT_Min, Bwd_IAT_Tot, Bwd_IAT_Mean, Bwd_IAT_Std, Bwd_IAT_Max, Bwd_IAT_Min, Fwd_PSH_Flags, Fwd_Header_Len, Bwd_Header_Len, Fwd_Pkts_s, Bwd_Pkts_s, Pkt_Len_Min, Pkt_Len_Max, Pkt_Len_Mean, Pkt_Len_Std, Pkt_Len_Var, FIN_Flag_Cnt, SYN_Flag_Cnt, RST_Flag_Cnt, PSH_Flag_Cnt, ACK_Flag_Cnt, URG_Flag_Cnt, ECE_Flag_Cnt, Down_Up_Ratio, Pkt_Size_Avg, Fwd_Seg_Size_Avg, Bwd_Seg_Size_Avg, Subflow_Fwd_Pkts, Subflow_Fwd_Byts, Subflow_Bwd_Pkts, Subflow_Bwd_Byts, Init_Fwd_Win_Byts, Init_Bwd_Win_Byts, Fwd_Act_Data_Pkts, Fwd_Seg_Size_Min, Active_Mean, Active_Std, Active_Max, Active_Min, Idle_Mean, Idle_Std, Idle_Max, Idle_Min)
    df_res=pd.DataFrame(f_result)
   #Print Results
    st.table(df_res)

