import streamlit as st
import functools
import numpy as np
import pandas as pd
from transformers import AutoTokenizer, RobertaTokenizerFast, RobertaForSequenceClassification, pipeline
from datasets import Dataset
import torch
import hashlib
from tempfile import NamedTemporaryFile
import pyshark
import re


# @st.cache(allow_output_mutation=True)
# @st.cache_data
@st.cache_resource
def get_model():
    tokenizer = RobertaTokenizerFast.from_pretrained("daxproai/daxpro-BERT")
    model = RobertaForSequenceClassification.from_pretrained("daxproai/daxpro-BERT")
    # response_model = "tiiuae/falcon-7b-instruct"
    # falcon_tokenizer = AutoTokenizer.from_pretrained(response_model)
    # falcon_pipeline = pipeline(
    #     "text-generation",
    #     model=response_model,
    #     tokenizer=falcon_tokenizer,
    #     torch_dtype=torch.bfloat16,
    #     trust_remote_code=True,
    #     device_map="auto",
    # )
    return tokenizer,model#,falcon_pipeline

# def rsetattr(obj, attr, val):
#     pre, _, post = attr.rpartition('.')
#     return setattr(rgetattr(obj, pre) if pre else obj, post, val)
    
def rgetattr(obj, attr, *args):
    def _getattr(obj, attr):
        return getattr(obj, attr, *args)
    return functools.reduce(_getattr, [obj] + attr.split('.'))
    
# Function to extract necessary information from each packet
def pcap2dataframe(pcap_file):
    fields = ['frame.time', 'ip.src_host', 'ip.dst_host', 'arp.dst.proto_ipv4', 'arp.opcode', 'arp.hw.size', 
              'arp.src.proto_ipv4', 'icmp.checksum', 'icmp.seq_le', 'icmp.transmit_timestamp', 'icmp.unused', 'http.file_data', 
              'http.content_length', 'http.request.uri.query', 'http.request.method', 'http.referer', 'http.request.full_uri', 
              'http.request.version', 'http.response', 'http.tls_port', 'tcp.ack', 'tcp.ack_raw', 'tcp.checksum', 
              'tcp.connection.fin', 'tcp.connection.rst', 'tcp.connection.syn', 'tcp.connection.synack', 'tcp.dstport', 
              'tcp.flags', 'tcp.flags.ack', 'tcp.len', 'tcp.options', 'tcp.payload', 'tcp.seq', 'tcp.srcport', 'udp.port', 
              'udp.stream', 'udp.time_delta', 'dns.qry.name', 'dns.qry.name.len', 'dns.qry.qu', 'dns.qry.type', 
              'dns.retransmission', 'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conack.flags', 
              'mqtt.conflag.cleansess', 'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msg', 
              'mqtt.msgtype', 'mqtt.proto_len', 'mqtt.protoname', 'mqtt.topic', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 
              'mbtcp.trans_id', 'mbtcp.unit_id']
    attributes = ["sniff_time", "ip.src_host", "ip.dst_host", "arp.dst_proto_ipv4", "arp.opcode", "arp.hw_size", 
                  "arp.src_proto_ipv4", "icmp.checksum", "icmp.seq_le", "icmp.transmit_timestamp", "icmp.unused", 
                  "http.file_data", "http.content_length", "http.request_uri_query", "http.request_method", "http.referer", 
                  "http.request_full_uri", "http.request_version", "http.response", "http.tls_port", "tcp.ack", "tcp.ack_raw", 
                  "tcp.checksum", "tcp.flags_fin", "tcp.flags_reset", "tcp.flags_syn", "tcp.completeness", 
                  "tcp.dstport", "tcp.flags", "tcp.flags_ack", "tcp.len", "tcp.options", "tcp.payload", "tcp.seq", 
                  "tcp.srcport", "udp.port", "udp.stream", "udp.time_delta", "dns.qry_name", "dns.qry_name_len", "dns.qry_qu", 
                  "dns.qry_type", "dns.retransmission", "dns.retransmit_request", "dns.retransmit_request_in", 
                  "mqtt.conack_flags", "mqtt.conflag_cleansess", "mqtt.conflags", "mqtt.hdrflags", "mqtt.len", 
                  "mqtt.msg_decoded_as", "mqtt.msg", "mqtt.msgtype", "mqtt.proto_len", "mqtt.protoname", "mqtt.topic", 
                  "mqtt.topic_len", "mqtt.ver", "mbtcp.len", "mbtcp.trans_id", "mbtcp.unit_id"]
    
    # Open the pcap file
    cap = pyshark.FileCapture(pcap_file)
    
    # Create an empty list to store rows
    data = []
    
    # Iterate through each packet in the pcap file
    for count, pkt in enumerate(cap):
        # if count == 0:
        #     for meth_name in dir(pkt.tcp):
        #         if not callable(getattr(pkt.tcp, meth_name)):
        #             st.write(meth_name)
        #             st.write(getattr(pkt.tcp, meth_name))
        if count >= 50:
            break
        row = {}
        for field, attribute in zip(fields, attributes):
            try:
                row[field] = rgetattr(pkt, attribute)
            except (KeyError,AttributeError):
                row[field] = 0                
        row["Attack_label"] = 0
        row["Attack_type"] = "Normal"
        for attack_type in id2label.values():
            if re.search(attack_type, pcap_file.split('.')[0]):
                row["Attack_label"] = 1
                row["Attack_type"] = attack_type 
        data.append(row)
        
    # Convert list of dictionaries to pandas DataFrame
    df = pd.DataFrame(data)
    
    # Save DataFrame to CSV file
    # df.to_csv("output.csv", index=False)
    
    # Close file
    cap.close()
    return df

def dataframe_with_selections(df):
    df_with_selections = df.copy()
    df_with_selections.insert(0, "Select", False)

    # Get dataframe row-selections from user with st.data_editor
    edited_df = st.data_editor(
        df_with_selections[df_with_selections.columns[:-2]],
        hide_index=True,
        column_config={"Select": st.column_config.CheckboxColumn(required=True)},
        disabled=df.columns,
        #num_rows="dynamic",
        use_container_width=True
    )

    # Filter the dataframe using the temporary column, then drop the column
    selected_rows = df_with_selections[edited_df.Select]
    return selected_rows.drop('Select', axis=1)
    
tokenizer,model = get_model()
# tokenizer,model,falcon_pipeline = get_model()

st.title("Cyber Threat Detection using DAXPRO-BERT model")

# user_input = st.text_area('Enter Text to Analyze')
user_input = st.file_uploader('Choose a file....', type=("pcap", "csv"))
button = st.button("Analyze")

id2label = {0: 'Backdoor',
 1: 'DDoS_HTTP',
 2: 'DDoS_ICMP',
 3: 'DDoS_TCP',
 4: 'DDoS_UDP',
 5: 'Fingerprinting',
 6: 'MITM',
 7: 'Normal',
 8: 'Password',
 9: 'Port_Scanning',
 10: 'Ransomware',
 11: 'SQL_injection',
 12: 'Uploading',
 13: 'Vulnerability_scanner',
 14: 'XSS'}

if user_input:
    if user_input.name.split('.')[1] == 'csv':
        df = pd.read_csv(user_input)
    elif user_input.name.split('.')[1] == 'pcap':
        with NamedTemporaryFile(dir='.', prefix=user_input.name.split('.')[0] , suffix='.pcap') as f:
            f.write(user_input.getbuffer())
            df = pcap2dataframe(f.name)
    else:
        # st.write(user_input.type)
        st.error("Please select a valid source type!")

    df_sel = dataframe_with_selections(df)
    if len(df_sel) > 0 and button:
        df_llm = pd.DataFrame(columns=['Text'])
        df_llm['Text'] = df_sel[df_sel.columns[:-2]].apply(lambda x: x.name+'$'+x.astype(str), axis=0).apply(np.vectorize(lambda x: hashlib.shake_256(x.encode("utf-8")).hexdigest(16)), axis=0).agg(' '.join, axis=1)
        ds_llm = Dataset.from_pandas(df_llm)
        # st.dataframe(ds_llm, use_container_width=True)
        
        # test_sample = tokenizer([user_input], add_special_tokens=True, truncation=True, padding="max_length", max_length=512, return_tensors='pt')
        test_sample = tokenizer(ds_llm['Text'], add_special_tokens=True, truncation=True, padding="max_length", max_length=512, return_tensors='pt')
        test_sample = {k: v for k,v in test_sample.items()}
        
        output = model(**test_sample)
        y_pred = np.argmax(output.logits.detach().numpy(),axis=1)
        for i in range(len(y_pred.tolist())):
            st.write("Actual Output: ", df_sel[df_sel.columns[-1]].iloc[i])
            st.write("Predicted Output: ", id2label[y_pred[i].item()])
            
        # sequences = falcon_pipeline(
        #    f"Our Cyber Security model 'DAXPRO_Bert' detected {id2label[np.argmax(output.logits.detach().numpy(), axis=1).item()]}. Propose security policies and procedures for data protection, password management, and social engineering awareness for the particular cyber threat detected above by 'DAXPRO_Bert'.",
        #     max_length=200,
        #     do_sample=True,
        #     top_k=10,
        #     num_return_sequences=1,
        #     eos_token_id=falcon_tokenizer.eos_token_id,
        # )
        # for seq in sequences:
        #     st.write("Response: ", seq['generated_text'])
    elif len(df_sel) <= 0 and button:
        df_llm = pd.DataFrame(columns=['Text'])
        df_llm['Text'] = df[df.columns[:-2]].apply(lambda x: x.name+'$'+x.astype(str), axis=0).apply(np.vectorize(lambda x: hashlib.shake_256(x.encode("utf-8")).hexdigest(16)), axis=0).agg(' '.join, axis=1)
        ds_llm = Dataset.from_pandas(df_llm)
        # st.dataframe(ds_llm, use_container_width=True)
        
        # test_sample = tokenizer([user_input], add_special_tokens=True, truncation=True, padding="max_length", max_length=512, return_tensors='pt')
        test_sample = tokenizer(ds_llm['Text'], add_special_tokens=True, truncation=True, padding="max_length", max_length=512, return_tensors='pt')
        test_sample = {k: v for k,v in test_sample.items()}
        
        output = model(**test_sample)
        y_pred = np.argmax(output.logits.detach().numpy(),axis=1)
        for i in range(len(y_pred.tolist())):
            st.write("Actual Output: ", df[df.columns[-1]].iloc[i], "\n Predicted Output: ", id2label[y_pred[i].item()])
            
        # sequences = falcon_pipeline(
        #    f"Our Cyber Security model 'DAXPRO_Bert' detected {id2label[np.argmax(output.logits.detach().numpy(), axis=1).item()]}. Propose security policies and procedures for data protection, password management, and social engineering awareness for the particular cyber threat detected above by 'DAXPRO_Bert'.",
        #     max_length=200,
        #     do_sample=True,
        #     top_k=10,
        #     num_return_sequences=1,
        #     eos_token_id=falcon_tokenizer.eos_token_id,
        # )
        # for seq in sequences:
        #     st.write("Response: ", seq['generated_text'])
