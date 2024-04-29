import streamlit as st
import numpy as np
import pandas as pd
from transformers import AutoTokenizer, RobertaTokenizerFast, RobertaForSequenceClassification, pipeline
from datasets import Dataset
import torch
import hashlib


@st.cache(allow_output_mutation=True)
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

def dataframe_with_selections(df):
    df_with_selections = df.copy()
    df_with_selections.insert(0, "Select", False)

    # Get dataframe row-selections from user with st.data_editor
    edited_df = st.data_editor(
        df_with_selections,
        hide_index=True,
        column_config={"Select": st.column_config.CheckboxColumn(required=True)},
        disabled=df.columns,
        #num_rows="dynamic",
        use_container_width=True
    )

    # Filter the dataframe using the temporary column, then drop the column
    selected_rows = edited_df[edited_df.Select]
    return selected_rows.drop('Select', axis=1)
    
tokenizer,model = get_model()
# tokenizer,model,falcon_pipeline = get_model()

# user_input = st.text_area('Enter Text to Analyze')
user_input = st.file_uploader('Choose a file')
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
    df = pd.read_csv(user_input)
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
            st.write("Prediction: ", id2label[y_pred[i].item()])
            
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
            st.write("Prediction: ", id2label[y_pred[i].item()])
            
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
