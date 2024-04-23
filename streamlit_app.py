import streamlit as st
import numpy as np
from transformers import AutoTokenizer, RobertaTokenizerFast, RobertaForSequenceClassification, pipeline
import torch
import hashlib

@st.cache(allow_output_mutation=True)
def get_model():
    tokenizer = RobertaTokenizerFast.from_pretrained("ehsanaghaei/SecureBERT_Plus")
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
    return tokenizer,model #,falcon_pipeline


tokenizer,model = get_model()

user_input = st.text_area('Enter Text to Analyze')
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

# def FLLE_converter(user_input):
#     df_llm = pd.DataFrame(columns=['Text', 'Label', 'Type'])
#     df_llm['Text'] = required_columns[required_columns.columns[:-2]].apply(lambda x: x.name+'$'+x.astype(str), 
#                                    axis=0).apply(np.vectorize(lambda x: hashlib.shake_256(x.encode("utf-8")).hexdigest(16)), 
#                                                  axis=0).agg(' '.join, axis=1)   # df.shape (2219201, 63)
#     # df_llm[['Label', 'Type']] = required_columns[required_columns.columns[[-2,-1]]].iloc[:5000]
#     df_llm[['Label', 'Type']] = required_columns[required_columns.columns[[-2,-1]]]
#     return FLLE_input

if user_input and button :
    test_sample = tokenizer([user_input], add_special_tokens=True, truncation=True, padding="max_length", max_length=512, return_tensors='pt')
    test_sample = {k: v for k,v in test_sample.items()}
    # test_sample
    output = model(**test_sample)
    st.write("Logits: ",output.logits)
    y_pred = np.argmax(output.logits.detach().numpy(),axis=1)
    st.write("Prediction: ", id2label[np.argmax(output.logits.detach().numpy(), axis=1).item()])
    # sequences = falcon_pipeline(
    #    f"Our Cyber Security model 'DAXPRO_Bert' detected {id2label[np.argmax(output.logits.detach().numpy(), axis=1).item()]}. Propose security policies and procedures for data protection, password management, and social engineering awareness, if 'DAXPRO_Bert' detected a cyber threat.",
    #     max_length=200,
    #     do_sample=True,
    #     top_k=10,
    #     num_return_sequences=1,
    #     eos_token_id=falcon_tokenizer.eos_token_id,
    # )
    # for seq in sequences:
    #     st.write("Response: ", seq['generated_text'])
