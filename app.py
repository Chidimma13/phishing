import streamlit as st
import joblib
import pickle
import numpy as np
import pandas as pd
import urllib.parse
import socket
import re

# Load the ensemble model and scaler
def load_model_and_scaler():
    try:
        with open('/Users/chidd/Downloads/ensemble_model.pkl', 'rb') as model_file:
            model = pickle.load(model_file)
        with open('/Users/chidd/Downloads/scaler.pkl', 'rb') as scaler_file:
            scaler = pickle.load(scaler_file)
        return model, scaler
    except FileNotFoundError:
        st.error("Model or scaler file not found. Make sure the files are correctly located.")
        st.stop()
    except Exception as e:
        st.error(f"An error occurred while loading the model or scaler: {e}")
        st.stop()

ensemble_model, scaler = load_model_and_scaler()

# Function to extract features from the URL
def extract_features_from_url(url):
    parsed_url = urllib.parse.urlparse(url)
    
    def has_ip_address(url):
        try:
            socket.inet_aton(urllib.parse.urlparse(url).netloc)
            return 1
        except socket.error:
            return 0
    
    def count_sensitive_words(url):
        # Example sensitive words list; you can expand this list
        sensitive_words = ['login', 'secure', 'account', 'update', 'bank', 'password']
        return sum(1 for word in sensitive_words if word in url.lower())
    
    length_of_url = len(url)
    using_https = 1 if parsed_url.scheme == 'https' else 0
    number_of_dots = url.count('.')
    ip_address = has_ip_address(url)
    num_sensitive_words = count_sensitive_words(url)
    no_https = 1 - using_https
    https_in_hostname = 1 if 'https' in parsed_url.netloc else 0
    num_dash = url.count('-')
    subdomain_level = len(parsed_url.netloc.split('.')) - 2
    path_level = len(parsed_url.path.split('/')) - 1
    domain_in_paths = 1 if parsed_url.path in parsed_url.netloc else 0
    hostname_length = len(parsed_url.netloc)
    query_length = len(parsed_url.query)
    double_slash_in_path = 1 if '//' in parsed_url.path else 0
    
    # For placeholders, if content analysis is not available, we keep them at 0
    features = {
        'UrlLength': length_of_url,
        'NumDots': number_of_dots,
        'IpAddress': ip_address,
        'NumSensitiveWords': num_sensitive_words,
        'NoHttps': no_https,
        'HttpsInHostname': https_in_hostname,
        'PopUpWindow': 0,  # Placeholder
        'PctExtHyperlinks': 0,  # Placeholder
        'PctExtNullSelfRedirectHyperlinksRT': 0,  # Placeholder
        'FrequentDomainNameMismatch': 0,  # Placeholder
        'InsecureForms': 0,  # Placeholder
        'PctNullSelfRedirectHyperlinks': 0,  # Placeholder
        'NumDash': num_dash,
        'SubmitInfoToEmail': 0,  # Placeholder
        'PctExtResourceUrls': 0,  # Placeholder
        'IframeOrFrame': 0,  # Placeholder
        'SubdomainLevel': subdomain_level,
        'PathLevel': path_level,
        'DomainInPaths': domain_in_paths,
        'HostnameLength': hostname_length,
        'QueryLength': query_length,
        'DoubleSlashInPath': double_slash_in_path,
    }
    
    feature_vector = [
        features['UrlLength'],
        features['NumDots'],
        features['IpAddress'],
        features['NumSensitiveWords'],
        features['NoHttps'],
        features['HttpsInHostname'],
        features['PopUpWindow'],
        features['PctExtHyperlinks'],
        features['PctExtNullSelfRedirectHyperlinksRT'],
        features['FrequentDomainNameMismatch'],
        features['InsecureForms'],
        features['PctNullSelfRedirectHyperlinks'],
        features['NumDash'],
        features['SubmitInfoToEmail'],
        features['PctExtResourceUrls'],
        features['IframeOrFrame'],
        features['SubdomainLevel'],
        features['PathLevel'],
        features['DomainInPaths'],
        features['HostnameLength'],
        features['QueryLength'],
        features['DoubleSlashInPath'],
    ]
    
    return feature_vector

# Streamlit interface setup
st.set_page_config(page_title="Phishing Detection", page_icon="🔒", layout="centered")

st.title('🔒 Phishing Detection System')
st.write("Enter a URL to check whether it is legitimate or a phishing attempt.")

url_input = st.text_input("🔗 Enter the URL here:")

if st.button('Predict'):
    if url_input:
        features = extract_features_from_url(url_input)
        features_df = pd.DataFrame([features])
        scaled_features = scaler.transform(features_df)
        prediction = ensemble_model.predict(scaled_features)
        
        result = 'Phishing' if prediction[0] == 1 else 'Legitimate'
        
        st.markdown(f"### 🔍 The URL is likely: *{result}*")
        
        if result == 'Phishing':
            st.error("🚨 Warning! This URL is likely a phishing attempt.")
        else:
            st.success("✅ This URL appears to be legitimate.")
        
    else:
        st.error("Please enter a valid URL.")