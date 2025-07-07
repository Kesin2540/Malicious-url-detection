import streamlit as st
st.set_page_config(page_title="Malicious URL Detector", layout="centered")

import pickle
import numpy as np
import pandas as pd
import tldextract
import ipaddress
from urllib.parse import urlparse, urlunparse 
from pathlib import Path
import math 


try:
    with open('malicious_url_model.pkl', 'rb') as f:
        model_package = pickle.load(f)

    model = model_package['model']
    feature_columns = model_package['features'] 
    label_map = model_package['label_map']
    inv_label_map = {v: k for k, v in label_map.items()}
    class_labels = [inv_label_map[i] for i in sorted(inv_label_map)] 
except FileNotFoundError:
    st.error("Error: 'malicious_url_model.pkl' not found. Please ensure the model training script has been run successfully.")
    st.stop()
except Exception as e:
    st.error(f"Error loading model: {e}")
    st.stop()

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "rebrand.ly", "bl.ink", "tr.im",
    "tiny.cc", "s.coop", "mcaf.ee", "t2m.io", "v.gd", "qr.ae", "0rz.tw", "x.co",
    "soo.gd", "lnkd.in", "shrtco.de", "chilp.it", "clck.ru", "s.id", "u.nu",
    "qr.net", "shorturl.at", "aka.ms", "gph.is", "ht.ly", "safe.mn", "wp.me",
    "y2u.be", "fb.me", "4sq.com", "snip.ly", "flip.it", "cur.lv", "kutt.it",
    "tiny.pl", "short.cm", "gg.gg", "ouo.io", "bc.vc", "festyy.com", "zee.gl"
}


top_sites_path = Path("top-1m.csv") 

top_sites_set = set()
if top_sites_path.exists():
    try:
        with top_sites_path.open(encoding='utf-8') as f:
            for line in f:
                try:
                    
                    parts = line.strip().split(",")
                    if len(parts) > 1: 
                        domain = parts[1]
                        top_sites_set.add(domain.lower())
                except ValueError:
                    continue 
    except Exception as e:
        st.warning(f"Error loading top-1m.csv: {e}. 'Is Top Site' feature may be inaccurate.")
else:
    st.warning(f"Top-1M file not found at {top_sites_path.resolve()} — 'Is Top Site' will be 0.")



def is_shortened(hostname): 
    try:
        hostname_str = str(hostname)
        return 1 if hostname_str.lower() in SHORTENERS else 0
    except:
        return 0

def is_ip(hostname): 
    try:
        hostname_str = str(hostname)
        if hostname_str:
            ipaddress.ip_address(hostname_str)
            return True
        return False
    except ValueError:
        return False
    except Exception:
        return False

def count_digits(s):
    s_str = str(s)
    return sum(c.isdigit() for c in s_str)

def count_special_chars(s, char):
    s_str = str(s)
    return s_str.count(char)

def query_param_count(url_full): 
    try:
        url_full_str = str(url_full)
        return urlparse(url_full_str).query.count('=')
    except:
        return 0

def word_char_ratio(s):
    s_str = str(s)
    letters = sum(c.isalpha() for c in s_str)
    return round(letters / len(s_str), 3) if len(s_str) > 0 else 0

def entropy(s):
    s_str = str(s)
    if len(s_str) == 0:
        return 0.0
    prob = [float(s_str.count(c)) / len(s_str) for c in dict.fromkeys(s_str)]
    return round(-sum([p * math.log2(p) for p in prob]), 3)

def is_top_domain(domain):
    domain_str = str(domain)
    domain_str = domain_str.replace("www.", "").lower() 
    return 1 if domain_str in top_sites_set else 0 
def first_directory_length(path):
    path_str = str(path)
    parts = path_str.split('/')
    return len(parts[1]) if len(parts) > 1 else 0

def _extract_features_core(url):
    data = {
        "URL": url,
        "Domain": "",
        "Hostname Length": 0,
        "Path Length": 0,
        "First Directory Length": 0,
        "TLD Length": 0,
        "No. of -": count_special_chars(url, '-'),
        "No. of @": count_special_chars(url, '@'),
        "No. of ?": count_special_chars(url, '?'),
        "No. of %": count_special_chars(url, '%'),
        "No. of .": count_special_chars(url, '.'),
        "No. of =": count_special_chars(url, '='),
        "No. of Numerical Values": count_digits(url),
        "Word-to-Char Ratio": word_char_ratio(url),
        "No. of Directories": count_special_chars(url, '/') - 1,
        "Query Param Count": query_param_count(url),
        "Path Entropy": 0.0,
        "IP address or not": 0,
        "Shortened Url Used": 0,
        "Uses HTTPS": 0,
        "Is Top Site": 0,
    }

    parsed = None
    url_str = str(url)

    try:
        
        full_url_for_parse = url_str if "://" in url_str else "http://" + url_str
        
        try:
            parsed = urlparse(full_url_for_parse)
        except ValueError as e:
            st.warning(f"URL parsing ValueError for '{url_str}': {e}. Returning default features for this URL.")
            return data
        except Exception as e:
            st.warning(f"General URL parsing error for '{url_str}': {e}. Returning default features for this URL.")
            return data

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        domain = tldextract.extract(url_str).domain 
        tld_suffix = tldextract.extract(url_str).suffix

        data.update({
            "Domain": domain,
            "Hostname Length": len(hostname),
            "Path Length": len(path),
            "First Directory Length": first_directory_length(path),
            "TLD Length": len(tld_suffix),
            "Uses HTTPS": 1 if parsed.scheme == "https" else 0,
            "IP address or not": is_ip(hostname),
            "Shortened Url Used": is_shortened(hostname),
            "Is Top Site": is_top_domain(domain + "." + tld_suffix if domain and tld_suffix else domain), 
            "Path Entropy": entropy(path),
        })

    except Exception as e:
        st.error(f"An unexpected error occurred during feature calculation for '{url}': {e}. Using default values for this URL.")

    return data

def extract_features_for_prediction(url):
    raw_features = _extract_features_core(url)
    
    ordered_features = []
    for col in feature_columns:
        val = raw_features.get(col, 0)
        val = pd.to_numeric(val, errors='coerce')
        ordered_features.append(val if not pd.isna(val) else 0)

    return ordered_features

def add_www_if_missing(url_string):
    temp_url_string = url_string
    if "://" not in temp_url_string:
        temp_url_string = "http://" + temp_url_string

    parsed_url = urlparse(temp_url_string)
    
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc 
    path = parsed_url.path
    params = parsed_url.params
    query = parsed_url.query
    fragment = parsed_url.fragment

    if (not netloc or
        netloc.startswith("www.") or
        is_ip(netloc)):
        return url_string 

    extracted = tldextract.extract(temp_url_string)
 
    if not extracted.subdomain:
        new_netloc = "www." + netloc
        reconstructed_url = urlunparse((scheme, new_netloc, path, params, query, fragment))
        return reconstructed_url
    
    return url_string 


st.markdown("""
    <style>
    body {
        /* This background-image URL might break if the source goes down */
        background-image: url('https://ugra-tv.ru/upload/iblock/7d3/p3ljkfen1h6h8k7pc1p6m4acus84l5q5.png');
        background-size: cover;
        background-attachment: fixed;
        background-repeat: no-repeat;
    }

    .stApp {
        background-color: rgba(0, 0, 0, 0.7);
        padding: 2rem;
        border-radius: 12px;
        max-width: 900px;
        margin: auto;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(2.5px);
    }
    h1, h2, h3, h4, h5, h6, .stMarkdown, .stText, .stButton, .stTextInput label {
        color: #FFFFFF; /* White text for better readability on dark background */
    }
    .stProgress > div > div {
        background-color: #4CAF50; /* Green progress bar */
    }
    .stSuccess {
        background-color: #28a745; /* Bootstrap success green */
        color: white;
    }
    .stError {
        background-color: #dc3545; /* Bootstrap error red */
        color: white;
    }
    .stWarning {
        background-color: #ffc107; /* Bootstrap warning yellow */
        color: black;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔍 Malicious URL Detection App")

with st.expander("How the Model Works"):
    st.markdown("""
This app uses a **machine learning model** to classify URLs into two categories:
**legitimate** and **Phishing**.

- It analyzes the structure of the URL using features such as:
  - Hostname and path length, TLD, directory count
  - Presence of special characters (`-`, `@`, `?`, `%`, `.`, `=`)
  - Number of numerical values, word-to-character ratio, query parameter count, path entropy
  - Whether it's an IP address, if a shortened URL service is used, HTTPS usage
  - Whether the domain is on a list of top 1 million sites.

- It uses a **Random Forest Classifier** trained on thousands of labeled URLs.

No internet connection (beyond initial setup of top-1m.csv) or database query is required for prediction — it's a fast, offline check.
    """)

with st.expander("What do these URL types mean?"):
    st.markdown("""
- **Legitimate**: These are considered safe and trustworthy websites.
- **Phishing**: These URLs are designed to deceive users into revealing sensitive information (like usernames, passwords, credit card details) by mimicking legitimate websites.
    """)

st.markdown("---")

st.markdown("### 🔗 Enter a URL below (Please use the complete URL)")
url_input = st.text_input("Paste the URL here:")

advanced_view = st.checkbox("Show Advanced View (Extracted Features)")

if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("⚠️ Please enter a valid URL.")
    else:
        try:
            processed_url_for_features = add_www_if_missing(url_input)
            
            if processed_url_for_features != url_input:
                st.info(f"URL adjusted for analysis: `{processed_url_for_features}`")

            features_for_prediction = extract_features_for_prediction(processed_url_for_features)

            proba = model.predict_proba([features_for_prediction])[0]
            prediction_idx = np.argmax(proba)
            predicted_label = inv_label_map[prediction_idx]

            st.markdown("### 🧾 Prediction Result:")
            if predicted_label == 'legitimate':
                st.success("✅ This URL is likely **Legitimate**.")
            else:
                st.error(f"⚠️ This URL is likely **{predicted_label.upper()}**.")

            st.markdown("### 📊 Confidence Levels:")
            sorted_indices = np.argsort(proba)[::-1]
            sorted_proba = proba[sorted_indices]
            sorted_labels = [class_labels[i] for i in sorted_indices]

            for i in range(len(sorted_labels)):
                label = sorted_labels[i]
                pct = sorted_proba[i] * 100
                st.markdown(f"**{label.capitalize()}**: {pct:.2f}%")
                st.progress(int(pct))

            if advanced_view:
                st.write("🔬 Extracted Feature Values (used by the model)")
                feature_dict_for_display = _extract_features_core(processed_url_for_features)
                filtered_feature_dict = {k: feature_dict_for_display[k] for k in feature_columns if k in feature_dict_for_display}
                
                display_df_data = []
                for col in feature_columns:
                    display_df_data.append({"Feature": col, "Value": filtered_feature_dict.get(col, "N/A")})
                
                st.dataframe(pd.DataFrame(display_df_data).set_index("Feature"), use_container_width=True)

        except Exception as e:
            st.error(f"❌ An unexpected error occurred while processing the URL. Please check the URL format or consult the logs.")
            st.exception(e)