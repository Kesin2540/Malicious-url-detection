import streamlit as st
st.set_page_config(page_title="Malicious URL Detector", layout="centered")

import pickle
import numpy as np
import pandas as pd
import tldextract
import ipaddress
from urllib.parse import urlparse

# === Load the trained model and metadata ===
with open('malicious_url_model.pkl', 'rb') as f:
    model_package = pickle.load(f)

model = model_package['model']
feature_columns = model_package['features']
label_map = model_package['label_map']
inv_label_map = {v: k for k, v in label_map.items()}
class_labels = [inv_label_map[i] for i in sorted(inv_label_map)]

# === Short URL detection list ===
SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", 
    "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "rebrand.ly", "bl.ink", "tr.im",
    "tiny.cc", "s.coop", "mcaf.ee", "t2m.io", "v.gd", "qr.ae", "0rz.tw", "x.co",
    "soo.gd", "lnkd.in", "shrtco.de", "chilp.it", "clck.ru", "s.id", "u.nu",
    "qr.net", "shorturl.at", "aka.ms", "gph.is", "ht.ly", "safe.mn", "wp.me",
    "y2u.be", "fb.me", "4sq.com", "snip.ly", "flip.it", "cur.lv", "kutt.it",
    "tiny.pl", "short.cm", "gg.gg", "ouo.io", "bc.vc", "festyy.com", "zee.gl"
}

# === Feature extraction from raw URL ===
def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    tld = tldextract.extract(url).suffix

    def fd_length():
        try:
            return len(path.split('/')[1])
        except:
            return 0

    def is_ip():
        try:
            ipaddress.ip_address(hostname)
            return True
        except:
            return False

    def count_digits():
        return sum(c.isdigit() for c in url)

    def count_letters():
        return sum(c.isalpha() for c in url)

    features = {
        "Hostname Length": len(hostname),
        "Path Length": len(path),
        "First Directory Length": fd_length(),
        "TLD Length": len(tld),
        "No. of -": url.count('-'),
        "No. of @": url.count('@'),
        "No. of ?": url.count('?'),
        "No. of %": url.count('%'),
        "No. of .": url.count('.'),
        "No. of =": url.count('='),
        "No. of http": url.count('http'),
        "No. of https": url.count('https'),
        "No. of www": url.count('www'),
        "No. of Numerical Values": count_digits(),
        "No. of Letters": count_letters(),
        "No. of Directories": url.count('/') - 1,
        "IP address or not": 1 if is_ip() else 0,
    }

    return features

st.markdown("""
    <style>
    body {
        background-image: url('https://ugra-tv.ru/upload/iblock/7d3/p3ljkfen1h6h8k7pc1p6m4acus84l5q5.png');
        background-size: cover;
        background-attachment: fixed;
        background-repeat: no-repeat;
    }

    .stApp {
        background-color: rgba(0, 0, 0, 0.7);  /* dark overlay for the content box */
        padding: 2rem;
        border-radius: 12px;
        max-width: 900px;
        margin: auto;
        box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(2.5px);
    }
    </style>
""", unsafe_allow_html=True)


# === Streamlit UI ===
st.title("🔍 Malicious URL Detection App")

# === Explanation Section ===
with st.expander("How the Model Works"):
    st.markdown("""
    This application uses a **Machine Learning model** trained on thousands of URLs labeled as **benign**, **malware**, **phishing**, or **defacement**.

    Here's a quick overview of how it works:

    - 🔍 The URL you enter is first **parsed into structured numerical features**, including:
        - Length of the hostname and path
        - Use of special characters (like `@`, `-`, `=`, `?`)
        - Number of digits, subdirectories, or dots
        - Whether the URL uses an IP address or shortening service

    - These features are passed into a **Random Forest classifier**, an ensemble of multiple decision trees that:
        - Works by building many trees on different random subsets of data
        - Aggregates their predictions for better accuracy and generalization
        - Reduces the risk of overfitting compared to a single decision tree

    - 🎯 The model then predicts the **most likely class** of the URL (benign, malware, phishing, or defacement), and returns **confidence scores** for each.

    This is a structural analysis — the model detects **malicious patterns in the URL itself** without querying external databases or web content.
    """)

with st.expander("What do these URL types mean?"):
    st.markdown("""
**Benign**: Safe websites with no harmful or deceptive content.  
**Malware**: Sites that try to install viruses, spyware, or ransomware.  
**Phishing**: Fake pages mimicking trusted services to steal credentials.  
**Defacement**: Websites that have been hacked and their content altered.

This tool analyzes the structure of a URL using machine learning to predict which category it likely falls into.
""")

st.markdown("---")

# === URL Input ===
st.markdown("### 🔗 Enter a URL below")
url_input = st.text_input("Paste the URL here:")

# === View Options ===
advanced_view = st.checkbox("Show Advanced View")

# === Prediction Section ===
if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("⚠️ Please enter a valid URL.")
    else:
        try:
            # Feature extraction
            feature_dict = extract_features_from_url(url_input)
            features_ordered = [feature_dict[col] for col in feature_columns]

            # Prediction
            proba = model.predict_proba([features_ordered])[0]
            prediction = np.argmax(proba)
            predicted_label = inv_label_map[prediction]

            st.markdown("### 🧾 Prediction Result:")
            if predicted_label == 'benign':
                st.success("✅ This URL is likely **benign**.")
            else:
                st.error(f"⚠️ This URL is likely **{predicted_label.upper()}**.")

            st.markdown("### 📊 Confidence Levels:")
            for i, label in enumerate(class_labels):
                pct = proba[i] * 100
                st.markdown(f"**{label.capitalize()}**: {pct:.2f}%")
                st.progress(int(pct))

            if advanced_view:
                st.write("🔬 Extracted Feature Values")
                feature_df = pd.DataFrame({
                "features": list(feature_dict.keys()),
                "value": list(feature_dict.values())
                })

                st.dataframe(feature_df.set_index("features"), use_container_width=True)

        except Exception as e:
            st.error(f"❌ Error processing the URL: {e}")
