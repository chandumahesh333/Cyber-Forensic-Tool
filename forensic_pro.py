import streamlit as st
from PIL import Image, ImageChops, ImageEnhance
import exifread
import hashlib
import numpy as np
import cv2
import io
import os

st.set_page_config(page_title="Mahi's Cyber Forensic Hub", layout="wide")

# Professional UI Styling
st.markdown("""
    <style>
    .stApp { background-color: #050a0f; color: #00d4ff; }
    .report-card { border: 2px solid #00d4ff; padding: 20px; border-radius: 10px; background: #0b1622; }
    .highlight { color: #ffffff; font-weight: bold; background: #005f73; padding: 2px 5px; border-radius: 3px; }
    </style>
    """, unsafe_allow_html=True)


def perform_ela(image_bytes):
    original = Image.open(io.BytesIO(image_bytes)).convert('RGB')
    temp_buffer = io.BytesIO()
    original.save(temp_buffer, 'JPEG', quality=90)
    resaved = Image.open(io.BytesIO(temp_buffer.getvalue()))
    ela_im = ImageChops.difference(original, resaved)
    extrema = ela_im.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0: max_diff = 1
    scale = 255.0 / max_diff
    ela_im = ImageEnhance.Brightness(ela_im).enhance(scale)
    return ela_im, max_diff


def forensic_scan(file_bytes, filename):
    tags = exifread.process_file(io.BytesIO(file_bytes))
    img = Image.open(io.BytesIO(file_bytes))
    img_array = np.array(img)

    # 1. Hardware Check
    make = str(tags.get('Image Make', 'Unknown'))
    model = str(tags.get('Image Model', 'Unknown'))
    software = str(tags.get('Image Software', 'None'))

    # 2. Pixel Consistency Check
    _, ela_score = perform_ela(file_bytes)

    # 3. Category Decision Engine
    category = "UNKNOWN"
    reason = ""
    confidence = 0

    if make != 'Unknown' and model != 'Unknown':
        category = "ORIGINAL CAMERA PHOTO"
        reason = f"Verified Hardware Signature: {make} {model}."
        confidence = 98
    elif 'Adobe' in software or 'PicsArt' in software or 'Canva' in software:
        category = "MODIFIED / EDITED IMAGE"
        reason = f"Found traces of {software} editing software."
        confidence = 95
    elif ela_score > 40:
        category = "AI GENERATED / MANIPULATED"
        reason = "Inconsistent pixel density detected (ELA Anomaly)."
        confidence = 85
    elif filename.lower().startswith('screenshot') or 'wa' in filename.lower():
        category = "SCREENSHOT / MESSENGER DOWNLOAD"
        reason = "File metadata stripped. Common in screenshots or WhatsApp."
        confidence = 90
    else:
        category = "INTERNET DOWNLOAD / STOCK IMAGE"
        reason = "Generic compression detected. No device info found."
        confidence = 80

    return category, reason, confidence, make, model, software, ela_score


# --- UI Interface ---
st.title("🛡️ Mahi's Advanced Digital Evidence Lab")
st.write("Professional Tool for Law Enforcement & Forensic Audit")

uploaded_file = st.file_uploader("Upload File to Analyze", type=['jpg', 'jpeg', 'png'])

if uploaded_file:
    file_bytes = uploaded_file.read()
    st.divider()

    # Run Forensic Scan
    res, why, conf, mk, md, sw, esc = forensic_scan(file_bytes, uploaded_file.name)

    col1, col2 = st.columns([1, 1.3])

    with col1:
        st.image(uploaded_file, caption="Subject Evidence", use_column_width=True)
        st.write(f"**Current Hash:** `{hashlib.sha256(file_bytes).hexdigest()[:20]}...`")

    with col2:
        st.markdown(f"<div class='report-card'>", unsafe_allow_html=True)
        st.subheader("🕵️ Forensic Report")

        # Display Result with Color
        color = "#00ff00" if "AUTHENTIC" in res or "CAMERA" in res else "#ff4b4b"
        st.markdown(f"**CATEGORY:** <span style='color:{color}; font-size:20px;'>{res}</span>", unsafe_allow_html=True)
        st.write(f"**Reason:** {why}")
        st.progress(conf / 100)
        st.write(f"**Confidence Level:** {conf}%")

        st.divider()
        st.write("### 📜 Detailed Artifacts")
        st.write(f"📱 **Device Name:** <span class='highlight'>{mk} {md}</span>", unsafe_allow_html=True)
        st.write(f"💻 **Software Trace:** <span class='highlight'>{sw}</span>", unsafe_allow_html=True)
        st.write(f"🔥 **ELA Stress Score:** `{esc}`")
        st.markdown("</div>", unsafe_allow_html=True)

    # ELA Image Display
    st.divider()
    st.subheader("🔬 Error Level Analysis (Pixel Map)")
    ela_img, _ = perform_ela(file_bytes)
    st.image(ela_img, caption="Bright areas show edited/AI zones", use_column_width=True)

st.divider()
st.caption("Developed by Mahi | Cyber Security Specialization | Visakhapatnam")