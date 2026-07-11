# Internship Scam & Fraud Detection System

An intelligent web application developed during a college internal hackathon to detect and classify fraudulent internship postings. The project leverages Machine Learning to analyze text descriptions and compute a scam probability score, helping students navigate job boards safely.

---

## 🚀 Features
* **Real-time Prediction:** Uses a trained Machine Learning model to evaluate whether an internship posting is legitimate or fraudulent.
* **Text Analysis:** Implements text vectorization to process job descriptions and catch common scam indicators.
* **Web Interface:** A simple, user-friendly frontend for submitting job details and viewing results instantly.

## 🛠️ Tech Stack
* **Frontend:** HTML5, CSS3
* **Backend:** Python (Flask)
* **Machine Learning:** Scikit-learn (TF-IDF Vectorization & Classification)

## 📁 Repository Structure
* `app.py` — The core Python backend handling routing and model inference.
* `login.html` & `login.css` — The user interface layout and styling.
* `internship_scam_model.pkl` — The trained machine learning classification model.
* `vectorizer.pkl` — The saved TF-IDF vectorizer used to transform text input.



## 🔮 Future Improvements & Known Issues
* **Model Accuracy:** Planning to expand the dataset to train the model on a wider variety of recent remote work scams.
* **Database Integration:** Working on adding a backend database to store flagged job postings for community reporting.
* **UI Refinement:** Improving error handling on the web interface to display descriptive error messages for invalid text inputs.
W
