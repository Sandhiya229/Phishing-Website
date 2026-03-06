from flask import Flask, render_template, request,jsonify
import pickle
from Feature import featureExtraction, feature_names
from bson.objectid import ObjectId

#MongoDB connection
from pymongo import MongoClient
from datetime import datetime


app = Flask(__name__)

# Load RandomForestClassifier model
rf_model = pickle.load(open('RandomForestClassifier.pickle.dat', 'rb'))
# Load XGBoostClassifier model
xgb_model = pickle.load(open('XGBoostClassifier.pickle.dat', 'rb'))

#MongoDB ClientConnection
client = MongoClient("mongodb://localhost:27017/")
db = client["phishing_db"]
collection = db["checked_urls"]



@app.route('/')
def index():
    recent_url = list(collection.find().sort("checked_at",-1).limit(7))
    
    total = collection.count_documents({"user_feedback":{"$exists":True}})
    correct = collection.count_documents({"user_feedback":True})
    
    accuracy = round((correct/total)*100,2) if total > 0  else 0
    
    return render_template('index.html',recent_url=recent_url, accuracy=accuracy)

@app.route('/check', methods=['POST'])
def check():
    url = request.form.get("url", "").strip()
    # Case 1: Empty input
    if not url:
        recent_url = list(collection.find().sort("checked_at", -1).limit(7))
        return render_template('index.html', recent_url=recent_url, message="Empty URL")

    # Case 2: Already checked
    existing = collection.find_one({"url": url})
    if existing:
        recent_url = list(collection.find().sort("checked_at", -1).limit(7))
        return render_template('index.html', recent_url=recent_url, message="Already checked")

    # Case 3: Fresh URL → process normally
    features = featureExtraction(url)
    rf_prediction = predict_label(url, rf_model)
    xgb_prediction = predict_label(url, xgb_model)
    
    final_prediction = rf_prediction if rf_prediction == xgb_prediction else rf_prediction
    
    collection.insert_one({
        "url": url,
        "rf_prediction": rf_prediction,
        "xgb_prediction": xgb_prediction,
        "final_prediction": final_prediction,
        "checked_at": datetime.now(),
        "user_feedback": None
    })    
    
    feature_tuples = list(zip(feature_names, features))
    return render_template('result.html', 
                           url=url,
                           rf_prediction=rf_prediction,
                           xgb_prediction=xgb_prediction,
                           features=feature_tuples)

@app.route('/feedback/<item_id>/<status>',methods=['POST'])
def feedback(item_id,status):
    if status not in ["true","false"]:
        return jsonify({"error":"Invalid Status"}),400
    collection.update_one(
        {"_id":ObjectId(item_id)},
        {"$set":{"user_feedback":True if status == "true" else False}}
    )
    return jsonify({"Success":True})

def predict_label(url, model):
    # Extract features from the URL
    features = featureExtraction(url)

    # Use the model to predict the label based on the features
    prediction = model.predict([features])[0]

    # Classify the URL based on the prediction
    if prediction == 1:
        label = "Phishing"
    else:
        label = "Legitimate"

    return label

if __name__ == '__main__':
    app.run(debug=True)
