from flask import Flask, request, render_template, redirect, url_for, jsonify
import pandas as pd
import threading
import time
import pywhatkit as kit
import os

app = Flask(__name__)

progress_status = {
    "total": 0,
    "sent": 0,
    "failed": []
}

def send_message(number, message, attachment=None):
    try:
        if attachment:
            kit.sendwhats_image(
                receiver=number, 
                img_path=attachment, 
                caption=message, 
                tab_close=True, 
                close_time=15
            )
        else:
            kit.sendwhatmsg_instantly(
                phone_no=number, 
                message=message, 
                tab_close=True
            )
        progress_status["sent"] += 1
    except Exception as e:
        progress_status["failed"].append(f"Failed to send message to {number}: {str(e)}")

def send_bulk_messages(numbers, message, attachment=None):
    for number in numbers:
        send_message(number, message, attachment)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send_message_route():
    global progress_status
    progress_status = {
        "total": 0,
        "sent": 0,
        "failed": []
    }

    file = request.files['file']
    try:
        df = pd.read_csv(file)
        if 'Number' not in df.columns:
            return "CSV file must contain a 'Number' column.", 400
        numbers = df['Number'].astype(str).apply(lambda x: "+" + x).tolist()
    except Exception as e:
        return f"Error reading CSV file: {str(e)}", 400

    message = request.form['message']
    attachment_file = request.files.get('attachment')
    attachment = None

    if attachment_file:
        attachment_path = os.path.join('uploads', attachment_file.filename)
        attachment_file.save(attachment_path)
        attachment = attachment_path

    progress_status["total"] = len(numbers)

    thread = threading.Thread(target=send_bulk_messages, args=(numbers, message, attachment))
    thread.start()

    return redirect(url_for('progress'))

@app.route('/progress')
def progress():
    return render_template('progress.html')

@app.route('/progress_status')
def get_progress_status():
    return jsonify(progress_status)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
