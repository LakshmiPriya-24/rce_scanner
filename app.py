# app.py
from flask import Flask, render_template, request
from scanner import scan

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your own secret key.

@app.route('/')
def index():
    return render_template('index.html', scan_result=None)

@app.route('/scan', methods=['POST'])
def scanner():
    script_path = request.form.get('script_path')
    extension = request.form.get('extension')

    vulnerabilities_results, severity_results, mitigation_results = scan(script_path, extension)

    if vulnerabilities_results or severity_results or mitigation_results:
        scan_result = (vulnerabilities_results, severity_results, mitigation_results)
    else:
        scan_result = None  # Handle the case where the scanner function encountered an error

    return render_template('index.html', scan_result=scan_result)

if __name__ == '__main__':
    app.run(debug=True)
