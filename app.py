import os
import flask
from flask import Flask, redirect, request, session, url_for, render_template_string
from google_auth_oauthlib.flow import Flow
import googleapiclient.discovery
import google.oauth2.credentials
import base64
import re
import json # 新增 json 函式庫

# --- Flask App 設定 ---
app = Flask(__name__)
# 從環境變數讀取 SECRET_KEY，這是在 Render 平台上設定的
app.secret_key = os.environ.get('SECRET_KEY', 'a-default-secret-key-for-local-dev')

# --- Google API 設定 ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

# 函式：從環境變數建立 Google 憑證資訊
def get_client_config():
    # 在 Render 上，我們會將 credentials.json 的內容儲存在一個名為 GOOGLE_CREDENTIALS 的環境變數中
    credentials_json_str = os.environ.get('GOOGLE_CREDENTIALS')
    if credentials_json_str:
        return json.loads(credentials_json_str)
    else:
        # 如果在本機測試，則繼續讀取檔案
        with open('credentials.json', 'r') as f:
            return json.load(f)

# --- 網頁模板 (維持不變) ---
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Gmail 驗證碼讀取器</title></head>
<body>
    <h1>Gmail 驗證碼讀取器</h1>
    <p>請登入您的 Google 帳戶以繼續。</p>
    <a href="/login"><button>使用 Google 帳戶登入</button></a>
</body>
</html>
"""

MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Gmail 驗證碼讀取器</title></head>
<body>
    <h1>Gmail 驗證碼讀取器</h1>
    <p>您已登入。點擊下方按鈕開始查詢最新的驗證碼。</p>
    <button onclick="fetchCode()">查詢最新驗證碼</button>
    <a href="/logout"><button>登出</button></a>
    <h2 id="result"></h2>
    <script>
        function fetchCode() {
            document.getElementById('result').innerText = '查詢中...';
            fetch('/get_code')
                .then(response => response.json())
                .then(data => {
                    if (data.code) {
                        document.getElementById('result').innerText = '找到的驗證碼是： ' + data.code;
                    } else {
                        document.getElementById('result').innerText = '錯誤：' + data.error;
                    }
                })
                .catch(error => {
                    document.getElementById('result').innerText = '請求失敗：' + error;
                });
        }
    </script>
</body>
</html>
"""

# --- 路由 (Routes) ---

@app.route('/')
def index():
    if 'credentials' not in session:
        return render_template_string(LOGIN_TEMPLATE)
    return render_template_string(MAIN_TEMPLATE)

@app.route('/login')
def login():
    flow = Flow.from_client_config(
        get_client_config(), scopes=SCOPES, redirect_uri=url_for('oauth2callback', _external=True))
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_config(
        get_client_config(), scopes=SCOPES, state=state, redirect_uri=url_for('oauth2callback', _external=True))
    
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('credentials', None)
    return redirect(url_for('index'))

@app.route('/get_code')
def get_code():
    if 'credentials' not in session:
        return flask.jsonify({'error': '使用者未登入'}), 401

    try:
        credentials = google.oauth2.credentials.Credentials(**session['credentials'])
        gmail = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
        
        # --- 您可以在這裡修改查詢條件 ---
        search_query = 'from:openai.com subject:"code" is:unread'
        # --- 修改結束 ---

        result = gmail.users().messages().list(userId='me', q=search_query, maxResults=1).execute()
        messages = result.get('messages', [])

        if not messages:
            return flask.jsonify({'error': '找不到符合條件的郵件'})

        msg = gmail.users().messages().get(userId='me', id=messages[0]['id']).execute()
        payload = msg['payload']
        parts = payload.get('parts')
        data = ""
        if parts:
            for part in parts:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    break
        else:
            data = payload['body']['data']
        
        email_body = base64.urlsafe_b64decode(data).decode('utf-8')
        match = re.search(r'\b(\d{6})\b', email_body)
        
        if match:
            return flask.jsonify({'code': match.group(1)})
        else:
            return flask.jsonify({'error': '在郵件內文中找不到 6 位數字驗證碼'})

    except Exception as e:
        return flask.jsonify({'error': f'發生錯誤: {str(e)}'}), 500

# 移除 if __name__ == '__main__': ... 的部分，因為 Gunicorn 會直接處理 app 物件