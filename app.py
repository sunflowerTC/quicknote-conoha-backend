import os
import requests
import json
import jwt
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from functools import wraps
from decorators import login_required_api

from flask import Flask, render_template, redirect, request, g, session, jsonify, current_app
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_session import Session
from flask_migrate import Migrate

from redis import Redis
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

from dotenv import load_dotenv

from config import Config
from db.db import db
from models import Account, Email, Job, ApiConfig, Instruction

import logging
from logging_config import setup_logging, get_logger_with_ip

import msal

from scheduler import load_schedules

import openai
import outlook_mailbox
import onenote
import openai_api

from services.auth_service import save_user_tokens_to_db
from webhook_tasks import process_webhook_notification

import utils

from routes import register_routes

"""mailsystem.envファイルを読み込む"""
load_dotenv("mailsystem.env")

"""IPアドレスを取得"""
server_ip = utils.get_local_ip() or "Unknown IP"
setup_logging(server_ip)

"""サーバー用ロガーを取得"""
base_logger = logging.getLogger("mailsystem")
base_logger.info("-------メールシステム起動-------")

"""現在の日時を取得"""
now_date, formatted_day_time = utils.current_date()

"""スケジューラ設定"""
tokyo_timezone = ZoneInfo("Asia/Tokyo")

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 拡張機能の初期化
    Bootstrap(app)
    CORS(app, supports_credentials=True, origins=["https://churchill-c.com", "https://www.churchill-c.com"])
    db.init_app(app)
    migrate = Migrate(app, db, directory="migrations")

    app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')  # 環境変数から読み込む
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True  # セッションデータを署名付きで保存
    app.config['SESSION_KEY_PREFIX'] = 'session:'
    app.config['SESSION_REDIS'] = Redis.from_url("redis://localhost:6379/0")
    app.config['SESSION_SERIALIZER'] = 'json'

    # ✅ 必須設定: Cookie がフロントエンドで使用できるようにする
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True

    Session(app)

    # ✅ ここで app_context を使って api_config を呼ぶ
    with app.app_context():
        try:
            from utils import api_config
            client_id, client_secret, tenant_id, user_id, redirect_uri, authority, scopes, user_scopes = api_config()
            msal_app = msal.ConfidentialClientApplication(
                client_id,
                authority=authority,
                client_credential=client_secret
            )

            # アプリの設定に格納して共有
            app.config["MSAL_APP"] = msal_app
            app.config["MS_CLIENT_ID"] = client_id
            app.config["MS_REDIRECT_URI"] = redirect_uri
            app.config["MS_SCOPES"] = scopes
            app.config["MS_USER_SCOPES"] = user_scopes
            
        except Exception as e:
            app.logger.warning(f"⚠️ Graph API設定の読み込みに失敗: {e}")

    register_routes(app)

    # ✅ ユーザーIPロガーを before_request でセット
    @app.before_request
    def before_request():
        user_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "Unknown IP"
        g.logger = get_logger_with_ip(user_ip)

    return app

# Flaskアプリを作成
app = create_app()

"""ログイン認証"""
@app.route('/api/user_login', methods=['POST'])
def user_login():
    RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')

    data = request.json
    recaptcha_token = data.get('recaptchaToken')

    # reCAPTCHA トークンの検証
    recaptcha_response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_token
        }
    )

    result = recaptcha_response.json()
    if not result.get('success') or result.get('score', 0) < 0.7:
        g.logger.warning(f"🛑 ログイン失敗 (reCAPTCHA不正) email={email}, userid={userid}, score={result.get('score')}")
        return jsonify({"success": False, "message": "reCAPTCHA の検証に失敗しました。"}), 400

    # ユーザー認証ロジック
    email = data.get('email')
    userid = data.get('userid')
    password = data.get('password')
    totp = data.get('totp')

    # DB からユーザー情報を取得
    user = Account.query.filter_by(email=email, userid=userid).first()

    if not user:
        g.logger.warning(f"🛑 ログイン失敗 (ユーザー存在なし) email={email}, userid={userid}")
        return jsonify({"success": False, "message": "ユーザーが存在しません。"}), 401

    # パスワードの検証 (DB に保存されているハッシュと比較)
    if not user.password_hash or not check_password_hash(user.password_hash, password):
        g.logger.warning(f"🛑 ログイン失敗 (パスワード不一致) email={email}, userid={userid}")
        return jsonify({"success": False, "message": "パスワードが間違っています。"}), 401

    # TOTP (Google Authenticator など) の検証
    if user.totp_secret:
        if not totp:
            g.logger.warning(f"🛑 ログイン失敗 (TOTP未入力) email={email}, userid={userid}")
            return jsonify({"success": False, "message": "TOTP が入力されていません。"}), 401
        totp_verifier = pyotp.TOTP(user.totp_secret)
        if not totp_verifier.verify(totp):
            g.logger.warning(f"🛑 ログイン失敗 (TOTP不一致) email={email}, userid={userid}")
            return jsonify({"success": False, "message": "ワンタイムパスワードが間違っています。"}), 401

    # 認証成功後にセッション情報を保存
    session["user_id"] = user.id
    session["user_role"] = user.role

    g.logger.info(f"✅ ログイン成功 email={email}, userid={userid}, role={user.role}")

    return jsonify({
        "success": True,
        "redirect": "top",
        "user": {
            "userid": user.userid,
            "role": user.role
        }
    })

"""ログアウト処理"""
@app.route('/api/logout', methods=['POST'])
def logout():
    user_id = session.get("user_id")

    if user_id:
        g.logger.info(f"👋 ログアウト user_id={user_id}")

    # セッションをクリア
    session.clear()

    return jsonify({"success": True, "message": "ログアウトしました。"})

"""ユーザー登録"""
@app.route('/api/register_user', methods=['POST'])
@login_required_api
def register_user():
    data = request.json

    email = data.get('email')
    userid = data.get('userid')
    password = data.get('password')
    last_name = data.get('last_name', '')  # デフォルト値は空文字
    first_name = data.get('first_name', '')  # デフォルト値は空文字
    role = data.get('role', 'user')  # デフォルトは 'user'

    # すでに同じ email または userid のユーザーが存在するか確認
    existing_user = Account.query.filter((Account.email == email) | (Account.userid == userid)).first()
    if existing_user:
        return jsonify({"success": False, "message": "このメールアドレスまたはユーザーIDは既に登録されています。"}), 400

    # パスワードをハッシュ化
    password_hash = generate_password_hash(password)

    # TOTP_SECRET を生成
    totp_secret = pyotp.random_base32()

    # DB に新規ユーザーを登録
    new_user = Account(
        email=email,
        userid=userid,
        password_hash=password_hash,
        totp_secret=totp_secret,  # TOTP 秘密鍵を保存
        role=role,  # role を保存
        last_name=last_name,  # last_name を保存
        first_name=first_name  # first_name を保存
    )

    db.session.add(new_user)
    db.session.commit()

    # TOTP QRコードを取得
    qr_code_url = utils.get_totp_qr(email, totp_secret)

    print("QR Code URL:", qr_code_url)

    return jsonify({
        "success": True,
        "message": "ユーザー登録成功",
        "totp_qr": qr_code_url
    })

"""TOP画面表示"""
@app.route("/top", methods=['GET'])
def top():
    
    return render_template('top.html')

"""GraphAPI認証"""
@app.route("/api/graph", methods=['GET'])
def index():
    msal_app = current_app.config.get("MSAL_APP")
    scopes = current_app.config.get("MS_SCOPES")
    redirect_uri = current_app.config.get("MS_REDIRECT_URI")

    if not msal_app or not redirect_uri or not scopes:
        g.logger.error("⚠️ MSAL構成が正しく読み込まれていません")
        return "設定エラー", 500

    auth_url = msal_app.get_authorization_request_url(
        scopes=scopes,
        redirect_uri=redirect_uri
    )

    return redirect(auth_url)

@app.route("/api/auth/check", methods=["GET"])
def auth_check():
    msal_app = current_app.config.get("MSAL_APP")
    scopes = current_app.config.get("MS_SCOPES")
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    if not access_token:
        g.logger.warning("⚠️ セッションにアクセストークンが存在しません")
        return jsonify({"authenticated": False, "redirect": "/api/graph"}), 401

    try:
        # Access token の有効性を確認する
        url = "https://graph.microsoft.com/v1.0/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers=headers)

        if response.status_code == 401 and refresh_token:
            # アクセストークンが無効の場合はリフレッシュトークンを使用する
            result = msal_app.acquire_token_by_refresh_token(refresh_token, scopes=scopes)

            if "access_token" in result:
                new_access_token = result["access_token"]
                new_refresh_token = result.get("refresh_token", refresh_token)

                session["access_token"] = new_access_token
                session["refresh_token"] = new_refresh_token
                session.modified = True

                # ここで /me を叩き直して、graph_user_id を更新する
                headers = {"Authorization": f"Bearer {new_access_token}"}
                response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
                if response.status_code == 200:
                    graph_user_info = response.json()
                    graph_user_id = graph_user_info.get('id')
                    session["graph_user_id"] = graph_user_id
                    g.logger.info(f"✅ graph_user_id をセッションに保存しました: {graph_user_id}")

                    if graph_user_id:
                        save_user_tokens_to_db(graph_user_id, new_access_token, new_refresh_token)
                        g.logger.info(f"🔄 トークン更新成功（graph_user_id={graph_user_id}）")

                return jsonify({"authenticated": True, "access_token": new_access_token}), 200
            else:
                g.logger.error(f"❌ リフレッシュ失敗: {result.get('error_description', 'No detail')}")
                return jsonify({"authenticated": False, "redirect": "/api/graph"}), 401

        if response.status_code == 200:
            graph_user_info = response.json()
            graph_user_id = graph_user_info.get('id')
            session["graph_user_id"] = graph_user_id
            g.logger.info(f"✅ graph_user_id をセッションに保存しました: {graph_user_id}")
            return jsonify({"authenticated": True, "access_token": access_token}), 200

        g.logger.error(f"❌ GraphAPI応答異常: {response.status_code}")
        return jsonify({"authenticated": False, "redirect": "/api/graph"}), 401

    except requests.exceptions.RequestException as e:
        g.logger.exception("❌ Microsoft Graph APIへの通信エラー")
        return jsonify({"authenticated": False, "redirect": "/api/graph"}), 500

@app.route("/api/auth/callback", methods=["GET"])
def auth_callback():
    code = request.args.get("code")
    if not code:
        return "Authorization code not provided", 400

    msal_app = current_app.config.get("MSAL_APP")
    scopes = current_app.config.get("MS_SCOPES")
    redirect_uri = current_app.config.get("MS_REDIRECT_URI")

    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=scopes,
        redirect_uri=redirect_uri
    )

    if "access_token" in result:
        # アクセストークンとリフレッシュトークンをセッションに保存
        session["access_token"] = result["access_token"]
        session["refresh_token"] = result.get("refresh_token")
        session.modified = True

        g.logger.info(f"✅ access_tokenをセッションに保存しました: {session["access_token"]}")
        g.logger.info(f"✅ refresh_tokenをセッションに保存しました: {session["refresh_token"]}")

        # ここを追加！
        id_token = result.get("id_token")
        if id_token:
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            graph_user_id = decoded.get("oid") or decoded.get("sub")  # Azure ADなら "oid" / 一般的なOAuth2なら "sub"

            session["graph_user_id"] = graph_user_id
            g.logger.info(f"✅ graph_user_idをセッションに保存しました: {graph_user_id}")
        else:
            g.logger.error("❌ id_tokenが存在しません。graph_user_idを取得できません")
            return "ID Token not found", 400

        # セッション ID を取得
        session_id = request.cookies.get("session")
        redis_key = f"session:{session_id}"
        redis_data = app.config['SESSION_REDIS'].get(redis_key)

        # ログ出力で確認
        g.logger.info(f"✅ セッションが保存されました - セッションID: {session_id}")
        g.logger.info(f"Redis に保存されたデータ (生): {redis_data}")

        try:
            save_user_tokens_to_db(
                user_id=graph_user_id, 
                access_token=result["access_token"], 
                refresh_token=result.get("refresh_token")
            )
        except Exception as e:
            g.logger.error(f"❌ トークン保存中にエラーが発生しました: {str(e)}")
            return "Failed to save user tokens", 500

        try:
            decoded_data = redis_data.decode()  # デコードして確認する
            g.logger.info(f"Redis に保存されたデータ (デコード済み): {decoded_data}")
        except Exception as e:
            g.logger.error(f"Redis データのデコードに失敗: {e}")

        g.logger.info(f"✅ セッションが保存されました。セッションID: {session_id}")
        return redirect("/api/notebooks")
    else:
        error_message = result.get('error_description', 'Unknown error')
        g.logger.error(f"❌ Error obtaining token: {error_message}")
        return f"Error obtaining token: {error_message}", 400

"""Webhookエンドポイント"""
@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    validation_token = request.args.get('validationToken') or request.form.get('validationToken')
    if validation_token:
        g.logger.info(f"✅ validationToken を受信: {validation_token}")
        return validation_token, 200, {'Content-Type': 'text/plain'}

    try:
        config = db.session.query(ApiConfig).first()
        if not config or not config.webhook_enabled:
            g.logger.warning("🚫 Webhook は現在無効です。メール処理は停止されています")
            return jsonify({"error": "Webhook is disabled."}), 403

        if not request.is_json:
            g.logger.error("⚠️ Content-Typeがapplication/jsonではありません")
            return jsonify({"error": "Unsupported Media Type"}), 415

        data = request.get_json()
        if not data or 'value' not in data:
            g.logger.error("⚠️ webhookデータが不正です (valueが存在しない)")
            return jsonify({"error": "Invalid webhook data"}), 400

        g.logger.info(f"🚀 webhook起動: {datetime.utcnow().isoformat()} data={data}")

        for notification in data['value']:
            g.logger.info(f"📤 Celeryにタスクを送信中: message_id={notification.get('resourceData', {}).get('id')}")

            try:
                json.dumps(notification)  # ← ここで例外が出るならNG
                g.logger.info("📤 送信するnotificationはJSON変換OK")
            except Exception as e:
                g.logger.error(f"❌ Celeryに渡すデータがJSON変換できません: {e}")
                continue
                
            process_webhook_notification.delay(notification)

        return jsonify({"status": "Webhook queued"}), 200

    except Exception as e:
        g.logger.exception("❌ Webhook全体処理中にエラー発生")
        return jsonify({"error": str(e)}), 500

"""最終処理メール日時を取得"""
@app.route('/max_received_date', methods=['GET'])
@login_required_api
def get_max_received_date():
    try:
        file_path_date = 'max_received_date.json'
        max_received_date_data = utils.load_json_data(file_path_date)
        return jsonify(max_received_date_data)
    except FileNotFoundError:
        return jsonify({"error": "ファイルが見つかりません"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "ファイル形式が正しくありません"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

"""指示書操作"""
@app.route("/api/instructions", methods=['GET', 'POST', 'DELETE', 'PATCH'])
@login_required_api
def manage_instructions():
    if request.method == "GET":
        try:
            instructions = Instruction.query.all()
            data = [item.as_dict() for item in instructions]
            return jsonify(data), 200
        except Exception as e:
            current_app.logger.exception("❌ /api/instructions GET エラー")
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == "POST":
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "無効なリクエストデータ"}), 400

            new_instruction = Instruction(
                id=str(uuid.uuid4()),
                request_date=data.get("requestDate"),
                email_received_date=data.get("emailReceivedDate"),
                instructions=data.get("instructions"),
                details=data.get("details"),
                attached_files=data.get("attachedFiles"),
                category=data.get("category"),
                storage_files=data.get("storageFiles"),
                complete_date=data.get("completeDate"),
                is_complete=data.get("isComplete", False)
            )
            db.session.add(new_instruction)
            db.session.commit()
            return jsonify({"status": "success", "data": new_instruction.as_dict()}), 201

        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == "PATCH":
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "更新データがありません"}), 400

            updated_items = data if isinstance(data, list) else data.get("data", [])

            for item in updated_items:
                instruction = Instruction.query.get(item.get("id"))
                if instruction:
                    instruction.is_complete = item.get("isComplete", instruction.is_complete)
                    instruction.updated_at = datetime.utcnow()
            db.session.commit()
            return jsonify({"status": "updated", "data": updated_items}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500

    elif request.method == "DELETE":
        try:
            instruction_id = request.args.get('id')
            if not instruction_id:
                return jsonify({"status": "error", "message": "IDが指定されていません"}), 400

            instruction = Instruction.query.get(instruction_id)
            if not instruction:
                return jsonify({"status": "error", "message": "指定されたIDのデータが存在しません"}), 404

            db.session.delete(instruction)
            db.session.commit()
            return jsonify({"status": "deleted", "data": instruction.as_dict()}), 200

        except Exception as e:
            db.session.rollback()
            return jsonify({"status": "error", "message": str(e)}), 500

"""メール履歴を取得"""
@app.route("/api/history", methods=['GET'])
@login_required_api
def history():
    try:
        # メール履歴を取得
        cleaned_emails = outlook_mailbox.get_history(limit=2000) or []
        received_date = outlook_mailbox.get_last_date() or "不明"

        # ログ出力
        g.logger.info(f"メール履歴を取得: {len(cleaned_emails)} 件, 最終更新: {received_date}")

        # JSONレスポンスを返す
        return jsonify({
            "emails": cleaned_emails,
            "received_date": received_date
        })
    
    except Exception as e:
        g.logger.error(f"メール履歴の取得に失敗: {str(e)}")
        return jsonify({"error": "メール履歴の取得に失敗しました"}), 500

"""OneNoteの情報を取得"""
@app.route("/api/notebooks", methods=['GET'])
@login_required_api
def get_onenote_info():
    auth_header = request.headers.get("Authorization")
    # g.logger.info(f"📌 Authorization ヘッダー: {auth_header}")

    if not auth_header or not auth_header.startswith("Bearer "):
        g.logger.error("❌ Authorization ヘッダーが正しく送信されていません。")
        return jsonify({"error": "Unauthorized"}), 401

    session_id = request.cookies.get('session')
    # g.logger.info(f"📌 セッション ID (フロントエンド): {session_id}")

    access_token_onenote = auth_header.split(" ")[1]
    if not access_token_onenote:
        return jsonify({"authenticated": False, "redirect": "/api/graph"}), 401

    try:
        user_id = os.getenv('user_mail')
        all_notebooks_info, _ = onenote.get_notebooks(user_id, access_token_onenote)
        
        if not all_notebooks_info:
            g.logger.warning("OneNoteのノートブック情報が空です")
            return jsonify({"notebooks": []}), 200

        converted_data = onenote.convert_all_dates_to_japan_time(all_notebooks_info)
        g.logger.info("✅ OneNoteの情報を正常に取得しました。")
        return jsonify({"notebooks": converted_data}), 200

    except Exception as e:
        g.logger.error(f"❌ APIリクエスト中にエラーが発生しました: {str(e)}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

"""OneNoteへ保存"""
@app.route("/api/save_notebooks", methods=['GET', 'POST'])
@login_required_api
def save_notebooks():
    access_token = session.get("access_token")
    user_id = session.get("graph_user_id")
    
    if not access_token or not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    notebooks_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/onenote/notebooks"
    response = requests.get(notebooks_url, headers=headers)
    notebooks = response.json().get("value", [])

    notebook_list = []

    for notebook in notebooks:
        notebook_id = notebook.get("id")
        notebook_name = notebook.get("displayName")

        sections_url = f"https://graph.microsoft.com/v1.0/users/{user_id}/onenote/notebooks/{notebook_id}/sections"
        sections_response = requests.get(sections_url, headers=headers)
        sections = sections_response.json().get("value", [])

        section_list = []
        for section in sections:
            section_list.append({
                "section_id": section.get("id"),
                "section_name": section.get("displayName")
            })

        notebook_list.append({
            "notebook_id": notebook_id,
            "notebook_name": notebook_name,
            "sections": section_list
        })

    output_file = "notebooks_all_info.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(notebook_list, f, ensure_ascii=False, indent=2)

    return jsonify({"success": True, "message": f"{output_file} に保存しました"}), 200

"""カテゴリーレポート"""
@app.route("/api/category_report", methods=['GET'])
@login_required_api
def category_report():
    try:
        # ✅ outlook_emails.json → DBから全件取得
        outlook_emails = [email.as_dict() for email in Email.query.all()]

        notebooks_info = utils.load_json_data("notebooks_info.json")

        # カテゴリーレポートを生成
        section_email_map = utils.extract_emails_by_section(outlook_emails, notebooks_info)
        g.logger.info("カテゴリーレポートを生成しました")

        # 最終メール受信日時を取得
        received_date = outlook_mailbox.get_last_date()

        # JSON データとして返す
        return jsonify({
            "count_cotagory": section_email_map or {},  # 空の場合でも {} を返す
            "received_date": received_date or "不明"  # データがない場合は "不明" を返す
        }), 200
    except Exception as e:
        logging.error("Error generating category report: %s", e)
        return jsonify({"error": str(e)}), 500

"""定期実行設定"""
@app.route("/api/settings_auto_execution", methods=['GET','POST'])
def settings_auto_execution():
    if request.method == 'GET':

        return render_template('settings_auto_execution.html')
    elif request.method == 'POST':
        new_data = request.json
        return jsonify({"message": "auto execution updated successfully."})

"""スケジュール設定"""
@app.route('/api/schedule_api', methods=['GET'])
def schedule_api():
    """スケジュール管理API"""
    try:
        config = db.session.query(ApiConfig).first()
        if request.method == 'GET':
            jobs = Job.query.all()
            job_list = [{
                "id": job.id,
                "name": job.name,
                "task": job.task,
                "trigger": job.trigger,
                "next_run_time": job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else "未定",
                "interval_hours": job.interval_hours,
                "interval_minutes": job.interval_minutes,
                "cron_hour": job.cron_hour,
                "cron_minute": job.cron_minute,
                "created_at": job.created_at.strftime('%Y-%m-%d %H:%M:%S') if job.created_at else None,
                "updated_at": job.updated_at.strftime('%Y-%m-%d %H:%M:%S') if job.updated_at else None,
            } for job in jobs]

            return jsonify({
                "jobs": job_list,
                "webhookEnabled": config.webhook_enabled if config else False
            }), 200

        elif request.method == "POST":
            data = request.get_json()
            enabled = data.get("enabled", False)

            if isinstance(enabled, str):
                enabled = enabled.lower() == "true"

            if config:
                config.webhook_enabled = enabled
                db.session.commit()
                return jsonify({
                    "message": f"Webhookを{'有効' if enabled else '無効'}に更新しました",
                    "enabled": enabled
                }), 200
            else:
                return jsonify({"error": "設定が見つかりません"}), 404

    except Exception as e:
        g.logger.error(f"❌ schedule_api エラー: {e}")
        return jsonify({"error": str(e)}), 500

"""Category情報を取得"""
@app.route("/api/settings_category", methods=['GET', 'POST'])
@login_required_api
def settings_category():
    file_path_category = "category_config.json"

    auth_header = request.headers.get("Authorization")
    # g.logger.info(f"📌 Authorization ヘッダー: {auth_header}")

    if not auth_header or not auth_header.startswith("Bearer "):
        g.logger.error("❌ Authorization ヘッダーが正しく送信されていません。")
        return jsonify({"error": "Unauthorized"}), 401

    session_id = request.cookies.get('session')
    # g.logger.info(f"📌 セッション ID (フロントエンド): {session_id}")

    access_token_onenote = auth_header.split(" ")[1]
    if not access_token_onenote:
        return jsonify({"authenticated": False, "redirect": "/api/graph"}), 401

    # GET: 設定情報を取得
    if request.method == 'GET':
        try:
            # JSON ファイルの読み込み
            category_config = utils.load_json_data(file_path_category)

            try:
                user_id = os.getenv('user_mail')
                all_notebooks_info, _ = onenote.get_notebooks(user_id, access_token_onenote)
                if all_notebooks_info is None:
                    all_notebooks_info = []
            except Exception as e:
                g.logger.error("OneNote API の取得中にエラー発生: %s", str(e))
                return jsonify({"error": "OneNote API の取得に失敗しました"}), 500  # ✅ 500エラーレスポンスを返す

            response_data = {
                "category_config": category_config,
                "notebooks": all_notebooks_info
            }

            return jsonify(response_data), 200

        except json.JSONDecodeError:
            g.logger.error("カテゴリー設定ファイルの形式が正しくありません: %s", file_path_category)
            return jsonify({"error": "カテゴリー設定ファイルの形式が正しくありません"}), 400
        except Exception as e:
            g.logger.error("エラー発生: %s", str(e))
            return jsonify({"error": f"サーバーエラー: {str(e)}"}), 500

    # POST: 設定情報の更新
    elif request.method == 'POST':
        try:
            new_data = request.get_json(force=True) or {}

            if not isinstance(new_data, dict):
                return jsonify({"error": "リクエストデータが無効です"}), 400

            user_id = os.getenv('user_mail')

            try:
                notebook_info, _ = onenote.get_notebooks(user_id, access_token_onenote)
                if notebook_info is None:
                    notebook_info = []
            except Exception as e:
                g.logger.error("OneNote API の取得中にエラー発生: %s", str(e))
                return jsonify({"error": "OneNote API の取得に失敗しました"}), 500

            # ノートブック情報をマッピング
            for email, entries in new_data.items():
                if not isinstance(entries, list):
                    continue  # 不正なデータ形式をスキップ

                for entry in entries:
                    notebook_name = entry.get('notebook', {}).get('notebook_name', "")
                    section_name = entry.get('section', {}).get('section_name', "")

                    # OneNote の notebook ID と section ID を設定
                    for notebook in notebook_info:
                        if notebook.get('displayName') == notebook_name:
                            entry['notebook']['notebook_id'] = notebook.get('id', "")
                            for section in notebook.get('sections', []):
                                if section.get('displayName') == section_name:
                                    entry['section']['section_id'] = section.get('id', "")
                                    break

            # JSON ファイルに保存
            utils.write_json_data(file_path_category, new_data)

            return jsonify({"message": "設定が更新されました"}), 200

        except Exception as e:
            g.logger.error("設定更新中にエラーが発生: %s", str(e))
            return jsonify({"error": f"サーバーエラー: {str(e)}"}), 500

"""API設定"""
@app.route("/api/settings_api", methods=['GET','POST'])
@login_required_api
def settings_api():
    if request.method == 'GET':
        try:
            config = ApiConfig.query.first()
            if not config:
                return jsonify({"error": "設定が登録されていません"}), 404
            return jsonify(config.as_dict()), 200
        except Exception as e:
            g.logger.error(f"Error loading API settings: {str(e)}")
            return jsonify({"error": "設定の取得に失敗しました"}), 500

    elif request.method == 'POST':
        try:
            new_data = request.get_json()
            required_keys = [
                "clientId", "clientSecret", "tenantId",
                "serviceAccountFile", "organization", "secretKey"
            ]
            if not all(k in new_data for k in required_keys):
                return jsonify({"error": "必要な項目が不足しています"}), 400

            config = ApiConfig.query.first()
            if not config:
                config = ApiConfig()
                db.session.add(config)

            config.client_id = new_data["clientId"]
            config.client_secret = new_data["clientSecret"]
            config.tenant_id = new_data["tenantId"]
            config.service_account_file = new_data["serviceAccountFile"]
            config.organization = new_data["organization"]
            config.secret_key = new_data["secretKey"]

            db.session.commit()
            return jsonify({"message": "設定を保存しました"}), 200
        except Exception as e:
            g.logger.error(f"Error saving API settings: {str(e)}")
            return jsonify({"error": "設定の保存に失敗しました"}), 500
    
"""Openai設定"""
@app.route("/api/settings_openai", methods=['GET','POST'])
@login_required_api
def settings_openai():
    if request.method == 'GET':
        try:
            # 設定情報を取得
            model, sys_content, user_content = utils.settings_gpt()
            return jsonify({
                "model": model,
                "sys_content": sys_content,
                "user_content": user_content
            })
        except Exception as e:
            g.logger.error(f"Error fetching OpenAI settings: {e}")
            return jsonify({"error": "Failed to fetch OpenAI settings."}), 500

    elif request.method == 'POST':
        try:
            # フロントエンドから送信されたデータを受け取る
            new_data = request.json
            file_path_gpt = 'gpt_config.json'
            utils.write_json_data(file_path_gpt, new_data)
            
            g.logger.info("gpt_config.json を更新しました")
            return jsonify({"message": "OpenAI settings updated successfully."})
        except Exception as e:
            g.logger.error(f"Error updating gpt_config.json: {e}")
            return jsonify({"error": "Failed to update OpenAI settings."}), 500

if __name__ == '__main__':
    app.run(debug=True)