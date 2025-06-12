import json
import time

from celery import shared_task
from services.auth_service import get_valid_access_token
from services.email_service import save_email_from_graph_data

from db.db import db
from models import Email

from onenote import main as onenote_main
import outlook_mailbox
import utils

import logging
from logging_config import setup_logging

"""ロギングのセットアップ"""
logger = logging.getLogger("celery_access")

"""Webhook の各通知データを非同期で処理する Celery タスク"""
@shared_task(name="webhook_tasks.process_webhook_notification", queue="celery")
def process_webhook_notification(notification_data):
    logger.info("✅ タスク実行開始")
    from app import create_app
    app = create_app()
    with app.app_context():
        try:
            message_id = utils.extract_message_id(notification_data)
            graph_user_id = utils.extract_user_id(notification_data)
            change_type = notification_data.get("changeType") or "created"

            if not message_id or not graph_user_id:
                logger.error(f"❌ 必要な情報が不足 (message_id: {message_id}, graph_user_id: {graph_user_id})")
                return

            logger.info(f"📨 メール通知: message_id={message_id}, change_type={change_type}, graph_user_id={graph_user_id}")

            # Graph API アクセストークン（アプリレベル）
            app_token = utils.create_access_token()
            if not app_token:
                logger.error("❌ アプリ用アクセストークンの取得に失敗")
                return

            # メール詳細取得---change_typeの値で、GoogleDriveへの保存の分岐---
            full_email, reason = outlook_mailbox.mail_processing(app_token, message_id, change_type)
            if not full_email:
                logger.error(f"📛 メール詳細の取得に失敗: {message_id} / 理由: {reason}")
                return

            # ユーザ用アクセストークンの取得（リフレッシュ対応）
            try:
                user_access_token = get_valid_access_token(graph_user_id)
            except Exception as e:
                logger.error(f"❌ user_access_token取得エラー: {e}")
                return

            """OneNote出力"""
            new_categories = full_email.get("categories", [])
            # 有効なカテゴリ（未設定以外）
            valid_categories = [c for c in new_categories if c != "未設定"]

            category_id_list = full_email.get("category_id", [])
            # 有効な category_id （空文字列以外）
            valid_category_id = [cid for cid in category_id_list if cid]


            if change_type == "created":
                logger.info("🆕 新規メール処理")

                # メール情報保存
                save_email_from_graph_data(full_email, app_token, change_type="created")
                logger.info(f"✅ メール詳細保存完了: {full_email.get('change_type', '(no change_type)')} / {full_email.get('subject', '(no subject)')}")

                # ----- OneNote 出力条件 -----
                if valid_category_id:
                    try:
                        onenote_main([full_email], user_access_token)
                    except Exception as e:
                        logger.error(f"❌ OneNote出力エラー: {e}")
                else:
                    logger.info("✅ OneNote 出力スキップ (category_id 未設定)")

                # ----- カテゴリ更新条件 -----
                if valid_categories:
                    try:
                        change_key = full_email.get("change_key")
                        update_results = outlook_mailbox.update_email_categories(user_access_token, full_email, graph_user_id, change_key)
                        logger.info(f"✅ カテゴリ更新結果: {update_results}")
                    except Exception as e:
                        logger.error(f"❌ カテゴリ更新エラー: {e}")
                else:
                    logger.info("✅ カテゴリ更新スキップ (有効なカテゴリなし)")

            elif change_type == "updated":
                logger.info("🔄 メール分類--更新処理--")
                time.sleep(5)

                # DBから保存済みのカテゴリ情報を取得
                saved_email = db.session.query(Email).filter_by(graph_id=message_id).first()
                saved_last_modified = saved_email.last_modified if saved_email else None
                saved_categories = json.loads(saved_email.categories) if saved_email else []


                # 最新のカテゴリと比較
                new_last_modified = full_email.get("last_modified")
                new_categories = full_email.get("categories", [])

                # 「未設定」の場合は保存のみ
                if new_categories == ["未設定"]:
                    logger.info("📝 カテゴリが未設定のため、DB保存のみ実行")
                    save_email_from_graph_data(full_email, app_token, change_type="updated")
                    return

                if (
                    set(new_categories) != set(saved_categories)
                    or (saved_last_modified and new_last_modified and saved_last_modified != new_last_modified)
                ):
                    logger.info(f"📌 カテゴリ変更検出: {saved_categories} → {new_categories}")

                    # メール情報保存
                    save_email_from_graph_data(full_email, app_token, change_type="updated")
                    time.sleep(5)
                    logger.info(f"✅ メール詳細保存完了: {full_email.get('change_type', '(no change_type)')} / {full_email.get('subject', '(no subject)')}")

                    try:
                        onenote_main([full_email], user_access_token)
                    except Exception as e:
                        logger.error(f"❌ OneNote出力エラー: {e}")
                else:
                    logger.info("✅ カテゴリ変更なし。処理スキップ")

        except Exception as e:
            logger.exception("❌ Webhook通知処理中にエラー")