import secrets

# 32文字のランダムな秘密鍵を生成
secret_key = secrets.token_hex(32)
print(secret_key)
