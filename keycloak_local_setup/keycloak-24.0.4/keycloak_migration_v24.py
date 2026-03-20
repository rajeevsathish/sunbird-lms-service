import csv
import json
import base64

def transform_fed_credentials():
    print("Transforming credentials...")
    try:
        with open('fed_user_credentials.csv') as f:
            reader = csv.DictReader(f)
            with open('insert_fed_creds_24_corrected.sql', 'w') as out:
                for row in reader:
                    # Handle null values
                    algorithm = row.get('algorithm') or 'pbkdf2-sha256'
                    hash_iterations = int(row.get('hash_iterations') or 20000)

                    # 1. Handle Salt: Postgres bytea hex (\x...) to Base64
                    salt_val = row.get('salt', '')
                    salt_b64 = ""
                    if salt_val:
                        if salt_val.startswith('\\x'):
                            try:
                                # Convert hex string (minus '\x') to bytes, then to base64
                                salt_bytes = bytes.fromhex(salt_val[2:])
                                salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
                            except Exception as e:
                                print(f"Error converting salt for user {row.get('user_id')}: {e}")
                                salt_b64 = salt_val # Fallback
                        else:
                            salt_b64 = salt_val

                    # 2. Handle 512-bit hash algorithm mismatch
                    # If the hash value is 64 bytes (decoded), it's likely pbkdf2-sha512, not sha256
                    try:
                        hash_val = row['value']
                        hash_bytes = base64.b64decode(hash_val)
                        if len(hash_bytes) == 64:
                            algorithm = 'pbkdf2-sha512'
                            # print(f"Corrected algorithm to pbkdf2-sha512 for user {row.get('user_id')}")
                    except Exception:
                        pass

                    # Correct JSON structure for 24.0.4
                    secret_data = {
                        "value": row['value'],
                        "salt": salt_b64,
                        "additionalParameters": {}
                    }

                    credential_data = {
                        "algorithm": algorithm,
                        "hashIterations": hash_iterations,
                        "additionalParameters": {}
                    }

                    # Escape quotes for SQL
                    secret_json = json.dumps(secret_data).replace("'", "''")
                    cred_json = json.dumps(credential_data).replace("'", "''")

                    # Replace old realm ID with new one
                    updated_user_id = row['user_id'].replace('f:baada8b1-e62e-44c4-a14d-6702ea90f496:', 'f:03a14f73-54bf-4749-be16-8e91f775bb35:')

                    sql = f"""INSERT INTO fed_user_credential (id, user_id, realm_id, storage_provider_id, type, secret_data, credential_data, priority, created_date) VALUES ('{row['id']}', '{updated_user_id}', '{row['realm_id']}', '03a14f73-54bf-4749-be16-8e91f775bb35', '{row['type']}', '{secret_json}', '{cred_json}', 10, {row['created_date'] or 'NOW()'});"""
                    out.write(sql + '\n')
        print("Credentials transformation complete. Output: insert_fed_creds_24_corrected.sql")
    except FileNotFoundError:
        print("Error: 'fed_user_credentials.csv' not found.")


def transform_fed_users():
    print("Transforming users...")
    try:
        with open('federated_users.csv') as f:
            reader = csv.DictReader(f)
            with open('insert_fed_users_24.sql', 'w') as out:
                for row in reader:
                    update_id = row['id'].replace('f:baada8b1-e62e-44c4-a14d-6702ea90f496:', 'f:03a14f73-54bf-4749-be16-8e91f775bb35:')
                    sql = f"""INSERT INTO federated_user (id, storage_provider_id, realm_id) VALUES ('{update_id}', '03a14f73-54bf-4749-be16-8e91f775bb35', '{row['realm_id']}');"""
                    out.write(sql + '\n')
        print("Users transformation complete. Output: insert_fed_users_24.sql")
    except FileNotFoundError:
        print("Error: 'federated_users.csv' not found.")

def transform_fed_attributes():
    print("Transforming attributes...")
    try:
        with open('fed_user_attributes.csv') as f:
            reader = csv.DictReader(f)
            with open('insert_fed_attrs_24.sql', 'w') as out:
                for row in reader:
                    # Handle long values for 24.0.4 format
                    value = row['value'] or ''
                    long_value = None
                    long_value_hash = None
                    
                    if len(value) > 255:
                        long_value = value
                        value = None
                        # Generate hash for long values (simplified)
                        import hashlib
                        long_value_hash = hashlib.sha256(long_value.encode()).digest().hex()

                    updated_user_id = row['user_id'].replace('f:baada8b1-e62e-44c4-a14d-6702ea90f496:', 'f:03a14f73-54bf-4749-be16-8e91f775bb35:')

                    if long_value:
                        sql = f"""INSERT INTO fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value, long_value, long_value_hash) VALUES ('{row['id']}', '{row['name']}', '{updated_user_id}', '{row['realm_id']}', '03a14f73-54bf-4749-be16-8e91f775bb35', NULL, '{long_value}', decode('{long_value_hash}', 'hex'));"""
                    else:
                        sql = f"""INSERT INTO fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value) VALUES ('{row['id']}', '{row['name']}', '{updated_user_id}', '{row['realm_id']}', '03a14f73-54bf-4749-be16-8e91f775bb35', '{value}');"""
                    out.write(sql + '\n')
        print("Attributes transformation complete. Output: insert_fed_attrs_24.sql")
    except FileNotFoundError:
        print("Error: 'fed_user_attributes.csv' not found.")

# Run transformations
if __name__ == "__main__":
    transform_fed_users()
    transform_fed_credentials()
    transform_fed_attributes()
