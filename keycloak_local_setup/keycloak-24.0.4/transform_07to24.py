#!/usr/bin/env python3
"""
Keycloak 7 to Keycloak 24 Credential Migration Script
Transforms fed_user_credential data from Keycloak 7.0.1 to 24.0.4 format
"""

import csv
import json
import base64
import binascii
import hashlib
from datetime import datetime


def transform_credentials():
    input_file = 'fed_user_credentials.csv'
    output_file = 'insert_credentials_kc24.sql'

    with open(input_file, 'r', encoding='utf-8') as csv_file:
        reader = csv.DictReader(csv_file)

        with open(output_file, 'w', encoding='utf-8') as sql_file:
            sql_file.write("-- Keycloak 24 fed_user_credential migration from Keycloak 7\n")
            sql_file.write(f"-- Generated: {datetime.now().isoformat()}\n\n")

            row_count = 0
            for row in reader:
                row_count += 1

                cred_id             = row['id'].strip()
                salt_hex            = row['salt'].strip() if row['salt'] else None
                cred_type           = row['type'].strip()
                value               = row['value'].strip() if row['value'] else ''
                created_date        = row['created_date'].strip() if row['created_date'] else None
                user_id             = row['user_id'].strip()
                realm_id            = row['realm_id'].strip()
                storage_provider_id = row['storage_provider_id'].strip() or None

                # ✅ Fix 2 & 3: Type-aware defaults
                algorithm = row.get('algorithm', '').strip()
                hash_iterations = row.get('hash_iterations', '').strip()

                if cred_type == 'password':
                    algorithm = algorithm or 'pbkdf2-sha256'
                    hash_iterations = hash_iterations or '20000'
                elif cred_type in ['totp', 'hotp', 'sms-auth.code']:
                    algorithm = algorithm or 'HmacSHA1'
                    hash_iterations = hash_iterations or '0'

                # ✅ Fix 1: Convert salt hex → bytes → Base64 for secret_data JSON
                salt_bytea = None
                salt_b64 = ""
                if salt_hex and salt_hex.startswith('\\x'):
                    hex_str = salt_hex.replace('\\x', '')
                    salt_bytes = binascii.unhexlify(hex_str)
                    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
                    salt_bytea = salt_hex  # keep original \x format for bytea column

                # ✅ Fix 6: Type-aware credential_data and secret_data
                if cred_type == 'password':
                    secret_data = {
                        "value": value,
                        "salt": salt_b64
                    }
                    credential_data = {
                        "hashIterations": int(hash_iterations),
                        "algorithm": algorithm
                    }
                elif cred_type in ['totp', 'hotp', 'sms-auth.code']:
                    secret_data = {
                        "value": value
                    }
                    credential_data = {
                        "subType": cred_type,
                        "digits": int(row.get('digits', '6').strip() or '6'),
                        "counter": int(row.get('counter', '0').strip() or '0'),
                        "period": int(row.get('period', '30').strip() or '30'),
                        "algorithm": algorithm
                    }
                else:
                    secret_data = {"value": value}
                    credential_data = {}

                secret_data_json    = json.dumps(secret_data, ensure_ascii=False).replace("'", "''")
                credential_data_json = json.dumps(credential_data, ensure_ascii=False).replace("'", "''")

                # ✅ Fix 4: user_label is NULL
                user_label = None

                # ✅ Fix 5: NULL-safe SQL values
                salt_sql     = f"'{salt_bytea}'"          if salt_bytea           else 'NULL'
                date_sql     = created_date               if created_date         else 'NULL'
                sp_sql       = f"'{storage_provider_id}'" if storage_provider_id  else 'NULL'
                label_sql    = f"'{user_label}'"          if user_label           else 'NULL'

                sql = f"""INSERT INTO fed_user_credential (
    id, salt, type, created_date, user_id, realm_id,
    storage_provider_id, user_label, secret_data, credential_data, priority
) VALUES (
    '{cred_id}',
    {salt_sql},
    '{cred_type}',
    {date_sql},
    '{user_id}',
    '{realm_id}',
    {sp_sql},
    {label_sql},
    '{secret_data_json}',
    '{credential_data_json}',
    10
);\n\n"""
                sql_file.write(sql)

            sql_file.write(f"-- Total rows migrated: {row_count}\n")
            print(f"✅ Migration complete: {row_count} rows written to {output_file}")

def transform_federated_users():
    """
    Transform Keycloak 7 federated_user CSV to Keycloak 24 SQL inserts
    
    Keycloak 7 & 24 Schema (same for both):
    - id (character varying(255))
    - storage_provider_id (character varying(255))
    - realm_id (character varying(36))
    """
    
    input_file = 'federated_users.csv'
    output_file = 'insert_federated_users_kc24.sql'
    
    try:
        with open(input_file, 'r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            
            with open(output_file, 'w', encoding='utf-8') as sql_file:
                # Write header comment
                sql_file.write("-- Keycloak 24 federated_user migration from Keycloak 7\n")
                sql_file.write(f"-- Generated: {datetime.now().isoformat()}\n\n")
                
                row_count = 0
                for row in reader:
                    row_count += 1
                    
                    # Extract fields
                    user_id = row['id'].strip()
                    storage_provider_id = row['storage_provider_id'].strip()
                    realm_id = row['realm_id'].strip()
                    
                    # Build SQL INSERT statement
                    sql = f"""INSERT INTO federated_user (
    id, 
    storage_provider_id, 
    realm_id
) VALUES (
    '{user_id}',
    '{storage_provider_id}',
    '{realm_id}'
);

"""
                    sql_file.write(sql)
                
                # Write summary
                sql_file.write(f"\n-- Total records migrated: {row_count}\n")
                print(f"✓ Federated users migration complete: {row_count} users transformed")
                print(f"✓ Output written to: {output_file}")
                
    except FileNotFoundError:
        print(f"⚠ Warning: {input_file} not found, skipping federated users migration")


def transform_fed_user_attributes():
    """
    Transform Keycloak 7 fed_user_attribute CSV to Keycloak 24 SQL inserts
    
    Keycloak 7 & 24 Schema:
    - id (character varying(36))
    - name (character varying(255))
    - user_id (character varying(255))
    - realm_id (character varying(36))
    - storage_provider_id (character varying(36))
    - value (character varying(2024))
    - long_value_hash (bytea)
    - long_value_hash_lower_case (bytea)
    - long_value (text)
    
    Note: If value length > 2024, it goes to long_value with hash
    """
    
    input_file = 'fed_user_attributes.csv'
    output_file = 'insert_fed_user_attributes_kc24.sql'
    
    try:
        with open(input_file, 'r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            
            with open(output_file, 'w', encoding='utf-8') as sql_file:
                # Write header comment
                sql_file.write("-- Keycloak 24 fed_user_attribute migration from Keycloak 7\n")
                sql_file.write(f"-- Generated: {datetime.now().isoformat()}\n\n")
                
                row_count = 0
                long_value_count = 0
                
                for row in reader:
                    row_count += 1
                    
                    # Extract fields
                    attr_id = row['id'].strip()
                    name = row['name'].strip().replace("'", "''")  # Escape quotes
                    user_id = row['user_id'].strip()
                    realm_id = row['realm_id'].strip()
                    storage_provider_id = row['storage_provider_id'].strip()
                    value = row.get('value', '').strip() if row.get('value') else ''
                    
                    # Escape single quotes in value
                    value_escaped = value.replace("'", "''")
                    
                    # Check if value needs to go into long_value
                    if len(value) > 2024:
                        long_value_count += 1
                        # Generate SHA-256 hash for long values
                        long_value_hash = hashlib.sha256(value.encode('utf-8')).digest().hex()
                        long_value_hash_lower = hashlib.sha256(value.lower().encode('utf-8')).digest().hex()
                        
                        sql = f"""INSERT INTO fed_user_attribute (
    id, 
    name, 
    user_id, 
    realm_id, 
    storage_provider_id, 
    value,
    long_value,
    long_value_hash,
    long_value_hash_lower_case
) VALUES (
    '{attr_id}',
    '{name}',
    '{user_id}',
    '{realm_id}',
    '{storage_provider_id}',
    NULL,
    '{value_escaped}',
    decode('{long_value_hash}', 'hex'),
    decode('{long_value_hash_lower}', 'hex')
);

"""
                    else:
                        # Regular value (fits in value column)
                        sql = f"""INSERT INTO fed_user_attribute (
    id, 
    name, 
    user_id, 
    realm_id, 
    storage_provider_id, 
    value
) VALUES (
    '{attr_id}',
    '{name}',
    '{user_id}',
    '{realm_id}',
    '{storage_provider_id}',
    '{value_escaped}'
);

"""
                    sql_file.write(sql)
                
                # Write summary
                sql_file.write(f"\n-- Total records migrated: {row_count}\n")
                sql_file.write(f"-- Long values: {long_value_count}\n")
                print(f"✓ Fed user attributes migration complete: {row_count} attributes transformed")
                print(f"  - Regular values: {row_count - long_value_count}")
                print(f"  - Long values: {long_value_count}")
                print(f"✓ Output written to: {output_file}")
                
    except FileNotFoundError:
        print(f"⚠ Warning: {input_file} not found, skipping fed user attributes migration")


if __name__ == '__main__':
    print("Starting Keycloak 7 to 24 migration...")
    print("=" * 60)
    
    # Migrate credentials
    print("\n1. Migrating credentials...")
    transform_credentials()
    
    # Migrate federated users
    print("\n2. Migrating federated users...")
    transform_federated_users()
    
    # Migrate federated user attributes
    print("\n3. Migrating federated user attributes...")
    transform_fed_user_attributes()
    
    print("\n" + "=" * 60)
    print("Migration script completed successfully!")
