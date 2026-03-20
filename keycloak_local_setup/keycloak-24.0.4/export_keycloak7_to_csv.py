import psycopg2
import csv
import sys
from psycopg2.extras import RealDictCursor

def export_keycloak7_data(db_host, db_port, db_name, db_user, db_password, realm_id=None):
    """
    Export federated user data from Keycloak 7 database to CSV files
    
    Args:
        db_host: Database host (e.g., 'localhost')
        db_port: Database port (default 5432 for PostgreSQL)
        db_name: Database name (usually 'keycloak')
        db_user: Database user
        db_password: Database password
        realm_id: Optional realm ID filter (if not specified, exports all)
    """
    
    try:
        # Connect to database
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password
        )
        print(f"✓ Connected to Keycloak 7 database: {db_name}")
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Export FEDERATED_USER
        print("\nExporting federated_users...")
        query_users = "SELECT id, storage_provider_id, realm_id FROM federated_user"
        if realm_id:
            query_users += f" WHERE realm_id = '{realm_id}'"
        
        cursor.execute(query_users)
        users = cursor.fetchall()
        
        if users:
            with open('federated_users.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['id', 'storage_provider_id', 'realm_id'])
                writer.writeheader()
                writer.writerows(users)
            print(f"✓ Exported {len(users)} federated users to federated_users.csv")
        else:
            print("⚠ No federated users found")
        
        # Export FED_USER_CREDENTIAL
        print("\nExporting fed_user_credentials...")
        query_creds = """
            SELECT 
                id, 
                user_id, 
                realm_id, 
                storage_provider_id, 
                type, 
                value, 
                salt, 
                hash_iterations, 
                algorithm, 
                created_date,
                device,
                counter,
                digits,
                period
            FROM fed_user_credential
        """
        if realm_id:
            query_creds += f" WHERE realm_id = '{realm_id}'"
        
        cursor.execute(query_creds)
        creds = cursor.fetchall()
        
        if creds:
            with open('fed_user_credentials.csv', 'w', newline='') as f:
                fieldnames = ['id', 'user_id', 'realm_id', 'storage_provider_id', 'type', 
                             'value', 'salt_b64', 'algorithm', 'hash_iterations', 
                             'created_date', 'device', 'counter', 'digits', 'period']
                writer = csv.DictWriter(f, fieldnames=fieldnames, restval='')
                writer.writeheader()
                
                for row in creds:
                    row_dict = dict(row)
                    # Handle null values
                    for key in row_dict.keys():
                        if row_dict.get(key) is None:
                            row_dict[key] = ''
                    
                    # Map salt to salt_b64 for consistency with transform script
                    writer.writerow({
                        'id': row_dict.get('id', ''),
                        'user_id': row_dict.get('user_id', ''),
                        'realm_id': row_dict.get('realm_id', ''),
                        'storage_provider_id': row_dict.get('storage_provider_id', ''),
                        'type': row_dict.get('type', ''),
                        'value': row_dict.get('value', ''),
                        'salt_b64': row_dict.get('salt', ''),  # Map salt to salt_b64
                        'algorithm': row_dict.get('algorithm', 'pbkdf2-sha1'),
                        'hash_iterations': row_dict.get('hash_iterations', 20000),
                        'created_date': row_dict.get('created_date', ''),
                        'device': row_dict.get('device', ''),
                        'counter': row_dict.get('counter', ''),
                        'digits': row_dict.get('digits', ''),
                        'period': row_dict.get('period', '')
                    })
            print(f"✓ Exported {len(creds)} federated user credentials to fed_user_credentials.csv")
        else:
            print("⚠ No federated user credentials found")
        
        # Export FED_USER_ATTRIBUTE
        print("\nExporting fed_user_attributes...")
        query_attrs = """
            SELECT 
                id, 
                name, 
                user_id, 
                realm_id, 
                storage_provider_id, 
                value
            FROM fed_user_attribute
        """
        if realm_id:
            query_attrs += f" WHERE realm_id = '{realm_id}'"
        
        cursor.execute(query_attrs)
        attrs = cursor.fetchall()
        
        if attrs:
            with open('fed_user_attributes.csv', 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['id', 'name', 'user_id', 'realm_id', 'storage_provider_id', 'value'])
                writer.writeheader()
                writer.writerows(attrs)
            print(f"✓ Exported {len(attrs)} federated user attributes to fed_user_attributes.csv")
        else:
            print("⚠ No federated user attributes found")
        
        cursor.close()
        conn.close()
        print("\n✓ Database export complete!")
        
    except psycopg2.Error as e:
        print(f"✗ Database error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Hardcoded configuration for localhost
    DB_HOST = "localhost"
    DB_PORT = 5432
    DB_NAME = "keycloak7"
    DB_USER = "postgres"
    DB_PASSWORD = "password123"
    REALM_ID = None  # Export all realms
    
    print("=" * 60)
    print("Keycloak 7 to CSV Exporter")
    print("=" * 60)
    print(f"Database: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"Realm Filter: {REALM_ID or 'All realms'}")
    print("=" * 60)
    
    export_keycloak7_data(DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, REALM_ID)
