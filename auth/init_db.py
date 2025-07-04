from database import get_connection, return_connection

sql = """

    CREATE TYPE role_type AS ENUM ('admin', 'user');

    CREATE TABLE IF NOT EXISTS company (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL UNIQUE,
        username VARCHAR(50) NOT NULL UNIQUE,
        firstname VARCHAR(50) NOT NULL,
        lastname VARCHAR(50) NOT NULL,
        role role_type NOT NULL DEFAULT 'user',
        password TEXT NOT NULL,
        company_id UUID REFERENCES company(id)
    );
"""

def create_table():
    connection = None
    try:
        connection = get_connection()
        with connection.cursor() as cursor:
            cursor.execute(sql)
        connection.commit()  
        print("Tables created successfully")
    except Exception as e:
        if connection:
            connection.rollback()
        raise e
    finally:
        if connection:
            return_connection(connection)

if __name__ == "__main__":
    create_table()
