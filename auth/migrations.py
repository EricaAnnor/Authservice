from database import get_connection, return_connection



sql = '''INSERT INTO company (name) VALUES ('DevTech');  '''


def migrations():
    connection = None
    try:
        connection = get_connection()
        with connection.cursor() as cursor:
            cursor.execute(sql)
        connection.commit()  
    except Exception as e:
        if connection:
            connection.rollback()
        raise e
    finally:
        if connection:
            return_connection(connection)

if __name__ == "__main__":
    migrations()