import sys
import traceback
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

db_host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")

def main(name1, email1, passw):
    conn = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
    cursor = conn.cursor()

    person = (name1, email1, passw)

    conn.autocommit = True

<<<<<<< HEAD
    sql = "select * from clients"

    # TRUNCATE TABLE clients RESTART IDENTITY; --> delete all info from table and start from 0

    cursor.execute("select count(*) from clients where email = %s", (email1,))
=======
    sql = "select * from reg_users"

    # TRUNCATE TABLE clients RESTART IDENTITY; --> delete all info from table and start from 0

    cursor.execute("select count(*) from reg_users where email = %s", (email1,))
>>>>>>> 67b6e45 (add js sign in btn and logic without adding cookie)
    # cursor.execute(sql)
    # print(cursor.fetchall()[0][0])
    if cursor.fetchall()[0][0] != 0:
        print("this person exist")
    else:
        #print("not exist")
        try:
<<<<<<< HEAD
            cursor.execute("insert into clients (name, email, hash_pass) values (%s, %s, md5(%s))", (person))
=======
            cursor.execute("insert into reg_users (name, email, pass) values (%s, %s, md5(%s))", (person))
>>>>>>> 67b6e45 (add js sign in btn and logic without adding cookie)
            print("Person added")
        except Exception:
            traceback.print_exc()
            raise

    # print(sql)

    cursor.close()
    conn.close()

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])
