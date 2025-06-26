import sqlite3

conn = sqlite3.connect('instance/doc.db')
cursor = conn.cursor()

cursor.execute("SELECT * FROM documents WHERE LOWER(filename) LIKE '%Порядок%'")
results = cursor.fetchall()

print(results)
conn.close()