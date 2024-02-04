import sqlite3

con = sqlite3.connect('/home/kyle/routers.db')
cursor = con.cursor()


cursor.execute('''
    CREATE TABLE IF NOT EXISTS routers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip INTEGER UNIQUE,
        username TEXT,
        password TEXT
    )
''')

cursor.execute('''
            CREATE TABLE IF NOT EXISTS BackupSchedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_time TEXT
            )
        ''')


cursor.execute('''
    CREATE TABLE IF NOT EXISTS netflow_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Date TEXT,
        Time TEXT,
        Router_ip TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        source_port INTEGER,
        dest_port INTEGER,
        protocol INTEGER,
        num_packets INTEGER
    )
''')



cursor.execute('''
     CREATE TABLE IF NOT EXISTS syslog_data (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         Date TEXT,
         Time TEXT,
         Router_IP TEXT,
         Message TEXT
    )
''')



cursor.execute('''
      CREATE TABLE IF NOT EXISTS link_trap_data (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          Date TEXT NOT NULL,
          Time TEXT NOT NULL,
          Router_IP TEXT NOT NULL,
          Interface_Name TEXT NOT NULL,
          State TEXT NOT NULL
  )
''')



con.commit()
con.close()

