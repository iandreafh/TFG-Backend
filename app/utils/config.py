import os

# Configuraciones de la base de datos
DB_HOST = "localhost"
DB_NAME = "PandaPlanningDB"
DB_USER = "postgres"
DB_PASSWORD = "7UwP8mo2."  # Considera mover esto a una variable de entorno

# Configuraciones del correo electrónico
MAIL_USERNAME = 'pandaplanningweb@gmail.com'
MAIL_PASSWORD = 'gdbjopjbxufxtitq'  # Considera mover esto a una variable de entorno
MAIL_DEFAULT_SENDER = 'pandaplanningweb@gmail.com'
MAIL_DEFAULT_TESTER = 'iandreafh@gmail.com'  # Correo electrónico para pruebas de envío

# Configuración de seguridad JWT
JWT_SECRET_KEY = 'super1998AFH14w33'

# Configuración del Scheduler para tareas automáticas
SCHEDULER_HOUR = 11  # Ejecución diaria para notificar mensajes no leídos

# Límite de elementos en las listas en caso de no indicarse un límite
MAX_LIST_LIMIT = 100

# Archivos de log
DETAILED_LOGS = True
ERROR_LOG_FILE = 'logs/error.log'  # Archivo para logs de errores
APP_LOG_FILE = 'logs/app.log'  # Archivo para logs de info y debug de la app
HTTP_LOG_FILE = 'logs/http.log'  # Archivo para logs de peticiones HTTP