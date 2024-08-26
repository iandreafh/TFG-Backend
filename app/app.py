import string
import datetime
import random
import logging
import bcrypt
import atexit
import os

from flask import Flask, request, send_from_directory
from flask_restx import Api, Resource, fields
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, verify_jwt_in_request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, or_
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.inspection import inspect
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from utils.config import *
from utils.generate_email import generate_html_email
from apscheduler.schedulers.background import BackgroundScheduler


# Configuración del logger
# Desglosado en archivos por tipo de logs
# Archivo app.log para INFO y DEBUG en caso de activarlo
# Archivo error.log para los errores y excepciones
# Archivo http.log para las peticiones HTTP
class ExcludeHTTPFilter(logging.Filter):
    def filter(self, record):
        return not any(method in record.getMessage() for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
class ExcludeErrorFilter(logging.Filter):
    def filter(self, record):
        return record.levelno < logging.ERROR

app_log_handler = logging.FileHandler('logs/app.log', encoding='utf-8')
app_log_handler.addFilter(ExcludeHTTPFilter())
app_log_handler.addFilter(ExcludeErrorFilter())

if DETAILED_LOGS:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s',
                        handlers=[app_log_handler, logging.StreamHandler()])
else:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s',
                        handlers=[app_log_handler, logging.StreamHandler()])

# Configuración del error handler
error_handler = logging.FileHandler(ERROR_LOG_FILE, encoding='utf-8')
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logging.getLogger().addHandler(error_handler)

# Configuración del http handler
http_handler = logging.FileHandler(HTTP_LOG_FILE, encoding='utf-8')
http_handler.setLevel(logging.INFO)
http_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
http_logger = logging.getLogger('http_logger')
http_logger.addHandler(http_handler)

app = Flask(__name__)
CORS(app, origins=["https://pandaplanning.es"])
@app.before_request
def log_request_info():
    http_logger.info(f'{request.remote_addr} - - [{datetime.datetime.now().strftime("%d/%b/%Y %H:%M:%S")}] "{request.method} {request.path} {request.scheme}/{request.environ.get("SERVER_PROTOCOL")}"')

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SWAGGER_UI_DOC_EXPANSION'] = 'list'
db = SQLAlchemy(app)

# Configuración del directorio para subir archivos
PROFILE_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads/profile_uploads')
if not os.path.exists(PROFILE_UPLOAD_FOLDER):
    os.makedirs(PROFILE_UPLOAD_FOLDER)
app.config['PROFILE_UPLOAD_FOLDER'] = PROFILE_UPLOAD_FOLDER

FILES_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads/files_uploads')
if not os.path.exists(FILES_UPLOAD_FOLDER):
    os.makedirs(FILES_UPLOAD_FOLDER)
app.config['FILES_UPLOAD_FOLDER'] = FILES_UPLOAD_FOLDER

@app.route('/uploads/profile_uploads/<filename>')
def uploaded_profile_file(filename):
    return send_from_directory(app.config['PROFILE_UPLOAD_FOLDER'], filename)

@app.route('/uploads/files_uploads/<filename>')
def uploaded_files_file(filename):
    return send_from_directory(app.config['FILES_UPLOAD_FOLDER'], filename)

# Configuración de la clave secreta para JWT
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY  # Cambia esto por una clave secreta real
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)  # Tiempo de expiración del token
jwt = JWTManager(app)

# Configuración del correo electrónico
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
app.config['MAIL_DEFAULT_TESTER'] = MAIL_DEFAULT_TESTER
mail = Mail(app)

# Reflexión de la base de datos dentro del contexto de la aplicación
with app.app_context():
    Base = automap_base()
    Base.prepare(autoload_with=db.engine)

    # Mapeo de tablas
    Usuario = Base.classes.usuarios
    Proyecto = Base.classes.proyectos
    MiembroProyecto = Base.classes.miembrosproyecto
    Tarea = Base.classes.tareas
    Comentario = Base.classes.comentarios
    Archivo = Base.classes.archivos
    Reunion = Base.classes.reuniones
    ParticipanteReunion = Base.classes.participantesreunion
    Mensaje = Base.classes.mensajes

    # Crear una sesión de SQLAlchemy
    session_factory = sessionmaker(bind=db.engine)
    Session = scoped_session(session_factory)

# Lista para almacenar tokens revocados
revoked_tokens = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in revoked_tokens

# Función para hashear las contraseñas antes de almacenarlas en la base de datos
def hash_password(password):
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode('utf-8')

# Función para verificar si las contraseñas coinciden
def verify_password(provided_password, stored_hash):
    provided_password_bytes = provided_password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    return bcrypt.checkpw(provided_password_bytes, stored_hash_bytes)

# Función para verificar que no se obtenga un listado con más elementos de los permitidos en una misma petición
def validate_limit(limit):
    if isinstance(limit, str) and limit.isdigit():
        limit = int(limit)
    if limit > MAX_LIST_LIMIT:
        limit = MAX_LIST_LIMIT
    return limit

# Función para convertir un objeto SQLAlchemy en un diccionario
def to_dict(obj):
    """Convierte un objeto SQLAlchemy en un diccionario."""
    if obj is None:
        return None

    obj_dict = {}
    for column in inspect(obj).mapper.column_attrs:
        if (column.key != 'password') and (column.key != 'hash'):
            value = getattr(obj, column.key)
            if isinstance(value, datetime.datetime) or isinstance(value, datetime.date):
                value = value.isoformat()
            if column.key == 'foto' and value:
                value = f"{request.url_root}api/uploads/profile_uploads/{value}"
            if column.key == 'ruta' and value:
                value = f"{request.url_root}api/uploads/files_uploads/{value}"
            obj_dict[column.key.capitalize()] = value

    return obj_dict


def get_logged_user(session):
    """ Devuelve los datos del usuario logueado en la session """
    identidad_actual = get_jwt()['sub']
    usuario_actual = session.query(Usuario).filter_by(id=identidad_actual).first()
    return usuario_actual


##############################################################################################################
# GESTIÓN DE ACCESO
##############################################################################################################

# Configuración de la seguridad de la API
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}

api = Api(app, version='1.0', title='Panda Planning API',
          description='API RESTful del proyecto Panda Planning',
          authorizations=authorizations,
          security='Bearer')

# Namespace para autenticación
ns = api.namespace('auth', description='Operaciones de Autenticación')

credenciales_modelo = api.model('Credenciales', {
    'Email': fields.String(required=True, description='Email del usuario'),
    'Password': fields.String(required=True, description='Contraseña')
})

@ns.route('/login')
class Login(Resource):
    @ns.expect(credenciales_modelo)
    @ns.doc('login',
            responses={
                200: 'Login exitoso',
                401: 'Credenciales inválidas',
                403: 'Usuario inactivo'
            })
    def post(self):
        datos = request.json
        email = datos.get('Email')
        password = datos.get('Password')

        # Obtener el usuario por email
        session = Session()
        try:
            usuario = session.query(Usuario).filter_by(email=email).first()

            if usuario and verify_password(password, usuario.password):
                # Verificar si el usuario está inactivo, para notificar y que pueda reactivar su cuenta
                if not usuario.check_activo:
                    logging.warning(f'Intento de inicio de sesión para usuario inactivo {email}')
                    return {'message': 'Usuario inactivo'}, 403

                # Crear el token de acceso si el usuario está activo y la contraseña es correcta
                access_token = create_access_token(identity=usuario.id)
                logging.info(f'Usuario {email} ha iniciado sesión exitosamente.')
                return {
                    'access_token': access_token,
                    'usuario': to_dict(usuario)  # Convertir el objeto usuario a diccionario
                }, 200
            else:
                logging.warning(f'Intento fallido de inicio de sesión para el usuario {email}')
                return {'message': 'Credenciales incorrectas'}, 401

        except Exception as e:
            logging.error(f'Error en el login del usuario {email}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns.route('/logout')
class Logout(Resource):
    @jwt_required()
    @ns.doc('logout',
            responses={
                200: 'Sesión cerrada correctamente',
                500: 'Error interno del servidor'
            })
    def post(self):
        try:
            jti = get_jwt()['jti']
            revoked_tokens.add(jti)
            logging.debug(f'Token {jti} ha sido revocado.')
            return {'message': 'Sesión finalizada correctamente'}, 200
        except Exception as e:
            logging.error(f'Error al cerrar sesión: {e}')
            return {'success': False, 'message': str(e)}, 500

# Modelo para solicitar el reseteo de la contraseña
reset_password_modelo = api.model('ResetPassword', {
    'Email': fields.String(required=True, description='Email del usuario')
})

@ns.route('/reset_password')
class ResetPassword(Resource):
    @ns.expect(reset_password_modelo)
    @ns.doc('reset_password',
            responses={
                200: 'Contraseña restaurada y enviada exitosamente',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        datos = request.json
        email = datos.get('Email')

        # Obtener el usuario por email
        session = Session()
        try:
            usuario = session.query(Usuario).filter_by(email=email).first()
            if not usuario:
                logging.warning(f'Intento de reseteo de contraseña para email no registrado {email}')
                return {'message': 'Usuario no encontrado'}, 404

            # Generar una nueva contraseña aleatoria
            nueva_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            hashed_password = hash_password(nueva_password)

            # Actualizar la contraseña del usuario en la base de datos
            usuario.password = hashed_password
            usuario.updated_at=datetime.datetime.now()
            session.commit()

            # Enviar la nueva contraseña por correo electrónico
            email_title = "Nueva contraseña restaurada"
            email_text = (f"<p>Tu nueva contraseña es: <strong>{nueva_password}</strong></p>"
                          "<p>Por favor, es importante que por motivos de seguridad "
                          "cambies esta contraseña en tu perfil después de iniciar sesión.</p>"
                          "<p>Gracias.</p>")
            html_body = generate_html_email(usuario.nombre, email_title, email_text)
            msg = Message(subject=email_title,
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[email]) # email
            msg.html = html_body
            mail.send(msg)

            logging.info(f'Contraseña restaurada y enviada al usuario {email}')
            return {'message': 'Nueva contraseña enviada al correo electrónico'}, 200
        except Exception as e:
            logging.error(f'Error en el reseteo de contraseña para el usuario {email}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns.route('/send_mail_test')
class SendEmailTest(Resource):
    @ns.doc('send_email_test',
            responses={
                200: 'Contraseña reseteada exitosamente',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        session = Session()
        try:
            email_title = "Nuevo comunicado de Panda Planning"
            email_text = (f"<p>Panda Planning ha enviado un nuevo comunicado:"
                          f"<div class='info-card'>"
                          f"<p>&emsp; <strong>Comunicado sobre modificaciones importantes</strong></p>"
                          f"<p>&emsp; Hola, queríamos comunicar desde el equipo de Panda Planning que se han realizado "
                          f"cambios relevantes en la funcionalidad de la aplicación. En concreto, a partir de ahora se podrán "
                          f"convocar y cancelar reuniones desde la pestaña de 'Agenda'.</p></div>"
                          "<p>Puedes consultar todos los detalles a través de nuestra aplicación.")

            html_body = generate_html_email("Andrea", email_title, email_text)
            msg = Message(email_title,
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[app.config['MAIL_DEFAULT_TESTER']])
            msg.html = html_body
            mail.send(msg)
            return 'Mail sent!'
        except Exception as e:
            return str(e)


##############################################################################################################
# GESTIÓN CRUD DE USUARIOS
##############################################################################################################

ns_usuario = api.namespace('usuarios', description='Operaciones sobre usuarios')

# Modelo para la entidad usuario
usuario_modelo = api.model('Usuario', {
    'Email': fields.String(required=True, description='Email del usuario'),
    'Password': fields.String(required=True, description='Contraseña'),
    'Nombre': fields.String(required=True, description='Nombre del usuario'),
    'Foto': fields.String(required=False, description='Ruta de la foto de perfil del usuario'),
    'Rol': fields.String(required=False, description='Rol del usuario, puede ser user o admin, por defecto user'),
    'Check_activo': fields.Boolean(required=False, description='Estado activo del usuario')
})


@ns_usuario.route('')
class UsuarioList(Resource):
    @jwt_required()
    @ns.doc('list_usuarios',
            description='Obtiene el listado completo de usuarios registrados en la aplicación',
            responses={
                200: 'Usuarios listados exitosamente',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    @ns.param('start', 'Inicio del rango de registros', type=int, required=False, default=0)
    @ns.param('limit', 'Número de registros a devolver', type=int, required=False, default=25)
    @ns.param('sort_by', 'Columna por la que ordenar los resultados', type=str, required=False)
    @ns.param('sort_direction', 'Orden por el que ordenar los resultados', type=str, required=False)
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Solo los administradores pueden obtener el listado completo
            if usuario_actual.rol == 'admin':
                start = request.args.get('start', 0)
                limit = request.args.get('limit', MAX_LIST_LIMIT)
                limit = validate_limit(limit)
                sort_by = request.args.get('sort_by', 'updated_at').lower()
                sort_direction = request.args.get('sort_direction', 'asc').lower()

                if sort_direction == 'asc':
                    usuarios = (session.query(Usuario).order_by(getattr(Usuario, sort_by)).offset(start).limit(limit).all())
                else:
                    usuarios = (session.query(Usuario).order_by(getattr(Usuario, sort_by).desc()).offset(start).limit(limit).all())

                if not usuarios:
                    logging.warning(f'Error en el intento de lectura del listado de usuarios, no encontrado.')
                    return {'error': 'Listado de usuarios no encontrado'}, 404

                usuarios_dict = [to_dict(usuario) for usuario in usuarios]
                logging.debug('Listado de usuarios obtenido exitosamente.')
                return usuarios_dict, 200
            else:
                logging.warning(f'Usuario {usuario_actual.email} no autorizado para leer el listado de usuarios.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al obtener el listado de usuarios: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    # No es necesario estar logueado para crear un nuevo usuario, cualquier persona puede registrarse
    # Pero solo un administrador podrá crear a otro usuario con rol de admin
    @jwt_required(optional=True)
    @ns.expect(usuario_modelo)
    @ns.doc('create_usuario',
            description='Crea el nuevo usuario con los datos introducidos, asignando el ID, rol, check activo y fechas por defecto,'
                        ' en caso de que no exista ya ese email. Si es admin si podrá asignarle el rol de admin a un nuevo usuario.',
            responses={
                201: 'Usuario creado exitosamente',
                400: 'Datos inválidos',
                409: 'Email ya registrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        data = request.form.to_dict()
        file = request.files.get('Foto')
        avatar = data.get('avatar')
        session = Session()
        try:
            # Verificar si el email ya existe en bbdd
            usuario_existente = session.query(Usuario).filter_by(email=data['Email']).first()
            if usuario_existente:
                logging.warning(f'Error en el intento de registro, email {data["Email"]} ya existente.')
                return {'error': 'El email introducido ya está registrado'}, 409

            nuevo_usuario = Usuario(
                email=data['Email'],
                password=hash_password(data['Password']),  # Hashear la contraseña para almacenarla
                nombre=data['Nombre'],
                foto='profile4.png',  # Avatar por defecto
                alertas=data.get('Alertas', 'false').lower() == 'true',  # Convertir a boolean
                rol='user',
                check_activo=True,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            # Gestionar la carga de la foto de perfil si sube alguna
            if file:
                filename = secure_filename(f"{nuevo_usuario.email}_{file.filename}")
                file.save(os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], filename))
                nuevo_usuario.foto = filename
            elif avatar:
                nuevo_usuario.foto = avatar

            # Solo los administradores pueden asignarle cualquier rol, si no será tipo user por defecto
            try:
                # Verifica si el token JWT está presente y es válido, si no saltará la excepción y continuará
                verify_jwt_in_request()
                usuario_actual = get_logged_user(session)

                # Si el admin logueado asigna un rol, se incluye, si no será por defecto user
                if usuario_actual.rol == 'admin':
                    nuevo_usuario.rol = data.get('Rol', 'user')
            except:
                # Si no está logueado, se continúa la ejecución del proceso
                pass

            session.add(nuevo_usuario)
            session.commit()
            usuario_dict = to_dict(nuevo_usuario)

            # Enviar correo electrónico de confirmación del registro
            email_title = f"¡Bienvenido a Panda Planning!"
            email_text = (f"<p>Gracias por registrarte en nuestra web, a partir de ahora podrás acceder a tus "
                          "proyectos y gestionar las tareas y comentarios de forma eficiente, "
                          "además de convocar reuniones e intercambiar mensajes con otros usuarios para estar"
                          " al día.</p>")
            html_body = generate_html_email(nuevo_usuario.nombre, email_title, email_text)
            nombre_usuario = nuevo_usuario.nombre.split()[0]
            msg = Message(subject=f"Bienvenido a Panda Planning, {nombre_usuario}",
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[nuevo_usuario.email]) # nuevo_usuario.email
            msg.html = html_body
            mail.send(msg)
            logging.debug(f'Correo de bienvenida enviado exitosamente: {nuevo_usuario.email}')

            logging.info(f'Usuario creado exitosamente: {nuevo_usuario.email}')
            return usuario_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al crear usuario: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al crear usuario: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


@ns_usuario.route('/profile')
class UserProfile(Resource):
    @jwt_required()
    @ns.doc('get_user_profile', description='Obtiene el perfil del usuario autenticado',
            responses={
                200: 'Perfil obtenido exitosamente',
                500: 'Error interno del servidor'
            })
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            usuario_dict = to_dict(usuario_actual)
            return usuario_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el perfil del usuario: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_usuario.route('/<int:id>')
class UsuarioResource(Resource):
    @jwt_required(optional=True)
    @ns.doc('get_usuario', description='Obtiene los datos del usuario con el id indicado, en caso de que exista',
            params={'id': 'ID del usuario'},
            responses={
                200: 'Usuario encontrado',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def get(self, id):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Los administradores pueden acceder a cualquiera, el resto solo puede acceder a sus propios datos
            if usuario_actual.rol == 'admin' or usuario_actual.id == id:
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Error en el intento de lectura de usuario con id {id} no encontrado.')
                    return {'error': 'Usuario no encontrado'}, 404

                usuario_dict = to_dict(usuario)
                logging.debug(f'Lectura de usuario con email: {usuario.email}')
                return usuario_dict, 200
            else:
                logging.warning(f'Usuario {usuario_actual.email} no autorizado para leer el id: {id}.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al obtener usuario con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(usuario_modelo)
    @ns.doc('update_usuario', description='Modifica los datos introducidos del usuario con el id indicado,'
                                          ' en caso de que exista', params={'id': 'ID del usuario'},
            responses={
                200: 'Usuario actualizado exitosamente',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                409: 'Email ya registrado',
                500: 'Error interno del servidor'
            })
    def put(self, id):
        data = request.form.to_dict()
        file = request.files.get('Foto')
        avatar = data.get('avatar')

        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            if usuario_actual.id != id:
                logging.warning(f'Usuario {usuario_actual.email} no autorizado para actualizar el id: {id}.')
                return {'error': 'Acceso denegado'}, 403

            usuario = session.get(Usuario, id)
            if not usuario:
                logging.warning(f'Error en el intento de actualización de usuario con id {id} no encontrado.')
                return {'error': 'Usuario no encontrado'}, 404

            new_email = data.get('Email')
            if new_email and new_email != usuario.email:
                # Verificar si el nuevo email ya existe
                email_exists = session.query(Usuario).filter(Usuario.email == new_email).first()
                if email_exists:
                    logging.warning(f'El nuevo email {new_email} ya está registrado.')
                    return {'error': 'El nuevo email introducido ya está registrado.'}, 409

            # Actualizar datos
            usuario.email = new_email
            usuario.nombre = data.get('Nombre', usuario.nombre)
            usuario.alertas = data.get('Alertas', usuario.alertas).lower() == 'true'  # Convertir de nuevo a boolean
            usuario.updated_at = datetime.datetime.now()

            # Gestionar la actualización de la contraseña
            actual_password = data.get('actualPassword')
            new_password = data.get('newPassword')

            # Si indica contraseñas se comprueba que la actual sea correcta y se actualiza
            if actual_password and new_password:
                if not (actual_password and new_password):
                    logging.warning('Todas las contraseñas deben estar completas.')
                    return {'error': 'Rellene todos los campos de contraseña.'}, 400

                if not verify_password(actual_password, usuario.password):
                    logging.warning('La contraseña actual no es correcta.')
                    return {'error': 'La contraseña actual no es correcta.'}, 403

                usuario.password = hash_password(new_password)

            # Gestionar la actualización de la foto de perfil
            if file or avatar:
                old_photo = usuario.foto
                # Eliminar la imagen de perfil anterior para liberar espacio
                if old_photo and not old_photo.startswith('profile'):
                    old_photo_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], old_photo)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)

                if file:
                    filename = secure_filename(f"{usuario.email}_{file.filename}")
                    file.save(os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], filename))
                    usuario.foto = filename
                elif avatar:
                    usuario.foto = avatar

            session.commit()
            usuario_dict = to_dict(usuario)
            logging.debug(f'Usuario actualizado exitosamente: {usuario.email}')
            return usuario_dict, 200

        except Exception as e:
            logging.error(f'Error al actualizar usuario con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.doc('delete_usuario',
            description='Elimina o da de baja al usuario con el id indicado en función del rol y del parámetro de eliminación',
            params={'id': 'ID del usuario', 'permanently': 'Boolean que indica si debe ser eliminado permanentemente'},
            responses={
                200: 'Operación exitosa',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def delete(self, id):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            permanently = request.args.get('permanently', 'false').lower() == 'true'

            # Solo los administradores pueden eliminar registros permanentemente
            if usuario_actual.rol == 'admin' and permanently:
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Error en el intento de eliminación de usuario con id: {id} no encontrado.')
                    return {'error': 'Usuario no encontrado'}, 404

                # Eliminar la imagen de perfil del servidor para liberar espacio
                if usuario.foto:
                    if not usuario.foto.startswith('profile'):
                        foto_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], usuario.foto)
                        if os.path.exists(foto_path):
                            os.remove(foto_path)

                session.delete(usuario)
                session.commit()
                logging.info(f'Usuario eliminado permanentemente por admin: {usuario.email}')
                return {'message': 'Usuario eliminado permanentemente'}, 200

            # Un usuario puede darse de baja a si mismo, pero no eliminarse
            elif usuario_actual.id == id:
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Intento de desactivación de usuario no encontrado, con id: {id}.')
                    return {'error': 'Usuario no encontrado'}, 404

                # Desasignar al usuario de todas las tareas asignadas
                tareas_asignadas = session.query(Tarea).filter_by(idusuario=id).all()
                for tarea in tareas_asignadas:
                    tarea.idusuario = None  # Desasignar la tarea
                    tarea.updated_at = datetime.datetime.now()

                usuario.check_activo = False
                usuario.alertas = False

                # Enviar correo electrónico de confirmación de la baja
                email_title = f"Tu solicitud de baja ha sido procesada"
                email_text = (f"<p>Se ha procesado correctamente tu petición para dar de baja tu perfil, a partir de ahora no podrás acceder a Panda Planning. "
                              "Tus proyectos y mensajes seguirán activos durante un tiempo, pero pasados 6 meses el equipo de Panda Planning podrá eliminar todos tus datos de la aplicación. "
                              "Si deseas reactivar tu cuenta, puedes ponerte en contacto con nuestro equipo en esta dirección de correo electrónico.</p>")
                html_body = generate_html_email(usuario.nombre, email_title, email_text)
                nombre_usuario = usuario.nombre.split()[0]
                msg = Message(subject=f"Bienvenido a Panda Planning, {nombre_usuario}",
                              sender=app.config['MAIL_DEFAULT_SENDER'],
                              recipients=[usuario.email])  # nuevo_usuario.email
                msg.html = html_body
                mail.send(msg)
                logging.debug(f'Correo de bienvenida enviado exitosamente: {usuario.email}')

                session.commit()
                logging.info(f'Usuario desactivado exitosamente: {usuario.email}')
                return {'message': 'Usuario desactivado exitosamente'}, 200

            else:
                logging.warning(f'Usuario {usuario_actual.email} no autorizado para eliminar el id: {id}.')
                return {'error': 'Acceso denegado'}, 403

        except Exception as e:
            logging.error(f'Error al eliminar usuario con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


##############################################################################################################
# GESTIÓN CRUD DE PROYECTOS
##############################################################################################################

ns_proyecto = api.namespace('proyectos', description='Operaciones sobre proyectos')

# Modelo para la entidad proyecto
proyecto_modelo = api.model('Proyecto', {
    'Titulo': fields.String(required=True, description='Título del proyecto'),
    'Descripcion': fields.String(description='Descripción del proyecto'),
    'Check_Activo': fields.Boolean(required=False, description='Estado activo del proyecto'),
    'Miembros': fields.List(fields.Nested(api.model('Miembro', {
        'Email': fields.String(required=True, description='Email del usuario'),
        'Permisos': fields.String(required=True, description='Permisos del usuario en el proyecto')
    })), description='Lista de miembros del proyecto')
})

""" Permisos de proyecto posibles: lector, editor, gestor """
def get_permisos_proyecto(id_proyecto, session):
    """ Devuelve los permisos que tiene el usuario actual sobre el proyecto indicado, en caso de ser miembro """
    usuario = get_logged_user(session)
    miembro = session.query(MiembroProyecto).filter_by(idusuario=usuario.id, idproyecto=id_proyecto).first()

    permisos = None
    if miembro:
        permisos = miembro.permisos

    return permisos


@ns_proyecto.route('')
class ProyectoList(Resource):
    @jwt_required()
    @ns.doc('list_proyectos',
            description='Obtiene el listado de proyectos de los que es miembro el usuario logueado o completo'
                        ' si es administrador y lo indica así',
            responses={
                200: 'Proyectos listados exitosamente',
                403: 'Acceso denegado',
                404: 'Proyectos no encontrados',
                500: 'Error interno del servidor'
            })
    @ns.param('start', 'Inicio del rango de registros', type=int, required=False, default=0)
    @ns.param('limit', 'Número de registros a devolver', type=int, required=False, default=MAX_LIST_LIMIT)
    @ns.param('sort_by', 'Columna por la que ordenar los resultados', type=str, required=False)
    @ns.param('sort_direction', 'Orden por el que ordenar los resultados', type=str, required=False)
    @ns.param('titulo', 'Título del proyecto para filtrar', type=str, required=False)
    @ns.param('check_activo', 'Estado activo del proyecto para filtrar', type=bool, required=False)
    @ns.param('complete', 'Indica si se desea el listado completo como administrador', type=bool, required=False)
    @ns.param('include_members', 'Indica si se deben incluir los datos de los miembros del proyecto', type=bool,
              required=False, default=False)
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            start = request.args.get('start', 0)
            limit = request.args.get('limit', MAX_LIST_LIMIT)
            limit = validate_limit(limit)
            sort_by = request.args.get('sort_by', 'updated_at').lower()
            sort_direction = request.args.get('sort_direction', 'asc').lower()
            titulo = request.args.get('titulo')
            check_activo = request.args.get('check_activo')
            complete = request.args.get('complete', False)
            include_members = request.args.get('include_members', False)

            # Solo los administradores pueden acceder al listado completo
            if usuario_actual.rol == 'admin' and complete:
                query = session.query(Proyecto)

            else:
                query = session.query(Proyecto).filter(
                    (Proyecto.id.in_(
                        session.query(MiembroProyecto.idproyecto).filter_by(idusuario=usuario_actual.id)
                    ))
                )

            if titulo:
                query = query.filter(Proyecto.titulo.ilike(f'%{titulo}%'))
            if check_activo is not None:
                query = query.filter(Proyecto.check_activo == check_activo)

            if sort_direction == 'asc':
                proyectos = query.order_by(getattr(Proyecto, sort_by)).offset(start).limit(limit).all()
            else:
                proyectos = query.order_by(getattr(Proyecto, sort_by).desc()).offset(start).limit(limit).all()

            if not proyectos:
                logging.warning(f'Error en el intento de lectura del listado de proyectos, no encontrados.')
                return {'error': 'Listado de proyectos no encontrado'}, 404

            proyectos_dict = []
            for proyecto in proyectos:
                proyecto_dict = to_dict(proyecto)
                if include_members:
                    miembros = session.query(MiembroProyecto).filter_by(idproyecto=proyecto.id).all()
                    miembros_list = []
                    for miembro in miembros:
                        usuario = session.get(Usuario, miembro.idusuario)
                        miembros_list.append({
                            'Idusuario': miembro.idusuario,
                            'Nombre': usuario.nombre,
                            'Email': usuario.email,
                            'Permisos': miembro.permisos,
                            'Foto': f"{request.url_root}api/uploads/profile_uploads/{usuario.foto}",
                            'Check_activo': usuario.check_activo
                        })

                    proyecto_dict = to_dict(proyecto)
                    # Se añade la lista de miembros al diccionario del proyecto
                    proyecto_dict['Miembros'] = miembros_list

                proyectos_dict.append(proyecto_dict)

            logging.debug('Listado de proyectos obtenido exitosamente.')
            return proyectos_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de proyectos: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(proyecto_modelo)
    @ns.doc('create_proyecto',
            description='Crea un nuevo proyecto con los datos introducidos',
            responses={
                201: 'Proyecto creado exitosamente',
                400: 'Datos inválidos',
                500: 'Error interno del servidor'
            })
    def post(self):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            nuevo_proyecto = Proyecto(
                titulo=data['Titulo'],
                descripcion=data.get('Descripcion', ''),
                check_activo=data.get('Check_Activo', True),  # Por defecto activo
                idcreador=usuario_actual.id,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            session.add(nuevo_proyecto)
            session.commit()
            proyecto_dict = to_dict(nuevo_proyecto)

            # Se añade al usuario creador como miembro del proyecto con permisos de gestor
            nuevo_miembro_proyecto = MiembroProyecto(
                idusuario=usuario_actual.id,
                idproyecto=nuevo_proyecto.id,
                permisos='gestor',
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )
            session.add(nuevo_miembro_proyecto)

            # Añadir otros miembros proporcionados en la solicitud
            if 'Miembros' in data:
                for miembro in data['Miembros']:
                    email = miembro['Email']
                    permisos = miembro['Permisos']
                    usuario_miembro = session.query(Usuario).filter_by(email=email).first()
                    if not usuario_miembro:
                        logging.warning(f'Error al intentar añadir miembro. Email no encontrado: {email}')
                        return {'error': f'Email de miembro no encontrado: {email}'}, 404

                    nuevo_miembro = MiembroProyecto(
                        idusuario=usuario_miembro.id,
                        idproyecto=nuevo_proyecto.id,
                        permisos=permisos,
                        created_at=datetime.datetime.now(),
                        updated_at=datetime.datetime.now()
                    )
                    session.add(nuevo_miembro)

                    # Enviar mensaje a cada nuevo miembro
                    mensaje = Mensaje(
                        asunto='Nuevo proyecto',
                        contenido=f'{usuario_actual.nombre} te ha invitado a un nuevo proyecto: {nuevo_proyecto.titulo}.'
                                  f' Ya puedes acceder a él desde tu workspace.',
                        check_leido=False,
                        created_at=datetime.datetime.now(),
                        updated_at=datetime.datetime.now(),
                        idemisor=usuario_actual.id,
                        idreceptor=usuario_miembro.id
                    )
                    session.add(mensaje)

                    # Se notifica por email si el nuevo miembro tiene activadas las alertas
                    if usuario_miembro.alertas:
                        email_title = "Nueva invitación a proyecto"
                        email_text = (f"<p>{usuario_actual.nombre} te ha invitado a un nuevo proyecto:"
                                      f" <strong>{nuevo_proyecto.titulo}</strong></p>"
                                      "<p>Puedes consultar todos los detalles a través de nuestra aplicación. "
                                      )
                        html_body = generate_html_email(usuario_miembro.nombre, email_title, email_text)
                        msg = Message(subject=email_title,
                                      sender=app.config['MAIL_DEFAULT_SENDER'],
                                      recipients=[email])
                        msg.html = html_body
                        mail.send(msg)

            session.commit()

            logging.debug(f'Proyecto creado exitosamente. ID: {nuevo_proyecto.id}. {nuevo_proyecto.titulo}.')
            return proyecto_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al crear proyecto: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al crear proyecto: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_proyecto.route('/<int:id>')
class ProyectoResource(Resource):
    @jwt_required()
    @ns.doc('get_proyecto', description='Obtiene el proyecto con el id indicado, en caso de que exista',
            params={'id': 'ID del proyecto'},
            responses={
                200: 'Proyecto encontrado',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def get(self, id):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            proyecto = session.get(Proyecto, id)
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Solo los miembros del proyecto pueden acceder
            if get_permisos_proyecto(id, session) is not None:

                # Obtener la lista de miembros del proyecto con su nombre y su email
                miembros = session.query(MiembroProyecto).filter_by(idproyecto=id).all()
                miembros_list = []
                for miembro in miembros:
                    usuario = session.get(Usuario, miembro.idusuario)
                    miembros_list.append({
                        'Idusuario': miembro.idusuario,
                        'Nombre': usuario.nombre,
                        'Email': usuario.email,
                        'Permisos': miembro.permisos,
                        'Foto': f"{request.url_root}api/uploads/profile_uploads/{usuario.foto}",
                        'Check_activo': usuario.check_activo
                    })

                proyecto_dict = to_dict(proyecto)
                proyecto_dict['Miembros'] = miembros_list  # Añadir la lista de miembros al diccionario del proyecto

                logging.debug(f'Lectura de proyecto con ID: {proyecto.id}. Título: {proyecto.titulo}.')
                return proyecto_dict, 200

            else:
                logging.warning(f'Usuario {usuario_actual.id} no autorizado para leer el proyecto id: {id}.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al obtener proyecto con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(proyecto_modelo)
    @ns.doc('update_proyecto',
            description='Modifica los datos introducidos del proyecto con el id indicado, en caso de que exista'
                        'y que el usuario sea un miembro con permisos de editor o gestor',
            params={'id': 'ID del proyecto'},
            responses={
                200: 'Proyecto actualizado exitosamente',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def put(self, id):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Solo los miembros con permisos de editor o gestor pueden actualizar un proyecto
            if (get_permisos_proyecto(id, session) == "gestor" or get_permisos_proyecto(id, session) == "editor"):

                proyecto = session.get(Proyecto, id)
                if not proyecto:
                    logging.warning(f'Error en el intento de actualización de proyecto con id: {id} no encontrado.')
                    return {'error': 'Proyecto no encontrado'}, 404

                proyecto.titulo = data.get('Titulo', proyecto.titulo)
                proyecto.descripcion = data.get('Descripcion', proyecto.descripcion)
                proyecto.updated_at = datetime.datetime.now()

                # Solo los gestores pueden dar de baja, reactivar un proyecto o modificar sus miembros
                if get_permisos_proyecto(id, session) == "gestor":
                    proyecto.check_activo = data.get('Check_Activo', proyecto.check_activo)

                    # Actualizar la lista de miembros si se proporciona
                    if 'Miembros' in data:
                        miembros_nuevos = data['Miembros']
                        miembros_actuales = session.query(MiembroProyecto).filter_by(idproyecto=id).all()
                        miembros_actuales_dict = {miembro.idusuario: miembro for miembro in miembros_actuales}

                        # Actualizar miembros existentes y agregar nuevos miembros
                        for miembro in miembros_nuevos:
                            email = miembro['Email']
                            permisos = miembro['Permisos']
                            participante = session.query(Usuario).filter_by(email=email).first()
                            if not participante:
                                logging.warning(f'Error al intentar añadir miembro. Email no encontrado: {email}')
                                return {'error': f'Email de miembro no encontrado: {email}'}, 404

                            if participante.id in miembros_actuales_dict:
                                miembros_actuales_dict[participante.id].permisos = permisos
                                miembros_actuales_dict[participante.id].updated_at = datetime.datetime.now()
                            else:
                                nuevo_miembro = MiembroProyecto(
                                    idusuario=participante.id,
                                    idproyecto=id,
                                    permisos=permisos,
                                    created_at=datetime.datetime.now(),
                                    updated_at=datetime.datetime.now()
                                )
                                session.add(nuevo_miembro)

                        # Eliminar miembros que ya no están en la lista proporcionada
                        for miembro_actual in miembros_actuales:
                            if miembro_actual.idusuario not in [
                                session.query(Usuario).filter_by(email=miembro['Email']).first().id for miembro in
                                miembros_nuevos]:
                                # Desasignar las tareas del miembro antes de eliminarlo
                                tareas_asignadas = session.query(Tarea).filter_by(idproyecto=id,
                                                                                  idusuario=miembro_actual.idusuario).all()
                                for tarea in tareas_asignadas:
                                    tarea.idusuario = None  # Desasignar la tarea
                                session.delete(miembro_actual)

                session.commit()
                proyecto_dict = to_dict(proyecto)
                logging.debug(f'Proyecto actualizado exitosamente: {proyecto.titulo}.')
                return proyecto_dict, 200

            else:
                logging.warning(f'Usuario {usuario_actual.id} no autorizado para actualizar el proyecto id: {id}.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al actualizar proyecto con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.doc('delete_proyecto',
            description='Elimina o desactiva el proyecto con el id indicado en función del rol y del parámetro de eliminación',
            params={'id': 'ID del proyecto', 'permanently': 'Boolean que indica si debe ser eliminado permanentemente'},
            responses={
                200: 'Operación exitosa',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def delete(self, id):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            permanently = request.args.get('permanently', 'false').lower() == 'true'

            # Solo los administradores pueden eliminar un proyecto permanentemente
            # Los miembros con permisos de gestor pueden darlo de baja
            if (usuario_actual.rol == "admin" or get_permisos_proyecto(id, session) == "gestor"):

                proyecto = session.get(Proyecto, id)
                if not proyecto:
                    logging.warning(f'Error en el intento de eliminación de proyecto con id: {id} no encontrado.')
                    return {'error': 'Proyecto no encontrado'}, 404

                if permanently and usuario_actual.rol == 'admin':
                    session.delete(proyecto)
                    session.commit()
                    logging.debug(f'Proyecto eliminado permanentemente. ID: {proyecto.id}. {proyecto.titulo}.')
                    return {'message': 'Proyecto eliminado permanentemente'}, 200
                else:
                    # Desasignar usuarios de las tareas del proyecto antes de darlo de baja
                    tareas = session.query(Tarea).filter_by(idproyecto=id).all()
                    for tarea in tareas:
                        tarea.idusuario = None
                        tarea.updated_at = datetime.datetime.now()

                    proyecto.check_activo = False
                    session.commit()
                    logging.debug(f'Proyecto desactivado exitosamente. ID: {proyecto.id}. {proyecto.titulo}.')
                    return {'message': 'Proyecto desactivado exitosamente'}, 200

            else:
                logging.warning(f'Usuario {usuario_actual.id} no autorizado para eliminar el proyecto id: {id}.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al eliminar proyecto con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()



##############################################################################################################
# GESTIÓN CRUD DE TAREAS
##############################################################################################################

ns_tarea = api.namespace('tareas', path='/proyectos/<int:id_proyecto>/tareas',
                         description='Operaciones sobre tareas de un proyecto específico')

# Modelo para la entidad tarea
tarea_modelo = api.model('Tarea', {
    'Titulo': fields.String(required=True, description='Título de la tarea'),
    'Descripcion': fields.String(description='Descripción de la tarea'),
    'Fechainicio': fields.Date(description='Fecha de inicio de la tarea'),
    'Fechafin': fields.Date(description='Fecha de fin de la tarea'),
    'Prioridad': fields.Integer(required=True, description='Prioridad de la tarea: 1 = Baja, 2 = Media, 3 = Alta'),
    'Estado': fields.String(description='Estado de la tarea: To do, In progress, Blocked, Done'),
    'Idusuario': fields.Integer(description='ID del usuario asignado a la tarea')
})


@ns_tarea.route('')
class TareaList(Resource):
    @jwt_required()
    @ns.doc('list_tareas',
            description='Obtiene el listado de tareas de un proyecto ordenadas por fecha fin, estado y prioridad',
            params={'id_proyecto': 'ID del proyecto'},
            responses={
                200: 'Listado de tareas obtenido exitosamente',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    @ns.param('start', 'Inicio del rango de registros', type=int, required=False, default=0)
    @ns.param('limit', 'Número de registros a devolver', type=int, required=False, default=MAX_LIST_LIMIT)
    @ns.param('Idusuario', 'Filtrar listado de tareas por id del usuario asignado a ella', type=int, required=False)
    def get(self, id_proyecto):
        session = Session()
        try:
            # Verificar si el proyecto existe
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None:
                return {'error': 'Acceso denegado'}, 403

            start = request.args.get('start', None, type=int)
            limit = request.args.get('limit', MAX_LIST_LIMIT)
            limit = validate_limit(limit)
            id_usuario = request.args.get('Idusuario', type=int)

            query = session.query(Tarea).filter_by(idproyecto=id_proyecto)

            if id_usuario:
                query = query.filter_by(idusuario=id_usuario)

            query = query.order_by(Tarea.fechafin, Tarea.prioridad.desc(), Tarea.updated_at.desc())

            if start is not None and limit is not None:
                tareas = query.offset(start).limit(limit).all()
            else:
                tareas = query.all()

            tareas_dict = [to_dict(tarea) for tarea in tareas]

            logging.debug('Listado de tareas obtenido exitosamente.')
            return tareas_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de tareas: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(tarea_modelo)
    @ns.doc('create_tarea',
            description='Crea una nueva tarea en un proyecto', params={'id_proyecto': 'ID del proyecto'},
            responses={
                201: 'Tarea creada exitosamente',
                400: 'Datos inválidos',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self, id_proyecto):
        data = request.get_json()
        session = Session()
        try:
            # Verificar si el proyecto existe
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            usuario_asignado = None
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None or permisos == 'lector':
                return {'error': 'Acceso denegado'}, 403

            # Verificar si el usuario asignado a la tarea existe y es miembro del proyecto
            usuario_asignado = None
            if 'Idusuario' in data:
                if data['Idusuario'] == '' : data['Idusuario'] = None
                if data['Idusuario'] is not None:
                    usuario_asignado = session.query(MiembroProyecto).filter_by(idusuario=data.get('Idusuario'),
                                                                             idproyecto=id_proyecto).first()

                    if not usuario_asignado:
                        return {'error': 'Acceso denegado para el usuario asignado'}, 403

            nueva_tarea = Tarea(
                titulo=data['Titulo'],
                descripcion=data.get('Descripcion', ''),
                fechainicio=data.get('Fechainicio', None),
                fechafin=data.get('Fechafin', None),
                prioridad=data['Prioridad'],
                estado=data['Estado'],
                idusuario=data.get('Idusuario', None),
                idproyecto=id_proyecto,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            session.add(nueva_tarea)
            session.commit()
            tarea_dict = to_dict(nueva_tarea)

            if usuario_asignado is not None:
                # Obtener detalles del usuario asignado y logueado
                usuario_asignado_detalles = session.query(Usuario).filter_by(id=usuario_asignado.idusuario).first()
                usuario_actual = get_logged_user(session)

                # Se notifica por email si el usuario asignado tiene activadas las alertas y no es el mismo que el usuario logueado
                if usuario_asignado_detalles.alertas and usuario_asignado_detalles.id != usuario_actual.id:
                    prioridad_tarea = {
                        1: "Baja",
                        2: "Media",
                        3: "Alta"
                    }
                    email_title = "Nueva tarea asignada"
                    email_text = (f"<p>Te han asignado una nueva tarea del proyecto: {proyecto.titulo} </p>"
                                  f"<div class='info-card'>"
                                  f"<p>&emsp; Título: <strong>{nueva_tarea.titulo}</strong></p>"
                                  f"<p>&emsp; Prioridad: {prioridad_tarea.get(nueva_tarea.prioridad)}</p>"
                                  f"<p>&emsp; Estado: {nueva_tarea.estado}</p></div>"
                                  "<p>Puedes consultar todos los detalles a través de nuestra aplicación. "
                                  )
                    html_body = generate_html_email(usuario_asignado_detalles.nombre, email_title, email_text)
                    msg = Message(subject=email_title,
                                  sender=app.config['MAIL_DEFAULT_SENDER'],
                                  recipients=[usuario_asignado_detalles.email])
                    msg.html = html_body
                    mail.send(msg)

            logging.debug(f'Tarea creada exitosamente. ID: {nueva_tarea.id}. {nueva_tarea.titulo}.')
            return tarea_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al crear tarea: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al crear tarea: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


@ns_tarea.route('/<int:id>')
class TareaResource(Resource):
    @jwt_required()
    @ns.doc('get_tarea',
            description='Obtiene la tarea con el id indicado, en caso de que exista',
            params={'id_proyecto': 'ID del proyecto', 'id': 'ID de la tarea'},
            responses={
                200: 'Tarea encontrada',
                403: 'Acceso denegado',
                404: 'Proyecto o tarea no encontrados',
                500: 'Error interno del servidor'
            })
    def get(self, id_proyecto, id):
        session = Session()
        try:
            # Verificar si el proyecto y la tarea existen
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            tarea = session.get(Tarea, id)
            if not tarea:
                logging.warning(f'Error en el intento de lectura de tarea con id: {id} no encontrada.')
                return {'error': 'Tarea no encontrada'}, 404

            # Verificar si el usuario tiene permisos en el proyecto y que la tarea pertenece al mismo
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None or tarea.idproyecto != id_proyecto:
                logging.warning(
                    f'Error en el intento de lectura, la tarea con id {id} no pertenece al proyecto {id_proyecto}.')
                return {'error': 'Acceso denegado'}, 403

            tarea_dict = to_dict(tarea)
            logging.debug(f'Lectura de tarea con ID: {tarea.id}. Título: {tarea.titulo}.')
            return tarea_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener tarea con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(tarea_modelo)
    @ns.doc('update_tarea',
            description='Modifica los datos de la tarea con el id indicado, en caso de que exista',
            params={'id_proyecto': 'ID del proyecto', 'id': 'ID de la tarea'},
            responses={
                200: 'Tarea actualizada exitosamente',
                400: 'Datos inválidos',
                403: 'Acceso denegado',
                404: 'Proyecto o tarea no encontrados',
                500: 'Error interno del servidor'
            })
    def put(self, id_proyecto, id):
        data = request.get_json()
        session = Session()
        try:
            # Verificar si el proyecto y la tarea existen
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            tarea = session.get(Tarea, id)
            if not tarea:
                logging.warning(f'Error en el intento de actualización de tarea con id: {id} no encontrada.')
                return {'error': 'Tarea no encontrada'}, 404

            # Verificar si el usuario tiene permisos para editar el proyecto y si la tarea pertenece al mismo
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None or permisos == 'lector' or tarea.idproyecto != id_proyecto:
                logging.warning(
                    f'Error en el intento de actualización, no tienes permisos o la tarea con id {id} no pertenece al proyecto {id_proyecto}.')
                return {'error': 'Acceso denegado'}, 403

            # Verificar si el usuario asignado a la tarea existe y es miembro del proyecto
            usuario_asignado = None
            if 'Idusuario' in data:
                if data['Idusuario'] == '': data['Idusuario'] = None
                if data['Idusuario'] is not None:
                    usuario_asignado = session.query(MiembroProyecto).filter_by(idusuario=data.get('Idusuario'),
                                                                             idproyecto=id_proyecto).first()
                    if not usuario_asignado:
                        return {'error': 'Acceso denegado para el usuario asignado'}, 403

            tarea.titulo = data.get('Titulo', tarea.titulo)
            tarea.descripcion = data.get('Descripcion', tarea.descripcion)
            tarea.fechainicio = data.get('Fechainicio', tarea.fechainicio)
            tarea.fechafin = data.get('Fechafin', tarea.fechafin)  # null si se quiere dejar en blanco
            tarea.prioridad = data.get('Prioridad', tarea.prioridad)
            tarea.estado = data.get('Estado', tarea.estado)
            tarea.idusuario = data.get('Idusuario', tarea.idusuario)
            tarea.updated_at = datetime.datetime.now()

            session.commit()
            tarea_dict = to_dict(tarea)

            # Se notifica al nuevo usuario asignado si se indica
            if usuario_asignado is not None:
                # Obtener detalles del usuario asignado
                usuario_asignado_detalles = session.query(Usuario).filter_by(id=usuario_asignado.idusuario).first()
                usuario_actual = get_logged_user(session)

                # Se notifica por email si el usuario asignado tiene activadas las alertas y no es el mismo que el usuario logueado
                if usuario_asignado_detalles.alertas and usuario_asignado_detalles.id != usuario_actual.id:
                    prioridad_tarea = {
                        1: "Baja",
                        2: "Media",
                        3: "Alta"
                    }
                    email_title = "Nueva tarea asignada"
                    email_text = (f"<p>Te han asignado una nueva tarea del proyecto: {proyecto.titulo} </p>"
                                  f"<div class='info-card'>"
                                  f"<p>&emsp; Título: <strong>{tarea.titulo}</strong></p>"
                                  f"<p>&emsp; Prioridad: {prioridad_tarea.get(tarea.prioridad)}</p>"
                                  f"<p>&emsp; Estado: {tarea.estado}</p></div>"
                                  "<p>Puedes consultar todos los detalles a través de nuestra aplicación. "
                                  )
                    html_body = generate_html_email(usuario_asignado_detalles.nombre, email_title, email_text)
                    msg = Message(subject=email_title,
                                  sender=app.config['MAIL_DEFAULT_SENDER'],
                                  recipients=[usuario_asignado_detalles.email])
                    msg.html = html_body
                    mail.send(msg)

            logging.debug(f'Tarea actualizada exitosamente. ID: {tarea.id}. {tarea.titulo}.')
            return tarea_dict, 200
        except Exception as e:
            logging.error(f'Error al actualizar tarea con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.doc('delete_tarea',
            description='Elimina la tarea con el id indicado. Solo puede eliminarse permanentemente.',
            params={'id_proyecto': 'ID del proyecto', 'id': 'ID de la tarea'},
            responses={
                200: 'Tarea eliminada exitosamente',
                403: 'Acceso denegado',
                404: 'Proyecto o tarea no encontrados',
                500: 'Error interno del servidor'
            })
    def delete(self, id_proyecto, id):
        session = Session()
        try:
            # Verificar si el proyecto y la tarea existen
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            tarea = session.get(Tarea, id)
            if not tarea:
                logging.warning(f'Error en el intento de eliminación de tarea con id: {id} no encontrada.')
                return {'error': 'Tarea no encontrada'}, 404

            # Verificar si el usuario tiene permisos de gestor en el proyecto y si la tarea pertenece al mismo
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos != 'gestor' or tarea.idproyecto != id_proyecto:
                logging.warning(
                    f'Error en el intento de eliminación, la tarea con id {id} no pertenece al proyecto {id_proyecto}.')
                return {'error': 'Acceso denegado'}, 403

            session.delete(tarea)
            session.commit()
            logging.debug(f'Tarea eliminada exitosamente. ID: {tarea.id}. {tarea.titulo}.')
            return {'message': 'Tarea eliminada exitosamente'}, 200
        except Exception as e:
            logging.error(f'Error al eliminar tarea con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


# Endpoint para obtener listado de tareas de un usuario concreto, sin indicar proyecto
ns_tarea_usuario = api.namespace('tareas_usuario', path='/tareas_usuario',
                                 description='Operaciones sobre tareas asignadas a un usuario específico')

@ns_tarea_usuario.route('')
class TareaListByUsuario(Resource):
    @jwt_required()
    @ns_tarea_usuario.param('Idusuario', 'Filtrar listado de tareas por id del usuario asignado a ella', type=int, required=True)
    @ns_tarea_usuario.param('estado', 'Filtrar listado de tareas por estado', type=str, required=False)
    @ns_tarea_usuario.param('start', 'Inicio del rango de registros', type=int, required=False, default=0)
    @ns_tarea_usuario.param('limit', 'Número de registros a devolver', type=int, required=False, default=MAX_LIST_LIMIT)
    def get(self):
        session = Session()
        try:
            id_usuario = request.args.get('Idusuario', type=int)
            if not id_usuario:
                return {'error': 'Idusuario es requerido'}, 400

            start = request.args.get('start', 0, type=int)
            limit = request.args.get('limit', MAX_LIST_LIMIT, type=int)
            limit = validate_limit(limit)
            estado = request.args.get('estado')

            query = session.query(Tarea).filter_by(idusuario=id_usuario)

            if estado:
                query = query.filter_by(estado=estado)
            else:
                # query filtrando por estado To do o In progress
                query = query.filter(Tarea.estado != "Done", Tarea.estado != "Blocked")

            tareas = query.order_by(Tarea.fechafin, Tarea.prioridad.desc()).offset(start).limit(limit).all()

            if not tareas:
                return {'error': 'No se encontraron tareas'}, 404

            tareas_dict = [to_dict(tarea) for tarea in tareas]

            logging.debug('Listado de tareas obtenido exitosamente.')
            return tareas_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de tareas: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()



##############################################################################################################
# GESTIÓN CRUD DE COMENTARIOS
##############################################################################################################

ns_comentario = api.namespace('comentarios', path='/proyectos/<int:id_proyecto>/comentarios',
                              description='Operaciones sobre comentarios de un proyecto específico')

# Modelo para la entidad archivo
archivo_modelo = api.model('Archivo', {
    'Nombre': fields.String(required=False, description='Nombre del archivo'),
    'Ruta': fields.String(required=True, description='Ruta del archivo'),
    'IDComentario': fields.Integer(required=False, description='ID del comentario al que pertenece el archivo')
})

# Modelo para la entidad comentario
comentario_modelo = api.model('Comentario', {
    'Contenido': fields.String(required=False, description='Contenido del comentario'),
    'Archivos': fields.List(fields.Nested(archivo_modelo), description='Lista de archivos adjuntos del comentario')
})

@ns_comentario.route('')
class ComentarioList(Resource):
    @jwt_required()
    @ns.doc('list_comentarios',
            description='Obtiene el listado de comentarios de un proyecto', params={'id_proyecto': 'ID del proyecto'},
            responses={
                200: 'Listado de comentarios obtenido exitosamente',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def get(self, id_proyecto):
        session = Session()
        try:
            # Verificar si el proyecto existe
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None:
                return {'error': 'Acceso denegado'}, 403

            comentarios = session.query(Comentario).filter_by(idproyecto=id_proyecto).all()
            comentarios_list = []
            for comentario in comentarios:
                comentario_dict = to_dict(comentario)
                archivos = session.query(Archivo).filter_by(idcomentario=comentario.id).all()
                comentario_dict['Archivos'] = [to_dict(archivo) for archivo in archivos]
                comentarios_list.append(comentario_dict)

            logging.debug('Listado de comentarios obtenido exitosamente.')
            return comentarios_list, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de comentarios: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(comentario_modelo)
    @ns.doc('create_comentario',
            description='Crea un nuevo comentario en un proyecto', params={'id_proyecto': 'ID del proyecto'},
            responses={
                201: 'Comentario creado exitosamente',
                400: 'Datos inválidos',
                403: 'Acceso denegado',
                404: 'Proyecto no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self, id_proyecto):
        session = Session()
        try:
            # Verificar si el proyecto existe
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            usuario_actual = get_logged_user(session)
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None:
                return {'error': 'Acceso denegado'}, 403

            # Obtener el contenido del comentario desde FormData
            contenido = request.form.get('Contenido', '')

            # Crear nuevo comentario
            nuevo_comentario = Comentario(
                contenido=contenido,
                idproyecto=id_proyecto,
                idusuario=usuario_actual.id,
                created_at=datetime.datetime.now()
            )

            session.add(nuevo_comentario)
            session.commit()

            # Procesar archivos adjuntos
            archivos = request.files.getlist("Archivos")
            for archivo in archivos:
                if archivo and archivo.filename:
                    filename = secure_filename(f"{nuevo_comentario.id}_{archivo.filename}")
                    archivo.save(os.path.join(app.config['FILES_UPLOAD_FOLDER'], filename))

                    nuevo_archivo = Archivo(
                        nombre=archivo.filename,
                        ruta=filename,
                        idcomentario=nuevo_comentario.id
                    )
                    session.add(nuevo_archivo)
                    session.commit()

            # Convertir el comentario a diccionario para la respuesta
            comentario_dict = to_dict(nuevo_comentario)
            archivos = session.query(Archivo).filter_by(idcomentario=nuevo_comentario.id).all()
            comentario_dict['Archivos'] = [to_dict(archivo) for archivo in archivos]

            logging.debug(f'Comentario creado exitosamente. ID: {nuevo_comentario.id}.')
            return comentario_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al crear comentario: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al crear comentario: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


##############################################################################################################
# GESTIÓN CRUD DE MENSAJES
##############################################################################################################

ns_mensaje = api.namespace('mensajes', description='Operaciones sobre mensajes entre usuarios')

# Modelo para la entidad mensaje
mensaje_modelo = api.model('Mensaje', {
    'EmailReceptor': fields.String(required=True, description='Email del receptor del mensaje'),
    'Asunto': fields.String(required=True, description='Asunto del mensaje'),
    'Contenido': fields.String(required=True, description='Contenido del mensaje')
})

@ns_mensaje.route('/chats')
class ChatList(Resource):
    @jwt_required()
    @ns.doc('list_chats', description='Obtiene el listado de chats del usuario logueado con el último mensaje',
            responses={
                200: 'Listado de chats obtenido exitosamente',
                403: 'Acceso denegado',
                500: 'Error interno del servidor'
            })
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Obtener los mensajes donde el usuario actual sea emisor o receptor
            mensajes = session.query(Mensaje).filter(
                or_(Mensaje.idemisor == usuario_actual.id, Mensaje.idreceptor == usuario_actual.id)
            ).order_by(Mensaje.created_at.desc()).all()

            # Almaceno los id de los usuarios con los que comparte el chat, para listarlos
            chats_dict = {}
            for mensaje in mensajes:
                # Filtro si soy emisor o receptor del mensaje
                if mensaje.idemisor != usuario_actual.id:
                    otro_usuario_id = mensaje.idemisor
                else:
                    otro_usuario_id = mensaje.idreceptor

                # Filtrar los distintos usuarios por orden de recientes
                if otro_usuario_id not in chats_dict:
                    otro_usuario = session.query(Usuario).filter_by(id=otro_usuario_id).first()

                    # Determinar el estado de lectura para el usuario actual
                    leido_por_mi = not (mensaje.idreceptor == usuario_actual.id and not mensaje.check_leido)

                    # Determinar el estado de lectura para el otro usuario
                    leido_por_otro = mensaje.idemisor == usuario_actual.id and not mensaje.check_leido

                    # Se asigna el id del otro usuario como posicion en el diccionario
                    chats_dict[otro_usuario_id] = {
                        'Idusuario': otro_usuario.id,
                        'Email': otro_usuario.email,
                        'Nombre': otro_usuario.nombre,
                        'Foto': f"{request.url_root}api/uploads/profile_uploads/{otro_usuario.foto}",
                        'UltimoMensaje': mensaje.created_at.isoformat(),
                        'LeidoPorMi': leido_por_mi,
                        'LeidoPorOtro': leido_por_otro
                    }

            # Convierto el diccionario en lista
            chats_list = [{'Idusuario': key, **value} for key, value in chats_dict.items()]
            return chats_list, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de chats: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_mensaje.route('/chats/<int:id_usuario>')
class ChatResource(Resource):
    @jwt_required()
    @ns.doc('get_chat', description='Obtiene el chat con un usuario específico', params={'id_usuario': 'ID del usuario'},
            responses={
                200: 'Chat obtenido exitosamente',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def get(self, id_usuario):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Verificar si el usuario receptor existe
            receptor = session.query(Usuario).filter_by(id=id_usuario).first()
            if not receptor:
                logging.warning(f'Error en el intento de lectura de usuario con id: {id_usuario} no encontrado.')
                return {'error': 'Usuario no encontrado'}, 404

            # Obtener los mensajes entre los dos usuarios
            mensajes = session.query(Mensaje).filter(
                or_(
                    and_(Mensaje.idemisor == usuario_actual.id, Mensaje.idreceptor == id_usuario),
                    and_(Mensaje.idemisor == id_usuario, Mensaje.idreceptor == usuario_actual.id)
                )
            ).order_by(Mensaje.created_at.desc()).all()

            # Marcar como leídos los mensajes recibidos por el usuario actual
            for mensaje in mensajes:
                if mensaje.idreceptor == usuario_actual.id and not mensaje.check_leido:
                    mensaje.check_leido = True
            session.commit()

            mensajes_dict = [to_dict(mensaje) for mensaje in mensajes]
            return mensajes_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el chat con el usuario {id_usuario}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_mensaje.route('')
class MensajeSend(Resource):
    @jwt_required()
    @ns.expect(mensaje_modelo)
    @ns.doc('send_mensaje',
            description='Envía un mensaje a otro usuario o hace un comunicado general si el emisor es administrador',
            responses={
                201: 'Mensaje enviado exitosamente',
                400: 'Datos inválidos',
                403: 'Acceso denegado',
                404: 'Usuario receptor no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            comunicado = data.get('comunicado', False)

            # Verificar si el usuario es administrador y quiere enviar un comunicado
            if comunicado and usuario_actual.rol == 'admin':
                # Enviar mensaje a todos los usuarios activos
                usuarios_receptores = session.query(Usuario).filter(Usuario.check_activo == True).all()
                if not usuarios_receptores:
                    logging.warning('No hay usuarios disponibles para enviar el comunicado.')
                    return {'error': 'No hay usuarios disponibles para enviar el comunicado'}, 404

                for receptor in usuarios_receptores:
                    nuevo_mensaje = Mensaje(
                        asunto=data['Asunto'],
                        contenido=data['Contenido'],
                        check_leido=False,
                        created_at=datetime.datetime.now(),
                        updated_at=datetime.datetime.now(),
                        idemisor=1, # Usuario Panda Planning
                        idreceptor=receptor.id
                    )
                    session.add(nuevo_mensaje)

                    if receptor.alertas:
                        # Enviar correo de notificación a los usuarios con alertas activadas
                        email = receptor.email
                        email_title = "Nuevo comunicado de Panda Planning"
                        email_text = (f"<p>Panda Planning ha enviado un nuevo comunicado:"
                                      f"<div class='info-card'>"
                                      f"<p>&emsp; <strong>{nuevo_mensaje.asunto}</strong></p>"
                                      f"<p>&emsp; {nuevo_mensaje.contenido}</p></div>"
                                      "<p>Puedes consultar todos los detalles a través de nuestra aplicación."
                                      )
                        html_body = generate_html_email(receptor.nombre, email_title, email_text)
                        msg = Message(subject=email_title,
                                      sender=app.config['MAIL_DEFAULT_SENDER'],
                                      recipients=[email])
                        msg.html = html_body
                        mail.send(msg)
                        logging.debug(f'Correo de notificación de nuevo mensaje enviado a {email}')

                session.commit()

                logging.info(f'Comunicado enviado exitosamente por administrador con id: {usuario_actual.id}.')
                return {'message': 'Comunicado enviado exitosamente'}, 201

            # Si el usuario no es administrador o no quiere enviar un comunicado, se envía un mensaje individual entre usuarios
            # Verificar si el receptor existe y es un usuario activo mediante el correo electrónico
            receptor = session.query(Usuario).filter_by(email=data['EmailReceptor']).first()
            if not receptor:
                logging.warning(f'Error en el intento de envío de mensaje. '
                                f'Usuario receptor con email: {data["EmailReceptor"]} no encontrado.')
                return {'error': 'Usuario receptor no encontrado'}, 404
            if receptor.check_activo == False:
                logging.warning(f'Error en el intento de envío de mensaje. '
                                f'Usuario receptor con email: {data["EmailReceptor"]} inactivo.')
                return {'error': 'Usuario receptor inactivo'}, 400

            # Verificar si el usuario receptor no es el mismo que el emisor
            if usuario_actual.id == receptor.id:
                logging.warning(f'Error en el intento de envío de mensaje. Usuario con email: {data["EmailReceptor"]} '
                                f'ha intentado enviarse un mensaje a sí mismo.')
                return {'error': 'Usuario emisor y receptor idénticos'}, 400

            nuevo_mensaje = Mensaje(
                asunto=data['Asunto'],
                contenido=data['Contenido'],
                check_leido=False,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now(),
                idemisor=usuario_actual.id,
                idreceptor=receptor.id
            )

            session.add(nuevo_mensaje)
            session.commit()
            mensaje_dict = to_dict(nuevo_mensaje)

            logging.debug(f'Mensaje enviado exitosamente. ID: {nuevo_mensaje.id}.')
            return mensaje_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al enviar mensaje: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al enviar mensaje: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_mensaje.route('/unread_count')
class UnreadMessagesCount(Resource):
    @jwt_required()
    @ns.doc('unread_messages_count', description='Obtiene el número de mensajes sin leer del usuario logueado',
            responses={
                200: 'Número de mensajes sin leer obtenido exitosamente',
                403: 'Acceso denegado',
                500: 'Error interno del servidor'
            })
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            unread_count = session.query(Mensaje).filter_by(idreceptor=usuario_actual.id, check_leido=False).count()
            return {'unread_count': unread_count}, 200
        except Exception as e:
            logging.error(f'Error al obtener el número de mensajes sin leer: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


##############################################################################################################
# GESTIÓN CRUD DE REUNIONES
##############################################################################################################

ns_reunion = api.namespace('reuniones', description='Operaciones sobre reuniones')

# Modelo para la entidad reunión
reunion_modelo = api.model('Reunion', {
    'Titulo': fields.String(required=True, description='Título de la reunión'),
    'Descripcion': fields.String(description='Descripción de la reunión'),
    'FechaHora': fields.DateTime(required=True, description='Fecha y hora de la reunión'),
    'Duracion': fields.Integer(required=True, description='Duración de la reunión en minutos'),
    'Modalidad': fields.String(required=True, description='Modalidad de la reunión: presencial, virtual o hibrido'),
    'Participantes': fields.List(fields.String, required=True, description='Lista de correos electrónicos de los participantes')
})

@ns_reunion.route('')
class ReunionesList(Resource):
    @jwt_required()
    @ns_reunion.param('start', 'Inicio del rango de registros', type=int, required=False, default=0)
    @ns_reunion.param('limit', 'Número de registros a devolver', type=int, required=False, default=MAX_LIST_LIMIT)
    @ns_reunion.param('closest', 'Indica si se deben obtener las reuniones más cercanas', type=bool, required=False,
                      default=False)
    @ns.doc('list_reuniones', description='Obtiene el listado de reuniones del usuario logueado',
            responses={
                200: 'Listado de reuniones obtenido exitosamente',
                403: 'Acceso denegado',
                500: 'Error interno del servidor'
            })
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)
            start = request.args.get('start', 0, type=int)
            limit = request.args.get('limit', MAX_LIST_LIMIT, type=int)
            limit = validate_limit(limit)
            closest = request.args.get('closest', 'false').lower() == 'true'

            # Obtener las reuniones donde el usuario actual sea participante
            participantes = session.query(ParticipanteReunion).filter_by(idusuario=usuario_actual.id).all()
            reuniones_ids = [p.idreunion for p in participantes]

            query = session.query(Reunion).filter(Reunion.id.in_(reuniones_ids)).order_by(Reunion.fechahora.asc())

            if closest:
                query = query.filter(Reunion.fechahora >= datetime.datetime.now())

            reuniones = query.offset(start).limit(limit).all()

            reuniones_list = []
            for reunion in reuniones:
                reunion_dict = to_dict(reunion)
                participantes = session.query(ParticipanteReunion).filter_by(idreunion=reunion.id).all()

                # Construir la lista de participantes con detalles adicionales
                participantes_list = []
                for participante in participantes:
                    usuario = session.get(Usuario, participante.idusuario)
                    participantes_list.append({
                        'Idusuario': participante.idusuario,
                        'Nombre': usuario.nombre,
                        'Email': usuario.email,
                        'Foto': f"{request.url_root}api/uploads/profile_uploads/{usuario.foto}",
                        'Respuesta': participante.respuesta
                    })

                reunion_dict['Participantes'] = participantes_list
                reuniones_list.append(reunion_dict)

            return reuniones_list, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de reuniones: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(reunion_modelo)
    @ns.doc('create_reunion', description='Crea una convocatoria para una nueva reunión',
            responses={
                201: 'Reunión creada exitosamente',
                400: 'Datos inválidos',
                404: 'Email de participante no encontrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Verificar si todos los participantes existen en el sistema
            participantes_no_encontrados = []
            participantes_no_activos = []
            for email in data['Participantes']:
                participante = session.query(Usuario).filter_by(email=email).first()
                if not participante:
                    participantes_no_encontrados.append(email)
                if participante.check_activo == False:
                    participantes_no_activos.append(email)

            if participantes_no_encontrados:
                logging.warning(f'No se ha podido enviar la convocatoria, '
                                f'no se encuentran los emails {participantes_no_encontrados}.')
                return {'error': f'Emails de participantes no encontrados: '
                                 f'{", ".join(participantes_no_encontrados)}'}, 404

            if participantes_no_activos:
                logging.warning(f'No se ha podido enviar la convocatoria, '
                                f'los emails {participantes_no_activos} están dados de baja en la aplicación.')
                return {'error': f'Emails de participantes inactivos: '
                                 f'{", ".join(participantes_no_activos)}'}, 400

            nueva_reunion = Reunion(
                titulo=data['Titulo'],
                descripcion=data.get('Descripcion', ''),
                fechahora=data['FechaHora'],
                duracion=data['Duracion'],
                modalidad=data['Modalidad'],
                created_at=datetime.datetime.now(),
                idcreador=usuario_actual.id
            )

            session.add(nueva_reunion)
            session.commit()

            # Añadir al usuario actual como participante
            nuevo_participante = ParticipanteReunion(
                idreunion=nueva_reunion.id,
                idusuario=usuario_actual.id,
                respuesta='ACEPTADA',
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )
            session.add(nuevo_participante)

            # Añadir otros participantes como pendientes de responder a la convocatoria
            for email in data['Participantes']:
                participante = session.query(Usuario).filter_by(email=email).first()
                nuevo_participante = ParticipanteReunion(
                    idreunion=nueva_reunion.id,
                    idusuario=participante.id,
                    respuesta='PENDIENTE',
                    created_at=datetime.datetime.now(),
                    updated_at=datetime.datetime.now()
                )
                session.add(nuevo_participante)

                # Se notifica por email a cada usuario participante
                email_title = "Nueva reunión convocada"
                email_text = (f"<p>{usuario_actual.nombre} te ha convocado a una nueva reunión: </p>"
                              f"<div class='info-card'>"
                      f"<p>&emsp; Título: <strong>{nueva_reunion.titulo}</strong></p>"
                      f"<p>&emsp; Fecha y Hora: {nueva_reunion.fechahora}</p>"
                      f"<p>&emsp; Duración: {nueva_reunion.duracion} minutos</p>"
                      f"<p>&emsp; Modalidad: {nueva_reunion.modalidad}</p></div>"
                      "<p>No olvides dar una respuesta a través de nuestra aplicación, "
                      "donde podrás consultar todos los detalles de la convocatoria.</p>")
                html_body = generate_html_email(participante.nombre, email_title, email_text)
                msg = Message(subject=email_title,
                              sender=app.config['MAIL_DEFAULT_SENDER'],
                              recipients=[email])
                msg.html = html_body
                mail.send(msg)
                logging.debug(f'Correo de notificación de nueva convocatoria enviado a {email}')

            session.commit()

            reunion_dict = to_dict(nueva_reunion)
            reunion_dict['Participantes'] = data['Participantes']
            logging.debug(f'Reunión creada exitosamente. ID: {nueva_reunion.id}.')
            return reunion_dict, 201
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al crear reunión: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al crear reunión: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_reunion.route('/<int:id>')
class ReunionResource(Resource):
    @jwt_required()
    @ns.doc('delete_reunion', description='Elimina una reunión con el id indicado en caso de que sea su creador',
            params={'id': 'ID de la reunión'},
            responses={
                200: 'Reunión eliminada exitosamente',
                403: 'Acceso denegado',
                404: 'Reunión no encontrada',
                500: 'Error interno del servidor'
            })
    def delete(self, id):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            reunion = session.query(Reunion).filter_by(id=id).first()
            if not reunion:
                logging.warning(f'Error en el intento de eliminación de reunión con id {id} no encontrada.')
                return {'error': 'Reunión no encontrada'}, 404

            # Verificar si el usuario actual es el creador de la reunión
            if reunion.idcreador != usuario_actual.id:
                logging.warning(f'Usuario con id: {usuario_actual.id} no autorizado para eliminar la reunión con id: {id}.')
                return {'error': 'Acceso denegado'}, 403

            # Eliminar todos los participantes de la reunión
            participantes = session.query(ParticipanteReunion).filter_by(idreunion=id).all()
            for participante in participantes:
                session.delete(participante)

            session.delete(reunion)
            session.commit()

            # Notificar a todos los participantes
            for participante in participantes:

                usuario_participante = session.query(Usuario).filter_by(id=participante.idusuario).first()

                # Se notifica por email a cada usuario participante
                email_title = "Reunión cancelada"
                email_text = (f"<p>Se ha cancelado la siguiente reunión:</p>"
                              f"<div class='info-card'>"
                              f"<p>&emsp; Título: <strong>{reunion.titulo}</strong></p>"
                              f"<p>&emsp; Fecha y Hora: {reunion.fechahora}</p>"
                              f"<p>&emsp; Duración: {reunion.duracion} minutos</p>"
                              f"<p>&emsp; Modalidad: {reunion.modalidad}</p></div>"
                              )
                html_body = generate_html_email(usuario_participante.nombre, email_title, email_text)
                msg = Message(subject=email_title,
                              sender=app.config['MAIL_DEFAULT_SENDER'],
                              recipients=[usuario_participante.email])
                msg.html = html_body
                mail.send(msg)
                logging.debug(f'Correo de notificación de convocatoria cancelada enviado a {usuario_participante.email}')

            session.commit()
            logging.debug(f'Reunión eliminada exitosamente. ID: {reunion.id}.')
            return {'message': 'Reunión eliminada exitosamente'}, 200
        except Exception as e:
            session.rollback()
            logging.error(f'Error al eliminar reunión con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

@ns_reunion.route('/respuesta/<int:id>')
class RespuestaReunion(Resource):
    @jwt_required()
    @ns.doc('responder_reunion', description='Responde a una convocatoria de reunión pendiente',
            params={'id': 'ID de la reunión'},
            responses={
                200: 'Respuesta a la reunión registrada exitosamente',
                400: 'Datos inválidos',
                404: 'Reunión o usuario no encontrado',
                500: 'Error interno del servidor'
            })
    @ns.expect(api.model('Respuesta', {
        'Respuesta': fields.String(required=True, description='Respuesta del usuario a la reunión: ACEPTADA o RECHAZADA')
    }), validate=True)
    def post(self, id):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Verificar si la reunión existe
            reunion = session.query(Reunion).filter_by(id=id).first()
            if not reunion:
                logging.warning(f'Error en el intento de responder a la reunión con id: {id} no encontrada.')
                return {'error': 'Reunión no encontrada'}, 404

            # Verificar si el usuario es participante de la reunión
            participante = session.query(ParticipanteReunion).filter_by(idreunion=id, idusuario=usuario_actual.id).first()
            if not participante:
                logging.warning(f'Error en el intento de responder a la reunión. Usuario con id: {usuario_actual.id} no es participante.')
                return {'error': 'Usuario no es participante de la reunión'}, 404

            # Actualizar la respuesta del participante
            if 'Respuesta' not in data:
                logging.warning('Error en el intento de responder a la reunión. Falta la respuesta en los datos proporcionados.')
                return {'error': 'Falta la respuesta en los datos proporcionados'}, 400

            participante.respuesta = data['Respuesta']
            participante.updated_at = datetime.datetime.now()

            usuario_participante = session.query(Usuario).filter_by(id=participante.idusuario).first()
            usuario_creador = session.query(Usuario).filter_by(id=reunion.idcreador).first()
            # Se notifica por email al creador de la convocatoria
            email_title = "Reunión " + data['Respuesta']
            email_text = (f"<p>{usuario_participante.nombre} ha contestado a tu convocatoria:</p>"
                          f"<div class='info-card'>"
                          f"<p>&emsp; Título: <strong>{reunion.titulo}</strong></p>"
                          f"<p>&emsp; Fecha y Hora: {reunion.fechahora}</p>"
                          f"<p>&emsp; Duración: {reunion.duracion} minutos</p>"
                          f"<p>&emsp; Modalidad: {reunion.modalidad} minutos</p>"
                          f"<p>&emsp; Respuesta: <strong>{data['Respuesta']}<strong></p></div>"
                          )
            html_body = generate_html_email(usuario_creador.nombre, email_title, email_text)
            msg = Message(subject=email_title,
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[usuario_creador.email])
            msg.html = html_body
            mail.send(msg)
            logging.debug(f'Correo de notificación de respuesta a la convocatoria enviado a {usuario_creador.email}')

            session.commit()
            logging.debug(f'Respuesta a la reunión registrada exitosamente. ID Reunión: {reunion.id}.')
            return to_dict(participante), 200
        except IntegrityError as e:
            session.rollback()
            logging.error(f'Error de integridad en los datos introducidos al responder reunión: {e}')
            return {'error': str(e)}, 400
        except Exception as e:
            session.rollback()
            logging.error(f'Error al responder reunión: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()



##############################################################################################################
# CONFIGURACIÓN DEL SCHEDULER Y SCRIPT AUTOMATIZADO CADA 24H PARA MENSAJES NO LEÍDOS
##############################################################################################################

def revisar_mensajes_no_leidos():
    session = Session()
    try:
        # Obtener solo los usuarios con alertas configuradas como True
        usuarios = session.query(Usuario).filter(Usuario.check_activo == True, Usuario.alertas == True).all()

        # Revisar número de mensajes sin leer recibidos hace más de 24 horas y notificar por correo
        for usuario in usuarios:
            mensajes_no_leidos = session.query(Mensaje).filter(
        Mensaje.idreceptor == usuario.id,
                Mensaje.check_leido == False,
                Mensaje.created_at <= (datetime.datetime.now() - datetime.timedelta(hours=24))
            ).count()

            if mensajes_no_leidos > 0:
                enviar_correo_notificacion(usuario, mensajes_no_leidos)
    except Exception as e:
        logging.error(f'Error al revisar mensajes no leídos: {e}')
    finally:
        session.close()


def enviar_correo_notificacion(usuario, mensajes_no_leidos):
    try:
        email_title = "Tienes mensajes sin leer"
        email_text = (f"<p>Tienes {mensajes_no_leidos} mensajes nuevos esperando en nuestra aplicación.</p>"
                      "<p>No te olvides de revisarlos para estar al día.</p>"
                      "<p>Gracias.</p>")
        html_body = generate_html_email(usuario.nombre, email_title, email_text)
        msg = Message(subject=email_title,
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[usuario.email])
        msg.html = html_body
        mail.send(msg)
        logging.debug(f'Correo de notificación enviado a {usuario.email}')
    except Exception as e:
        logging.error(f'Error al enviar el correo de notificación a {usuario.email}: {e}')


def job_wrapper():
    with app.app_context():
        revisar_mensajes_no_leidos()


# Configuración del scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(job_wrapper, 'cron', hour=SCHEDULER_HOUR)  # Ejecución diaria programada en config
scheduler.start()

# Se cierra el scheduler al apagar la aplicación
atexit.register(lambda: scheduler.shutdown())


if __name__ == '__main__':
    with app.app_context():
        app.run(debug=False, host='0.0.0.0', port=5000)
