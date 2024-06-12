import logging
import string

from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, verify_jwt_in_request
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.inspection import inspect
from sqlalchemy.exc import IntegrityError
from config import DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER
import datetime
import random

# Configuración del logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s',
                    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()])

app = Flask(__name__)
CORS(app)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SWAGGER_UI_DOC_EXPANSION'] = 'list'
db = SQLAlchemy(app)

# Configuración de la clave secreta para JWT
app.config['JWT_SECRET_KEY'] = 'super1998AFHk'  # Cambia esto por una clave secreta real
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=8)
jwt = JWTManager(app)

# Configuración del correo electrónico
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = MAIL_DEFAULT_SENDER
mail = Mail(app)

# Reflexión de la base de datos dentro del contexto de la aplicación
with app.app_context():
    Base = automap_base()
    Base.prepare(autoload_with=db.engine)

    # Mapeo de tablas
    Usuario = Base.classes.usuarios
    Proyecto = Base.classes.proyectos
    MiembrosProyecto = Base.classes.miembrosproyecto
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
            obj_dict[column.key.capitalize()] = value

    return obj_dict

def get_logged_user(session):
    """ Devuelve los datos del usuario logueado en la session """
    identidad_actual = get_jwt()['sub']
    usuario_actual = session.query(Usuario).filter_by(id=identidad_actual).first()
    return usuario_actual

# Función que devuelve el cuerpo de un email con estilo personalizado
def generate_html_email(name, title, text):
    return f"""
    <html>
    <body style="font-family: Calibri; margin: 0; padding: 0;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="700">
            <tr>
                <td align="center" bgcolor="#4B62AE" style="padding: 30px 40px 25px;">
                    <h1 style="color: white;">{title}</h1>
                </td>
            </tr>
            <tr>
                <td bgcolor="#ffffff" style="padding: 40px 80px; font-size: 17px;">
                    <p>Hola {name},</p>
                    <p>{text}</p>
                    <br>
                    <p>El equipo de Panda Planning</p>
                </td>
            </tr>
            <tr>
                <td bgcolor="#4B62AE" style="padding: 20px 30px;">
                    <p style="color: white; text-align: center;">&copy; 2024 Panda Planning. Todos los derechos reservados.</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """


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
          description='Una API de ejemplo con Flask y Swagger',
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
                # Verificar si el usuario está inactivo
                if not usuario.check_activo:
                    logging.warning(f'Intento de inicio de sesión para usuario inactivo {email}.')
                    return {'message': 'Usuario inactivo'}, 403

                # Crear el token de acceso si el usuario está activo y la contraseña es correcta
                access_token = create_access_token(identity=usuario.id)
                logging.info(f'Usuario {email} ha iniciado sesión exitosamente.')
                return {
                    'access_token': access_token,
                    'usuario': to_dict(usuario)  # Convertir el objeto usuario a diccionario
                }, 200
            else:
                logging.warning(f'Intento fallido de inicio de sesión para el usuario {email}.')
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
            logging.info(f'Token {jti} ha sido revocado.')
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
                200: 'Contraseña reseteada y enviada exitosamente',
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
                logging.warning(f'Intento de reseteo de contraseña para email no registrado {email}.')
                return {'message': 'Usuario no encontrado'}, 404

            # Generar una nueva contraseña aleatoria
            nueva_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            hashed_password = hash_password(nueva_password)

            # Actualizar la contraseña del usuario en la base de datos
            usuario.password = hashed_password
            usuario.updated_at=datetime.datetime.now()
            session.commit()

            # Enviar la nueva contraseña por correo electrónico
            email_title = "Reseteo de contraseña"
            email_text = (f"<p>Tu nueva contraseña es: <strong>{nueva_password}</strong></p>"
                          "<p>Por favor, cambia esta contraseña después de iniciar sesión.</p>"
                          "<p>Gracias.</p>")
            html_body = generate_html_email(usuario.nombre, email_title, email_text)
            msg = Message(subject=email_title,
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[email])
            msg.html = html_body
            mail.send(msg)

            logging.info(f'Contraseña reseteada y enviada al usuario {email}.')
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
        try:
            nueva_password = "1234Test"
            # Enviar la nueva contraseña por correo electrónico
            email_title = "Reseteo contraseña"
            email_text = (f"<p>Tu nueva contraseña es: <strong>{nueva_password}</strong></p>"
                          "<p>Por favor, cambia esta contraseña después de iniciar sesión.</p>"
                          "<p>Gracias,</p>")
            html_body = generate_html_email("Andrea", email_title, email_text)
            msg = Message(email_title,
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=['iandreafh@gmail.com'])
            msg.html = html_body
            mail.send(msg)
            return 'Mail sent!'
        except Exception as e:
            return str(e)

##############################################################################################################
# GESTIÓN CRUD DE USUARIOS
##############################################################################################################

ns_usuario = api.namespace('user', description='Operaciones sobre usuarios')

# Modelo para la entidad usuario
usuario_modelo = api.model('Usuario', {
    'Email': fields.String(required=True, description='Email del usuario'),
    'Password': fields.String(required=True, description='Contraseña'),
    'Nombre': fields.String(required=True, description='Nombre del usuario'),
    'Edad': fields.Integer(required=True, description='Edad del usuario'),
    'Rol': fields.String(required=False, description='Rol del usuario'),
    'Check_activo': fields.Boolean(required=False, description='Estado activo del usuario')
})

@ns_usuario.route('/usuarios')
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
    def get(self):
        session = Session()
        try:
            usuarios = session.query(Usuario).all()
            if not usuarios:
                logging.warning(f'Error en el intento de lectura del listado de usuarios, no encontrado.')
                return {'error': 'Listado de usuarios no encontrado'}, 404

            usuario_actual = get_logged_user(session)

            # Solo los administradores pueden obtener el listado completo
            if usuario_actual.rol == 'admin':
                usuarios_dict = [to_dict(usuario) for usuario in usuarios]
                logging.info('Listado de usuarios obtenido exitosamente.')
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
    @ns.expect(usuario_modelo)
    @ns.doc('create_usuario',
            description='Crea el nuevo usuario con los datos introducidos, asignando el ID, rol, check activo y fechas por defecto,'
                        ' en caso de que no exista ya ese email.',
            responses={
                201: 'Usuario creado exitosamente',
                400: 'Datos inválidos',
                409: 'Email ya registrado',
                500: 'Error interno del servidor'
            })
    def post(self):
        data = request.get_json()
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
                edad=data['Edad'],
                # Estos valores son por defecto, no afecta lo que introduzca el usuario
                # TODO Pendiente de evaluar si se asigna de base un rol pending hasta confirmar correo
                rol='user',
                check_activo=True,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            # Solo los administradores pueden asignarle cualquier rol, si no será tipo user por defecto
            try:
                verify_jwt_in_request()
                usuario_actual = get_logged_user(session)

                if usuario_actual.rol == 'admin':
                    nuevo_usuario.rol = data.get('Rol', 'user')
            except:
                # No se requiere autenticación JWT para crear un nuevo usuario, por lo que si falla, simplemente continuamos
                pass

            session.add(nuevo_usuario)
            session.commit()
            usuario_dict = to_dict(nuevo_usuario)

            # Enviar correo electrónico de confirmación del registro
            email_title = f"¡Bienvenido a Panda Planning, {nuevo_usuario.nombre}!"
            email_text = (f"<h2>¡Bienvenido a Panda Planning!</h2>"
                          "<p>Gracias por registrarte en nuestra web, a partir de ahora podrás acceder a tus proyectos"
                          "y gestionar las tareas de forma eficiente y sincronizada, concretar reuniones "
                          "e intercambiar mensajes con otros usuarios.</p>"
                          "<p>Esperamos verte pronto.</p>")
            html_body = generate_html_email(nuevo_usuario.nombre, email_title, email_text)
            msg = Message(subject="¡Bienvenido!",
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[nuevo_usuario.email])
            msg.html = html_body
            mail.send(msg)
            logging.info(f'Correo de bienvenida enviado exitosamente: {nuevo_usuario.email}.')

            logging.info(f'Usuario creado exitosamente: {nuevo_usuario.email}.')
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

@ns_usuario.route('/usuarios/<int:id>')
class UsuarioResource(Resource):
    @jwt_required()
    @ns.doc('get_usuario', description='Obtiene el usuario con el id indicado, en caso de que exista',
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
                logging.info(f'Lectura de usuario con email: {usuario.email}.')
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
    @ns.doc('update_usuario', description='Modifica los datos introducidos del usuario con el id indicado, en caso de que exista',
            responses={
                200: 'Usuario actualizado exitosamente',
                403: 'Acceso denegado',
                404: 'Usuario no encontrado',
                500: 'Error interno del servidor'
            })
    def put(self, id):
        data = request.get_json()
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Los administradores pueden modificar a cualquier usuario, el resto solo puede modificar sus propios datos
            if usuario_actual.rol == 'admin' or usuario_actual.id == id:
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Error en el intento de actualización de usuario con id {id} no encontrado.')
                    return {'error': 'Usuario no encontrado'}, 404
                # Se actualizan solo los campos que se hayan introducido y la fecha updated_at, el resto se mantiene igual
                usuario.email = data.get('Email', usuario.email)
                usuario.nombre = data.get('Nombre', usuario.nombre)
                usuario.edad = data.get('Edad', usuario.edad)
                usuario.updated_at = datetime.datetime.now()

                # Solo los administradores pueden modificar el rol y estado activo del usuario
                if usuario_actual.rol == 'admin':
                    usuario.rol = data.get('Rol', usuario.rol)
                    usuario.check_activo = data.get('Check_activo', usuario.check_activo)

                session.commit()
                usuario_dict = to_dict(usuario)
                logging.info(f'Usuario actualizado exitosamente: {usuario.email}.')
                return usuario_dict, 200
            else:
                logging.warning(f'Usuario {usuario_actual.email} no autorizado para actualizar el id: {id}.')
                return {'error': 'Acceso denegado'}, 403
        except Exception as e:
            logging.error(f'Error al actualizar usuario con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.doc('delete_usuario', description='Elimina o da de baja al usuario con el id indicado',
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

            # Solo los administradores pueden eliminar registros
            if usuario_actual.rol == 'admin':
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Error en el intento de eliminación de usuario con id: {id} no encontrado.')
                    return {'error': 'Usuario no encontrado'}, 404
                session.delete(usuario)
                session.commit()
                logging.info(f'Usuario eliminado exitosamente por admin: {usuario.email}.')
                return {'message': 'Usuario eliminado exitosamente'}, 200
            # Un usuario puede darse de baja a si mismo, pero no eliminarse
            elif usuario_actual.id == id:
                usuario = session.get(Usuario, id)
                if not usuario:
                    logging.warning(f'Intento de eliminación de usuario no encontrado, con id: {id}.')
                    return {'error': 'Usuario no encontrado'}, 404
                usuario.check_activo = False
                session.commit()
                logging.info(f'Usuario desactivado exitosamente: {usuario.email}.')
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

ns_proyecto = api.namespace('project', description='Operaciones sobre proyectos')

# Modelo para la entidad proyecto
proyecto_modelo = api.model('Proyecto', {
    'Titulo': fields.String(required=True, description='Título del proyecto'),
    'Descripcion': fields.String(description='Descripción del proyecto'),
    'Check_Activo': fields.Boolean(required=True, description='Estado activo del proyecto'),
    'IDCreador': fields.Integer(required=True, description='ID del creador del proyecto'),
    'Miembros': fields.List(fields.Nested(api.model('Miembro', {
        'IDUsuario': fields.Integer(required=True, description='ID del usuario'),
        'Permisos': fields.String(required=True, description='Permisos del usuario en el proyecto')
    })), description='Lista de miembros del proyecto')
})

""" Permisos de proyecto posibles: lector, editor, gestor """
def get_permisos_proyecto(id_proyecto, session):
    """ Devuelve los permisos que tiene el usuario actual sobre el proyecto indicado, en caso de ser miembro """
    usuario = get_logged_user(session)
    miembro = session.query(MiembrosProyecto).filter_by(idusuario=usuario.id, idproyecto=id_proyecto).first()

    permisos = None
    if miembro:
        permisos = miembro.permisos

    return permisos


@ns_proyecto.route('/proyectos')
class ProyectoList(Resource):
    @jwt_required()
    @ns.doc('list_proyectos',
            description='Obtiene el listado de proyectos de los que es miembro el usuario logueado o completo para los administradores',
            responses={
                200: 'Proyectos listados exitosamente',
                403: 'Acceso denegado',
                404: 'Proyectos no encontrados',
                500: 'Error interno del servidor'
            })
    def get(self):
        session = Session()
        try:
            usuario_actual = get_logged_user(session)

            # Solo los administradores pueden acceder al listado completo
            if usuario_actual.rol == 'admin':
                proyectos = session.query(Proyecto).all()
            else:
                proyectos = session.query(Proyecto).filter(
                    (Proyecto.id.in_(
                        session.query(MiembrosProyecto.idproyecto).filter_by(idusuario=usuario_actual.id)
                    ))
                ).all()

            if not proyectos:
                logging.warning(f'Error en el intento de lectura del listado de proyectos, no encontrados.')
                return {'error': 'Listado de proyectos no encontrado'}, 404

            proyectos_dict = [to_dict(proyecto) for proyecto in proyectos]
            logging.info('Listado de proyectos obtenido exitosamente.')
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
            nuevo_proyecto = Proyecto(
                titulo=data['Titulo'],
                descripcion=data.get('Descripcion', ''),
                check_activo=True,
                idcreador=get_jwt()['sub'],
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            session.add(nuevo_proyecto)
            session.commit()
            proyecto_dict = to_dict(nuevo_proyecto)

            # Se añade al usuario creador como miembro del proyecto con permisos de gestor
            nuevo_miembro_proyecto = MiembrosProyecto(
                idusuario=nuevo_proyecto.idcreador,
                idproyecto=nuevo_proyecto.id,
                permisos='gestor',
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )
            session.add(nuevo_miembro_proyecto)
            session.commit()

            logging.info(f'Proyecto creado exitosamente. ID: {nuevo_proyecto.id}. {nuevo_proyecto.titulo}.')
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

@ns_proyecto.route('/proyectos/<int:id>')
class ProyectoResource(Resource):
    @jwt_required()
    @ns.doc('get_proyecto', description='Obtiene el proyecto con el id indicado, en caso de que exista',
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

            # Solo los administradores o miembros pueden acceder a un proyecto
            if (usuario_actual.rol == "admin" or get_permisos_proyecto(id, session) is not None):

                proyecto = session.get(Proyecto, id)
                if not proyecto:
                    logging.warning(f'Error en el intento de lectura de proyecto con id: {id} no encontrado.')
                    return {'error': 'Proyecto no encontrado'}, 404

                # Obtener la lista de miembros del proyecto con su nombre y su email
                miembros = session.query(MiembrosProyecto).filter_by(idproyecto=id).all()
                miembros_list = []
                for miembro in miembros:
                    usuario = session.get(Usuario, miembro.idusuario)
                    miembros_list.append({
                        'IDUsuario': miembro.idusuario,
                        'Nombre': usuario.nombre,
                        'Email': usuario.email,
                        'Permisos': miembro.permisos
                    })

                proyecto_dict = to_dict(proyecto)
                proyecto_dict['Miembros'] = miembros_list  # Añadir la lista de miembros al diccionario del proyecto

                logging.info(f'Lectura de proyecto con ID: {proyecto.id}. Título: {proyecto.titulo}.')
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
                    logging.warning(f'Error en el intento de eliminación de proyecto con id: {id} no encontrado.')
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
                        miembros_actuales = session.query(MiembrosProyecto).filter_by(idproyecto=id).all()
                        miembros_actuales_dict = {miembro.idusuario: miembro for miembro in miembros_actuales}

                        # Actualizar miembros existentes y agregar nuevos miembros
                        for miembro in miembros_nuevos:
                            id_usuario = miembro['IDUsuario']
                            permisos = miembro['Permisos']
                            if id_usuario in miembros_actuales_dict:
                                miembros_actuales_dict[id_usuario].permisos = permisos
                                miembros_actuales_dict[id_usuario].updated_at = datetime.datetime.now()
                            else:
                                nuevo_miembro = MiembrosProyecto(
                                    idusuario=id_usuario,
                                    idproyecto=id,
                                    permisos=permisos,
                                    created_at=datetime.datetime.now(),
                                    updated_at=datetime.datetime.now()
                                )
                                session.add(nuevo_miembro)

                        # Eliminar miembros que ya no están en la lista proporcionada
                        for miembro_actual in miembros_actuales:
                            if miembro_actual.idusuario not in [miembro['IDUsuario'] for miembro in miembros_nuevos]:
                                session.delete(miembro_actual)

                session.commit()
                proyecto_dict = to_dict(proyecto)
                logging.info(f'Proyecto actualizado exitosamente: {proyecto.titulo}.')
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
    @ns.doc('delete_proyecto', description='Elimina o desactiva el proyecto con el id indicado',
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

            # Solo los administradores pueden eliminar un proyecto, los miembros con permisos de gestor pueden darlo de baja
            if (usuario_actual.rol == "admin" or get_permisos_proyecto(id, session) == "gestor"):

                proyecto = session.get(Proyecto, id)
                if not proyecto:
                    logging.warning(f'Error en el intento de eliminación de proyecto con id: {id} no encontrado.')
                    return {'error': 'Proyecto no encontrado'}, 404

                if usuario_actual.rol == 'admin':
                    session.delete(proyecto)
                    session.commit()
                    logging.info(f'Proyecto eliminado exitosamente. ID: {proyecto.id}. {proyecto.titulo}.')
                    return {'message': 'Proyecto eliminado exitosamente'}, 200
                else:
                    proyecto.check_activo = False
                    session.commit()
                    logging.info(f'Proyecto desactivado exitosamente. ID: {proyecto.id}. {proyecto.titulo}.')
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

ns_tarea = api.namespace('project/{id_proyecto}/tasks', path='/project/<int:id_proyecto>/tasks',
                         description='Operaciones sobre tareas de un proyecto específico')

# Modelo para la entidad tarea
tarea_modelo = api.model('Tarea', {
    'Titulo': fields.String(required=True, description='Título de la tarea'),
    'Descripcion': fields.String(description='Descripción de la tarea'),
    'FechaInicio': fields.Date(description='Fecha de inicio de la tarea'),
    'FechaFin': fields.Date(description='Fecha de fin de la tarea'),
    'Estado': fields.String(required=True, description='Estado de la tarea'),
    'IDUsuario': fields.Integer(description='ID del usuario asignado a la tarea'),
    'IDProyecto': fields.Integer(required=True, description='ID del proyecto al que pertenece la tarea')
})


@ns_tarea.route('/')
class TareaList(Resource):
    @jwt_required()
    @ns.doc('list_tareas',
            description='Obtiene el listado de tareas de un proyecto',
            responses={
                200: 'Listado de tareas obtenido exitosamente',
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

            tareas = session.query(Tarea).filter_by(idproyecto=id_proyecto).all()
            tareas_dict = [to_dict(tarea) for tarea in tareas]

            logging.info('Listado de tareas obtenido exitosamente.')
            return tareas_dict, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de tareas: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(tarea_modelo)
    @ns.doc('create_tarea',
            description='Crea una nueva tarea en un proyecto',
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
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None or permisos == 'lector':
                return {'error': 'Acceso denegado'}, 403

            # Verificar si el usuario asignado a la tarea existe y es miembro del proyecto
            if 'IDUsuario' in data:
                usuario_asignado = session.query(MiembrosProyecto).filter_by(idusuario=data.get('IDUsuario'),
                                                                             idproyecto=id_proyecto).first()
                if not usuario_asignado:
                    return {'error': 'Acceso denegado para el usuario asignado'}, 403

            nueva_tarea = Tarea(
                titulo=data['Titulo'],
                descripcion=data.get('Descripcion', ''),
                fechainicio=data.get('FechaInicio', None),
                fechafin=data.get('FechaFin', None),
                estado=data['Estado'],
                idusuario=data.get('IDUsuario', None),
                idproyecto=id_proyecto,
                created_at=datetime.datetime.now(),
                updated_at=datetime.datetime.now()
            )

            session.add(nueva_tarea)
            session.commit()
            tarea_dict = to_dict(nueva_tarea)

            logging.info(f'Tarea creada exitosamente. ID: {nueva_tarea.id}. {nueva_tarea.titulo}.')
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
            logging.info(f'Lectura de tarea con ID: {tarea.id}. Título: {tarea.titulo}.')
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
                    f'Error en el intento de actualización, la tarea con id {id} no pertenece al proyecto {id_proyecto}.')
                return {'error': 'Acceso denegado'}, 403

            # Verificar si el usuario asignado a la tarea existe y es miembro del proyecto
            if 'IDUsuario' in data:
                usuario_asignado = session.query(MiembrosProyecto).filter_by(idusuario=data.get('IDUsuario'),
                                                                             idproyecto=id_proyecto).first()
                if not usuario_asignado:
                    return {'error': 'Acceso denegado para el usuario asignado'}, 403

            tarea.titulo = data.get('Titulo', tarea.titulo)
            tarea.descripcion = data.get('Descripcion', tarea.descripcion)
            tarea.fechainicio = data.get('FechaInicio', tarea.fechainicio)
            tarea.fechafin = data.get('FechaFin', tarea.fechafin)  # null si se quiere dejar en blanco
            tarea.estado = data.get('Estado', tarea.estado)
            tarea.idusuario = data.get('IDUsuario', tarea.idusuario)
            tarea.updated_at = datetime.datetime.now()

            session.commit()
            tarea_dict = to_dict(tarea)
            logging.info(f'Tarea actualizada exitosamente. ID: {tarea.id}. {tarea.titulo}.')
            return tarea_dict, 200
        except Exception as e:
            logging.error(f'Error al actualizar tarea con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.doc('delete_tarea',
            description='Elimina la tarea con el id indicado',
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
            logging.info(f'Tarea eliminada exitosamente. ID: {tarea.id}. {tarea.titulo}.')
            return {'message': 'Tarea eliminada exitosamente'}, 200
        except Exception as e:
            logging.error(f'Error al eliminar tarea con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


##############################################################################################################
# GESTIÓN CRUD DE COMENTARIOS
##############################################################################################################

ns_comentario = api.namespace('project/{id_proyecto}/comments', path='/project/<int:id_proyecto>/comments',
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

@ns_comentario.route('/')
class ComentarioList(Resource):
    @jwt_required()
    @ns.doc('list_comentarios',
            description='Obtiene el listado de comentarios de un proyecto',
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

            logging.info('Listado de comentarios obtenido exitosamente.')
            return comentarios_list, 200
        except Exception as e:
            logging.error(f'Error al obtener el listado de comentarios: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()

    @jwt_required()
    @ns.expect(comentario_modelo)
    @ns.doc('create_comentario',
            description='Crea un nuevo comentario en un proyecto',
            responses={
                201: 'Comentario creado exitosamente',
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
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            # Verificar si el usuario tiene permisos en el proyecto
            usuario_actual = get_logged_user(session)
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None:
                return {'error': 'Acceso denegado'}, 403

            nuevo_comentario = Comentario(
                contenido=data.get('Contenido', ''),
                idproyecto=id_proyecto,
                idusuario=usuario_actual.id,
                created_at=datetime.datetime.now()
            )

            session.add(nuevo_comentario)
            session.commit()

            # Procesar archivos adjuntos
            if 'Archivos' in data:
                for archivo_data in data['Archivos']:
                    nuevo_archivo = Archivo(
                        nombre=archivo_data.get('Nombre', ''),
                        ruta=archivo_data['Ruta'],
                        idcomentario=nuevo_comentario.id
                    )
                    session.add(nuevo_archivo)
                session.commit()

            comentario_dict = to_dict(nuevo_comentario)
            archivos = session.query(Archivo).filter_by(idcomentario=nuevo_comentario.id).all()
            comentario_dict['Archivos'] = [to_dict(archivo) for archivo in archivos]

            logging.info(f'Comentario creado exitosamente. ID: {nuevo_comentario.id}.')
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

@ns_comentario.route('/<int:id>')
class ComentarioResource(Resource):
    @jwt_required()
    @ns.doc('delete_comentario',
            description='Elimina un comentario con el id indicado',
            responses={
                200: 'Comentario eliminado exitosamente',
                403: 'Acceso denegado',
                404: 'Proyecto o comentario no encontrado',
                500: 'Error interno del servidor'
            })
    def delete(self, id_proyecto, id):
        session = Session()
        try:
            # Verificar si el proyecto y el comentario existen
            proyecto = session.query(Proyecto).filter_by(id=id_proyecto).first()
            if not proyecto:
                logging.warning(f'Error en el intento de lectura de proyecto con id: {id_proyecto} no encontrado.')
                return {'error': 'Proyecto no encontrado'}, 404

            comentario = session.query(Comentario).filter_by(id=id).first()
            if not comentario:
                logging.warning(f'Error en el intento de eliminación de comentario con id: {id} no encontrado.')
                return {'error': 'Comentario no encontrado'}, 404

            if comentario.idproyecto != id_proyecto:
                logging.warning(f'Error en el intento de eliminación, el comentario con id {id}'
                                f' no pertenece al proyecto {id_proyecto}.')
                return {'error': 'Acceso denegado'}, 403

            # Verificar si el usuario tiene permisos para borrar el comentario y si este pertenece al proyecto
            # Solo los gestores pueden borrar cualquier comentario, los editores y gestores solo los suyos
            usuario_actual = get_logged_user(session)
            permisos = get_permisos_proyecto(id_proyecto, session)
            if permisos is None or (permisos != 'gestor' and comentario.idusuario != usuario_actual.id):
                logging.warning(f'Error en el intento de eliminación de comentario con id: {id} por falta de permisos.')
                return {'error': 'Acceso denegado'}, 403

            # Eliminar archivos adjuntos
            archivos = session.query(Archivo).filter_by(idcomentario=id).all()
            for archivo in archivos:
                session.delete(archivo)

            session.delete(comentario)
            session.commit()

            logging.info(f'Comentario eliminado exitosamente. ID: {comentario.id}.')
            return {'message': 'Comentario eliminado exitosamente'}, 200
        except Exception as e:
            session.rollback()
            logging.error(f'Error al eliminar comentario con id {id}: {e}')
            return {'error': str(e)}, 500
        finally:
            session.close()


# MODELOS PENDIENTES DE IMPLEMENTAR

# Modelo para la entidad reunión
reunion_modelo = api.model('Reunion', {
    'Titulo': fields.String(required=True, description='Título de la reunión'),
    'Descripcion': fields.String(required=False, description='Descripción de la reunión'),
    'FechaHora': fields.DateTime(required=True, description='Fecha y hora de la reunión')
})

# Modelo para la entidad participante de la reunión
participante_reunion_modelo = api.model('ParticipanteReunion', {
    'IDReunion': fields.Integer(required=True, description='ID de la reunión'),
    'IDUsuario': fields.Integer(required=True, description='ID del usuario participante'),
    'Aceptada': fields.String(required=True, description='Estado de aceptación del usuario')
})

# Modelo para la entidad mensaje
mensaje_modelo = api.model('Mensaje', {
    'Asunto': fields.String(required=True, description='Asunto del mensaje'),
    'Contenido': fields.String(required=True, description='Contenido del mensaje'),
    'Check_Leido': fields.Boolean(required=True, description='Estado de lectura del mensaje'),
    'IDEmisor': fields.Integer(required=True, description='ID del emisor del mensaje'),
    'IDReceptor': fields.Integer(required=True, description='ID del receptor del mensaje')
})



if __name__ == '__main__':
    with app.app_context():
        app.run(debug=True)
