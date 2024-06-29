# Panda Planning - TFG Backend

Este repositorio contiene el código backend del proyecto TFG para la aplicación Panda Planning, desarrollada para el proyecto final del Grado de Ingeniería Informática en Sistemas de Información de la EPS UPO.

## Descripción

Panda Planning es una aplicación diseñada para ayudar en la gestión y planificación de tareas y proyectos. Este backend está desarrollado utilizando Flask y SQLAlchemy, y proporciona una API RESTful documentada con Swagger para manejar operaciones de autenticación, gestión de usuarios, proyectos, tareas, comentarios, mensajes y reuniones.

## Características

- **Autenticación**: Manejo seguro de inicio y cierre de sesión, y reseteo de contraseñas.
- **Gestión de Usuarios**: Registro, actualización y eliminación de usuarios.
- **Gestión de Proyectos**: Creación, actualización y eliminación de proyectos.
- **Gestión de Tareas**: Creación, actualización y eliminación de tareas asociadas a proyectos.
- **Gestión de Comentarios**: Creación, actualización y eliminación de comentarios en proyectos.
- **Gestión de Mensajes**: Envío y recepción de mensajes entre usuarios.
- **Gestión de Reuniones**: Creación, actualización y eliminación de reuniones.

## Tecnologías

- **Python**: Lenguaje de programación principal.
- **Flask**: Framework para desarrollar aplicaciones web.
- **Flask-RESTx**: Extensión de Flask para crear API RESTful.
- **Swagger**: Herramienta para la documentación interactiva de la API.
- **SQLAlchemy**: ORM (Object Relational Mapper) para manejar la base de datos.
- **Flask-Mail**: Extensión para enviar correos electrónicos desde la aplicación.
- **Flask-JWT-Extended**: Extensión para manejar autenticación JWT.
- **APScheduler**: Para la ejecución de tareas programadas en segundo plano.

## Instalación y Configuración

### Requisitos Previos

- Python 3.8 o superior
- PostgreSQL

### Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/iandreafh/TFG-Backend.git
   cd TFG-Backend

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt

3. Configura las variables de entorno necesarias en el archivo `config.py`


## Uso

### Documentación de la API

La documentación interactiva de la API se encuentra disponible en `http://localhost:5000/` una vez que la aplicación está en funcionamiento. 

### Endpoints Principales

#### Autenticación

- **POST /auth/login**: Iniciar sesión.
- **POST /auth/logout**: Cerrar sesión.
- **POST /auth/reset_password**: Solicitar reseteo de contraseña.

#### Usuarios

- **GET /user/usuarios**: Listar todos los usuarios (solo administradores).
- **POST /user/usuarios**: Crear un nuevo usuario.
- **GET /user/usuarios/<int:id>**: Obtener detalles de un usuario específico.
- **PUT /user/usuarios/<int:id>**: Actualizar un usuario específico.
- **DELETE /user/usuarios/<int:id>**: Eliminar un usuario específico.

#### Proyectos

- **GET /project/proyectos**: Listar todos los proyectos del usuario logueado.
- **POST /project/proyectos**: Crear un nuevo proyecto.
- **GET /project/proyectos/<int:id>**: Obtener detalles de un proyecto específico.
- **PUT /project/proyectos/<int:id>**: Actualizar un proyecto específico.
- **DELETE /project/proyectos/<int:id>**: Eliminar un proyecto específico.

#### Tareas

- **GET /project/<int:id_proyecto>/tasks**: Listar todas las tareas de un proyecto.
- **POST /project/<int:id_proyecto>/tasks**: Crear una nueva tarea en un proyecto.
- **GET /project/<int:id_proyecto>/tasks/<int:id>**: Obtener detalles de una tarea específica.
- **PUT /project/<int:id_proyecto>/tasks/<int:id>**: Actualizar una tarea específica.
- **DELETE /project/<int:id_proyecto>/tasks/<int:id>**: Eliminar una tarea específica.

#### Comentarios

- **GET /project/<int:id_proyecto>/comments**: Listar todos los comentarios de un proyecto y sus archivos adjuntos.
- **POST /project/<int:id_proyecto>/comments**: Crear un nuevo comentario en un proyecto, con opción de adjuntar archivos.
- **DELETE /project/<int:id_proyecto>/comments/<int:id>**: Eliminar un comentario específico.

#### Mensajes

- **GET /messages/chats**: Listar todos los chats del usuario logueado con el último mensaje.
- **GET /messages/chats/<int:id_usuario>**: Obtener el chat con un usuario específico.
- **POST /messages**: Enviar un mensaje a otro usuario o hacer un comunicado general si el emisor es administrador.

#### Reuniones

- **GET /meetings**: Listar todas las reuniones del usuario logueado.
- **POST /meetings**: Crear una nueva reunión.
- **DELETE /meetings/<int:id>**: Eliminar una reunión específica.
- **POST /meetings/respuesta/<int:id>**: Responder a una convocatoria de reunión.
