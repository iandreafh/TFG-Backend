# Panda Planning - TFG Backend

Este repositorio contiene el código backend del proyecto TFG para la aplicación Panda Planning, desarrollada para el proyecto final del Grado de Ingeniería Informática en Sistemas de Información de la EPS UPO.

## Descripción

Panda Planning es una aplicación diseñada para ayudar en la gestión y planificación de tareas y proyectos. Este backend está desarrollado utilizando Flask y SQLAlchemy, y proporciona una API RESTful documentada con Swagger para manejar operaciones de autenticación, gestión de usuarios, proyectos, tareas, comentarios, mensajes y reuniones.

## Características

- **Autenticación**: Manejo seguro de inicio y cierre de sesión, y reseteo de contraseñas.
- **Gestión de Usuarios**: Registro, actualización y eliminación de usuarios.
- **Gestión de Proyectos**: Creación, actualización y eliminación de proyectos.
- **Gestión de Tareas**: Creación, actualización y eliminación de tareas asociadas a proyectos.
- **Gestión de Comentarios**: Creación y listado de comentarios en proyectos, con opción de adjuntar archivos.
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
- PostgreSQL 8.2 o superior

### Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/iandreafh/TFG-Backend.git
   cd TFG-Backend

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt

3. Configura los valores necesarios en el archivo `config.py`


4. Ejecuta el proyecto:
   ```bash
   py app/app.py

## Uso

### Documentación de la API

La documentación interactiva de la API se encuentra disponible en `http://localhost:5000/` una vez que la aplicación está en funcionamiento.

### Endpoints Principales

#### Autenticación

- **POST /auth/login**: Iniciar sesión.
- **POST /auth/logout**: Cerrar sesión.
- **POST /auth/reset_password**: Solicitar reseteo de contraseña.

#### Usuarios

- **GET /usuarios**: Listar todos los usuarios (solo administradores).
- **POST /usuarios**: Crear un nuevo usuario.
- **GET /usuarios/\<int:id\>**: Obtener detalles de un usuario específico.
- **PUT /usuarios/\<int:id\>**: Actualizar un usuario específico.
- **DELETE /usuarios/\<int:id\>**: Dar de baja o eliminar un usuario específico.
- **GET /usuarios/profile**: Obtener el perfil del usuario autenticado.

#### Proyectos

- **GET /proyectos**: Listar todos los proyectos del usuario logueado o completos si es administrador.
- **POST /proyectos**: Crear un nuevo proyecto.
- **GET /proyectos/\<int:id\>**: Obtener detalles de un proyecto específico.
- **PUT /proyectos/\<int:id\>**: Actualizar un proyecto específico.
- **DELETE /proyectos/\<int:id\>**: Dar de baja o eliminar un proyecto específico.

#### Tareas

- **GET /proyectos/\<int:id_proyecto\>/tareas**: Listar todas las tareas de un proyecto.
- **POST /proyectos/\<int:id_proyecto\>/tareas**: Crear una nueva tarea en un proyecto.
- **GET /proyectos/\<int:id_proyecto\>/tareas/\<int:id\>**: Obtener detalles de una tarea específica.
- **PUT /proyectos/\<int:id_proyecto\>/tareas/\<int:id\>**: Actualizar una tarea específica.
- **DELETE /proyectos/\<int:id_proyecto\>/tareas/\<int:id\>**: Eliminar una tarea específica.

#### Comentarios

- **GET /proyectos/\<int:id_proyecto\>/comentarios**: Listar todos los comentarios de un proyecto y sus archivos adjuntos.
- **POST /proyectos/\<int:id_proyecto\>/comentarios**: Crear un nuevo comentario en un proyecto, con opción de adjuntar archivos.

#### Mensajes

- **GET /mensajes/chats**: Listar todos los chats del usuario logueado con el último mensaje.
- **GET /mensajes/chats/\<int:id_usuario\>**: Obtener el chat con un usuario específico.
- **POST /mensajes**: Enviar un mensaje a otro usuario o hacer un comunicado general si el emisor es administrador.

#### Reuniones

- **GET /reuniones**: Listar todas las reuniones del usuario logueado, pudiendo filtrar para ocultar las pasadas.
- **POST /reuniones**: Crear una nueva reunión.
- **DELETE /reuniones/\<int:id\>**: Cancelar una reunión específica.
- **POST /reuniones/respuesta/\<int:id\>**: Responder a una convocatoria de reunión.

#### Correo

- **POST /auth/send_mail_test**: Enviar un correo de prueba para comprobar la configuración y estilo.