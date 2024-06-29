-- Script SQL para generar las tablas y datos de prueba de la database PandaPlanningDB
-- Eliminar tablas si existen
DROP TABLE IF EXISTS ParticipantesReunion, MiembrosProyecto, Mensajes, Archivos, Comentarios, Tareas, Proyectos, Reuniones, Usuarios CASCADE;

-- Crear tabla Usuarios
CREATE TABLE Usuarios (
    ID serial PRIMARY KEY,
    Email varchar(255) UNIQUE NOT NULL,
    Password varchar(255) NOT NULL,
    Nombre varchar(255) NOT NULL,
    Foto varchar(255),
    Alertas boolean NOT NULL,
    Rol varchar(50) NOT NULL,
    Check_Activo boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL
);

-- Crear tabla Proyectos
-- Si se borra un proyecto, se borran sus tareas, miembros, comentarios y archivos adjuntos
CREATE TABLE Proyectos (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(150),
    Check_Activo boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDCreador integer NOT NULL,
    FOREIGN KEY (IDCreador) REFERENCES Usuarios(ID)
);

-- Crear tabla MiembrosProyecto
CREATE TABLE MiembrosProyecto (
    ID serial PRIMARY KEY,
    IDUsuario integer NOT NULL,
    IDProyecto integer NOT NULL,
    Permisos varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID),
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE
);

-- Crear tabla Tareas
CREATE TABLE Tareas (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    FechaInicio date,
    FechaFin date,
    Prioridad integer NOT NULL,
    Estado varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDUsuario integer,
    IDProyecto integer,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID),
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE
);

-- Crear tabla Comentarios
CREATE TABLE Comentarios (
    ID serial PRIMARY KEY,
    Contenido varchar(255),
    Created_at timestamp NOT NULL,
    IDProyecto integer NOT NULL,
    IDUsuario integer NOT NULL,
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID)
);

-- Crear tabla Archivos
CREATE TABLE Archivos (
    ID serial PRIMARY KEY,
    Nombre varchar(255),
    Ruta varchar(255) NOT NULL,
    IDComentario integer,
    FOREIGN KEY (IDComentario) REFERENCES Comentarios(ID) ON DELETE CASCADE
);

-- Crear tabla Mensajes
CREATE TABLE Mensajes (
    ID serial PRIMARY KEY,
    Asunto varchar(50) NOT NULL,
    Contenido text NOT NULL,
    Check_Leido boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDEmisor integer NOT NULL,
    IDReceptor integer NOT NULL,
    FOREIGN KEY (IDEmisor) REFERENCES Usuarios(ID),
    FOREIGN KEY (IDReceptor) REFERENCES Usuarios(ID)
);

-- Crear tabla Reuniones
CREATE TABLE Reuniones (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    FechaHora timestamp NOT NULL,
    Duracion integer NOT NULL,
    Modalidad varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    IDCreador integer NOT NULL,
    FOREIGN KEY (IDCreador) REFERENCES Usuarios(ID)
);

-- Crear tabla ParticipantesReunion
CREATE TABLE ParticipantesReunion (
    ID serial PRIMARY KEY,
    IDReunion integer NOT NULL,
    IDUsuario integer NOT NULL,
    Respuesta varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    FOREIGN KEY (IDReunion) REFERENCES Reuniones(ID),
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID)
);




-- Insertar datos de prueba en las tablas
-- Usuarios
-- Passwords: admin, user, andrea y pablo
INSERT INTO Usuarios (Email, Password, Nombre, Alertas, Rol, Check_Activo, Created_at, Updated_at) VALUES
('admin@gmail.com', '$2b$12$Kt8r5Epc.xr4hiStgwwS2.8VwD/ZoN7VoDWoDMhT.SAtLv6aueB/y', 'Administrador', False, 'admin', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('user@gmail.com', '$2b$12$bsWlAoOB9StSouDLhZFdmOYavpdI4IDw0PPxt93vrcR4ScZtt6dfi', 'User de prueba', False, 'user', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('iandreafh@gmail.com', '$2b$12$l1GN7N05KK2I9M8iqnYndOYf4rM64eaObgbTG4hI8h0ZmAR.K0JSy', 'Andrea Fernández', True, 'user', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('pablo@gmail.com', '$2b$12$l1GN7N05KK2I9M8iqnYndOYf4rM64eaObgbTG4hI8h0ZmAR.K0JSy', 'Pablo Casas', False, 'user', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Proyectos
-- IDCreador se declara siempre como gestor en miembros del proyecto
INSERT INTO Proyectos (Titulo, Descripcion, Check_Activo, Created_at, Updated_at, IDCreador) VALUES
('Proyecto Alpha', 'Descripción del Proyecto Alpha', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3),
('Proyecto Beta', 'Descripción del Proyecto Beta', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4),
('Proyecto Gamma', 'Descripción del Proyecto Gamma', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3);

-- MiembrosProyecto
INSERT INTO MiembrosProyecto (IDUsuario, IDProyecto, Permisos, Created_at, Updated_at) VALUES
(3, 1, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(4, 2, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(3, 3, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(4, 3, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Tareas
-- Prioridades posibles: 0 (Baja), 1 (Media), 2 (Alta)
-- Estados posibles: To do, In progress, Blocked, Done
INSERT INTO Tareas (Titulo, Descripcion, FechaInicio, FechaFin, Prioridad, Estado, Created_at, Updated_at, IDUsuario, IDProyecto) VALUES
('Tarea 1 de Alpha', 'Descripción de la tarea 1 del Proyecto Alpha', '2024-05-01', '2024-05-20', 1, 'In progress', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 1),
('Tarea 2 de Alpha', 'Descripción de la tarea 2 del Proyecto Alpha', '2024-05-10', '2024-05-25', 0, 'To do', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 1),
('Tarea 1 de Beta', 'Descripción de la tarea 1 del Proyecto Beta', '2024-05-07', '2024-05-25', 2, 'To do', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4, 2),
('Tarea 2 de Beta', 'Descripción de la tarea 2 del Proyecto Beta', '2024-06-01', '2024-06-30', 1, 'In progress', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4, 2),
('Tarea 1 de Gamma', 'Descripción de la tarea 1 del Proyecto Gamma', '2024-06-01', '2024-06-15', 2, 'Blocked', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 3),
('Tarea 2 de Gamma', 'Descripción de la tarea 2 del Proyecto Gamma', '2024-06-10', '2024-06-20', 0, 'Done', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 3),
('Tarea 3 de Gamma', 'Descripción de la tarea 3 del Proyecto Gamma', '2024-06-15', '2024-06-25', 1, 'In progress', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 3),
('Tarea 4 de Gamma', 'Descripción de la tarea 4 del Proyecto Gamma', '2024-06-20', '2024-06-30', 2, 'To do', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4, 3),
('Tarea 5 de Gamma', 'Descripción de la tarea 5 del Proyecto Gamma', '2024-06-25', '2024-07-05', 1, 'Done', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4, 3);

-- Comentarios
INSERT INTO Comentarios (Contenido, Created_at, IDProyecto, IDUsuario) VALUES
('Comentario de Andrea en Proyecto Alpha', CURRENT_TIMESTAMP, 1, 3),
('Comentario de Pablo en Proyecto Beta', CURRENT_TIMESTAMP, 2, 4),
('Comentario de Andrea en Proyecto Gamma', CURRENT_TIMESTAMP, 3, 3),
('Comentario de Pablo en Proyecto Gamma', CURRENT_TIMESTAMP, 3, 4),
('Comentario adicional de Andrea en Proyecto Gamma', CURRENT_TIMESTAMP, 3, 3);

-- Archivos
INSERT INTO Archivos (Nombre, Ruta, IDComentario) VALUES
('Archivo de Proyecto Alpha', '/files/file1.pdf', 1),
('Archivo de Proyecto Beta', '/files/file2.pdf', 2),
('Archivo de Proyecto Gamma', '/files/file3.pdf', 3),
('Archivo adicional de Proyecto Gamma', '/files/file4.pdf', 5);

-- Mensajes
INSERT INTO Mensajes (Asunto, Contenido, Check_Leido, Created_at, Updated_at, IDEmisor, IDReceptor) VALUES
('Bienvenida', '¡Bienvenido al equipo!', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 2),
('Recordatorio', 'Hola, quería recordarte la reunión de mañana. ¡Nos vemos pronto!', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 4),
('Intercambio de Andrea y Pablo', 'Mensaje de Andrea a Pablo', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 3, 4),
('Intercambio de Pablo y Andrea', 'Mensaje de Pablo a Andrea', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 4, 3),
('Comunicado General', 'Este es un comunicado general para todos los usuarios.', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 2),
('Comunicado General', 'Este es un comunicado general para todos los usuarios.', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 3),
('Comunicado General', 'Este es un comunicado general para todos los usuarios.', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 4);

-- Reuniones
INSERT INTO Reuniones (Titulo, Descripcion, FechaHora, Duracion, Modalidad, Created_at, IDCreador) VALUES
('Reunión de Seguimiento 1', 'Primera reunión de seguimiento del proyecto', '2024-06-01 10:00:00', 60, 'Virtual', CURRENT_TIMESTAMP, 3),
('Reunión de Seguimiento 2', 'Segunda reunión de seguimiento del proyecto', '2024-06-15 11:00:00', 30, 'Presencial', CURRENT_TIMESTAMP, 3);

-- ParticipantesReunion
-- Respuestas posibles: PENDIENTE, ACEPTADA, RECHAZADA
INSERT INTO ParticipantesReunion (IDReunion, IDUsuario, Respuesta, Created_at, Updated_at) VALUES
(1, 3, 'ACEPTADA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(1, 4, 'ACEPTADA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 3, 'ACEPTADA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 4, 'ACEPTADA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
