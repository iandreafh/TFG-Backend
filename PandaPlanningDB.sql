-- Script SQL para generar las tablas y datos de prueba de la database PandaPlanningDB
-- Eliminar tablas si existen
DROP TABLE IF EXISTS ParticipantesReunion, MiembrosProyecto, Mensajes, Archivos, Comentarios, Tareas, Proyectos, Reuniones, Usuarios CASCADE;

-- Crear tabla Usuarios
CREATE TABLE Usuarios (
    ID serial PRIMARY KEY,
    Email varchar(255) UNIQUE NOT NULL,
    Password varchar(255) NOT NULL,
    Nombre varchar(255) NOT NULL,
    Edad integer NOT NULL,
    Rol varchar(50) NOT NULL,
    Check_Activo boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL
);

-- Crear tabla Proyectos
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
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID)
);

-- Crear tabla Tareas
CREATE TABLE Tareas (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    FechaInicio date,
    FechaFin date,
    Estado varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDUsuario integer,
    IDProyecto integer,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID),
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID)
);

-- Crear tabla Comentarios
CREATE TABLE Comentarios (
    ID serial PRIMARY KEY,
    Contenido varchar(255),
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDProyecto integer NOT NULL,
    IDUsuario integer NOT NULL,
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID),
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID)
);

-- Crear tabla Archivos
CREATE TABLE Archivos (
    ID serial PRIMARY KEY,
    Nombre varchar(255),
    Ruta varchar(255) NOT NULL,
    IDComentario integer,
    FOREIGN KEY (IDComentario) REFERENCES Comentarios(ID)
);

-- Crear tabla Reuniones
CREATE TABLE Reuniones (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    FechaHora timestamp NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL
);

-- Crear tabla ParticipantesReunion
CREATE TABLE ParticipantesReunion (
    ID serial PRIMARY KEY,
    IDReunion integer NOT NULL,
    IDUsuario integer NOT NULL,
    Aceptada varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    FOREIGN KEY (IDReunion) REFERENCES Reuniones(ID),
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID)
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


-- Insertar datos de prueba en las tablas
-- Usuarios
INSERT INTO Usuarios (Email, Password, Nombre, Edad, Rol, Check_Activo, Created_at, Updated_at) VALUES
('admin@gmail.com', '$2b$12$Kt8r5Epc.xr4hiStgwwS2.8VwD/ZoN7VoDWoDMhT.SAtLv6aueB/y', 'Administrador', 30, 'admin', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('user@gmail.com', '$2b$12$bsWlAoOB9StSouDLhZFdmOYavpdI4IDw0PPxt93vrcR4ScZtt6dfi', 'User de prueba', 25, 'user', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Proyectos
INSERT INTO Proyectos (Titulo, Descripcion, Check_Activo, Created_at, Updated_at, IDCreador) VALUES
('Project Alpha', 'Description of Project Alpha', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1),
('Project Beta', 'Description of Project Beta', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 2);

-- Tareas
INSERT INTO Tareas (Titulo, Descripcion, FechaInicio, FechaFin, Estado, Created_at, Updated_at, IDUsuario, IDProyecto) VALUES
('Task 1', 'Description of Task 1', '2024-05-01', '2024-05-20', 'In progress', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 1),
('Task 2', 'Description of Task 2', '2024-05-07', '2024-05-25', 'To do', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 2, 2);

-- Reuniones
INSERT INTO Reuniones (Titulo, Descripcion, FechaHora, Created_at, Updated_at) VALUES
('Meeting 1', 'Discussion on project', '2024-05-08 10:00:00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('Meeting 2', 'Review of the project', '2024-05-15 11:00:00', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- ParticipantesReunion
INSERT INTO ParticipantesReunion (IDReunion, IDUsuario, Aceptada, Created_at, Updated_at) VALUES
(1, 1, 'ACEPTADA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(1, 2, 'PENDIENTE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- MiembrosProyecto
INSERT INTO MiembrosProyecto (IDUsuario, IDProyecto, Permisos, Created_at, Updated_at) VALUES
(1, 1, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(1, 2, 'gestor', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 2, 'lector', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Mensajes
INSERT INTO Mensajes (Asunto, Contenido, Check_Leido, Created_at, Updated_at, IDEmisor, IDReceptor) VALUES
('Welcome', 'Welcome to the team!', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 2),
('Reminder', 'Hey, I wanted to remind you of the meeting tomorrow. See you soon!', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 2, 1);

-- Comentarios
INSERT INTO Comentarios (Contenido, Created_at, Updated_at, IDProyecto, IDUsuario) VALUES
('Os subo las 2 versiones para ver qué portada os gusta más.', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, 1),
('Needs some changes. I can upload the new version with the corrections tomorrow.', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 2, 2);

-- Archivos
INSERT INTO Archivos (Nombre, Ruta, IDComentario) VALUES
('Plan de proyecto', '/files/file1.pdf', 1),
('PP', '/files/file2.pdf', 1);