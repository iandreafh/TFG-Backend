-- Script SQL para generar las tablas y datos de prueba de la database PandaPlanning en PostgreSQL
-- Eliminar tablas si existen
DROP TABLE IF EXISTS ParticipantesReunion, MiembrosProyecto, Mensajes, Archivos, Comentarios, Tareas, Proyectos, Reuniones, Usuarios CASCADE;

-- 1. Crear tabla Usuarios
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

-- 2. Crear tabla Proyectos
-- Si se borra un proyecto, se borran sus tareas, miembros, comentarios y archivos adjuntos
CREATE TABLE Proyectos (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    Check_Activo boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDCreador integer NOT NULL,
    FOREIGN KEY (IDCreador) REFERENCES Usuarios(ID) ON DELETE CASCADE
);

-- 3. Crear tabla MiembrosProyecto
CREATE TABLE MiembrosProyecto (
    ID serial PRIMARY KEY,
    IDUsuario integer NOT NULL,
    IDProyecto integer NOT NULL,
    Permisos varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE
);

-- 4. Crear tabla Tareas
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
    IDProyecto integer NOT NULL,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE
);

-- 5. Crear tabla Comentarios
CREATE TABLE Comentarios (
    ID serial PRIMARY KEY,
    Contenido varchar(255),
    Created_at timestamp NOT NULL,
    IDProyecto integer NOT NULL,
    IDUsuario integer NOT NULL,
    FOREIGN KEY (IDProyecto) REFERENCES Proyectos(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID) ON DELETE CASCADE
);

-- 6. Crear tabla Archivos
CREATE TABLE Archivos (
    ID serial PRIMARY KEY,
    Nombre varchar(255),
    Ruta varchar(255) NOT NULL,
    IDComentario integer,
    FOREIGN KEY (IDComentario) REFERENCES Comentarios(ID) ON DELETE CASCADE
);

-- 7. Crear tabla Mensajes
CREATE TABLE Mensajes (
    ID serial PRIMARY KEY,
    Asunto varchar(50) NOT NULL,
    Contenido text NOT NULL,
    Check_Leido boolean NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    IDEmisor integer NOT NULL,
    IDReceptor integer NOT NULL,
    FOREIGN KEY (IDEmisor) REFERENCES Usuarios(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDReceptor) REFERENCES Usuarios(ID) ON DELETE CASCADE
);

-- 8. Crear tabla Reuniones
CREATE TABLE Reuniones (
    ID serial PRIMARY KEY,
    Titulo varchar(50) NOT NULL,
    Descripcion varchar(255),
    FechaHora timestamp NOT NULL,
    Duracion integer NOT NULL,
    Modalidad varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    IDCreador integer NOT NULL,
    FOREIGN KEY (IDCreador) REFERENCES Usuarios(ID) ON DELETE CASCADE
);

-- 9. Crear tabla ParticipantesReunion
CREATE TABLE ParticipantesReunion (
    ID serial PRIMARY KEY,
    IDReunion integer NOT NULL,
    IDUsuario integer NOT NULL,
    Respuesta varchar(50) NOT NULL,
    Created_at timestamp NOT NULL,
    Updated_at timestamp NOT NULL,
    FOREIGN KEY (IDReunion) REFERENCES Reuniones(ID) ON DELETE CASCADE,
    FOREIGN KEY (IDUsuario) REFERENCES Usuarios(ID) ON DELETE CASCADE
);

-- 10. INSERTS

-- Insertar datos en Usuarios
-- Passwords igual al correo
INSERT INTO Usuarios (Email, Password, Nombre, Foto, Alertas, Rol, Check_Activo, Created_at, Updated_at) VALUES
('pandaplanningweb@gmail.com', '$2b$12$plzOP.T3EbONdfiPoa3sT.1FU9YEcZXP9sErQ8jLq7BtLUSrlnNy2', 'Panda Planning', 'Panda_grande_azul.png', False, 'admin', TRUE, '2023-10-01 10:00:00', '2023-10-01 10:00:00'),
('admin@gmail.com', '$2b$12$plzOP.T3EbONdfiPoa3sT.1FU9YEcZXP9sErQ8jLq7BtLUSrlnNy2', 'Administrador', 'profile6.png', False, 'admin', TRUE, '2023-10-01 10:00:00', '2023-10-01 10:00:00'),
('user@gmail.com', '$2b$12$cOoywC1aqo4AC7le/M7P0ezjjdh.d3rxYareEyEpYO/1u45Xynntu', 'User de prueba', 'profile3.png', False, 'user', TRUE, '2023-11-15 09:30:00', '2024-01-20 14:00:00'),
('iandreafh@gmail.com', '$2b$12$M6wIiTnMv.hrEWe2OGctkOxDTJkJRus43H6CIJCWHMNxSkDIr01LK', 'Andrea Fernández', 'profile1.png', True, 'user', TRUE, '2024-02-10 08:00:00', '2024-05-05 16:00:00'),
('pablo@gmail.com', '$2b$12$njrlC7Ck1cBnQdmWTOVhy.utwYKkTRsUEphMyTgbO8FzksUCkojRS', 'Pablo Casas', 'profile4.png', True, 'user', TRUE, '2023-12-20 11:00:00', '2023-12-20 11:00:00'),
('maria@gmail.com', '$2b$12$HmK3fBzX7rqSpI2ksdG3deZLGp/XsDa9ZkVbHeBxIa.fYVNaBhC3m', 'María Varo', 'profile2.png', False, 'user', TRUE, '2024-01-05 10:00:00', '2024-04-15 12:00:00'),
('fran@gmail.com', '$2b$12$xxGJYmGhUJCU778pqJa50ubDTbVWDqjWPP/yoq.h3vUXkFDeJddkC', 'Francesc Rodríguez', 'profile7.png', False, 'user', TRUE, '2024-03-01 09:00:00', '2024-03-01 09:00:00'),
('carlos@gmail.com', '$2b$12$tfx19ip5QPvw20nwBGwrnO78Oap.HiBB9pkp.53G54UAae6RC.CDa', 'Carlos Bedmar', 'profile5.png', False, 'user', TRUE, '2024-04-10 14:00:00', '2024-07-20 18:00:00'),
('jorge@gmail.com', '$2b$12$plzOP.T3EbONdfiPoa3sT.1FU9YEcZXP9sErQ8jLq7BtLUSrlnNy2', 'Jorge Martínez', 'profile5.png', False, 'user', TRUE, '2024-05-15 13:00:00', '2024-05-15 13:00:00'),
('laura@gmail.com', '$2b$12$cOoywC1aqo4AC7le/M7P0ezjjdh.d3rxYareEyEpYO/1u45Xynntu', 'Laura López', 'profile3.png', False, 'user', TRUE, '2024-06-20 15:00:00', '2024-08-12 17:00:00'),
('marta@gmail.com', '$2b$12$M6wIiTnMv.hrEWe2OGctkOxDTJkJRus43H6CIJCWHMNxSkDIr01LK', 'Marta García', 'profile2.png', False, 'user', TRUE, '2024-07-05 16:00:00', '2024-07-05 16:00:00'),
('ana@gmail.com', '$2b$12$abc123abc123abc123abc123abc123abc123abc123abc123abc123', 'Ana Pérez', 'profile1.png', False, 'user', FALSE, '2023-05-10 10:00:00', '2023-05-10 10:00:00'),
('luis@gmail.com', '$2b$12$def456def456def456def456def456def456def456def456def456', 'Luis Gómez', 'profile6.png', False, 'user', FALSE, '2023-06-15 11:00:00', '2023-06-15 11:00:00'),
('sara@gmail.com', '$2b$12$ghi789ghi789ghi789ghi789ghi789ghi789ghi789ghi789ghi789', 'Sara López', 'profile3.png', False, 'user', FALSE, '2023-07-20 12:00:00', '2023-07-20 12:00:00'),
('david@gmail.com', '$2b$12$jkl012jkl012jkl012jkl012jkl012jkl012jkl012jkl012jkl012', 'David Martín', 'profile5.png', False, 'user', TRUE, '2024-02-25 13:00:00', '2024-05-30 14:00:00'),
('lucia@gmail.com', '$2b$12$mno345mno345mno345mno345mno345mno345mno345mno345mno345', 'Lucía Fernández', 'profile1.png', False, 'user', TRUE, '2024-03-10 14:00:00', '2024-06-15 15:00:00'),
('pepe@gmail.com', '$2b$12$pOe/oroeWQzhv8gaUP8T6ObekLmJ6RL8H/.nVfaZkpzTT9XfVt5hy', 'José Francisco Torres', 'profile6.png', TRUE, 'user', TRUE, '2024-03-10 14:00:00', '2024-06-15 15:00:00');

-- Insertar datos en Proyectos
INSERT INTO Proyectos (Titulo, Descripcion, Check_Activo, Created_at, Updated_at, IDCreador) VALUES
-- Proyecto Alpha - Creado hace 10 semanas, actualizado hace 8 semanas
('Proyecto Alpha', 'Descripción del Proyecto Alpha', TRUE, '2024-05-20 10:00:00', '2024-06-03 14:00:00', 4),  -- ID 1, Creador: Andrea
-- Proyecto Beta - Creado hace 6 semanas, actualizado hace 5 semanas
('Proyecto Beta', 'Descripción del Proyecto Beta', TRUE, '2024-06-20 09:30:00', '2024-06-27 11:00:00', 5),   -- ID 2, Creador: Pablo
-- Proyecto Gamma - Creado hace 4 semanas, no actualizado
('Proyecto Gamma', 'Descripción del Proyecto Gamma', TRUE, '2024-07-05 12:00:00', '2024-07-05 12:00:00', 4),  -- ID 3, Creador: Andrea
-- Proyecto Delta - Creado hace 2 semanas, actualizado hace 1 semana
('Proyecto Delta', 'Descripción del Proyecto Delta', TRUE, '2024-07-25 15:00:00', '2024-08-01 09:00:00', 2),  -- ID 4, Creador: Administrador
-- Proyecto Epsilon - Creado hace 3 días, no actualizado
('Proyecto Epsilon', 'Descripción del Proyecto Epsilon', TRUE, '2024-08-05 08:45:00', '2024-08-05 08:45:00', 3),  -- ID 5, Creador: User
-- Proyecto Zeta - Creado hace 1 semana, actualizado hace 5 días
('Proyecto Zeta', 'Descripción del Proyecto Zeta', FALSE, '2024-07-30 10:30:00', '2024-08-02 12:00:00', 3),  -- ID 6, Creador: User
-- Proyecto Kappa - Creado hace 4 días, no actualizado
('Proyecto Kappa', 'Descripción del Proyecto Kappa', FALSE, '2024-08-04 11:15:00', '2024-08-04 11:15:00', 3), -- ID 7, Creador: User
-- Proyecto Theta - Creado hace 8 semanas, actualizado hace 6 semanas, inactivo, con varias tareas y comentarios
('Proyecto Theta', 'Descripción del Proyecto Theta, un proyecto inactivo.', FALSE, '2024-05-15 09:00:00', '2024-06-01 11:00:00', 2), -- ID 8, Creador: Admin
-- Proyecto "Sistemas Distribuidos"
('Sistemas Distribuidos', 'Proyecto para la asignatura de Sistemas Distribuidos. Incluye tareas de ejercicios, EPDs y preparación para exámenes.', TRUE, '2024-09-01 09:00:00', '2024-10-21 14:00:00', 5),
-- Proyecto "TFG"
('TFG', 'Proyecto final de grado para el desarrollo de una aplicación web.', TRUE, '2023-10-01 10:00:00', '2024-08-15 10:00:00', 4); -- ID 10, Creador: Andrea


-- Insertar datos en MiembrosProyecto
INSERT INTO MiembrosProyecto (IDUsuario, IDProyecto, Permisos, Created_at, Updated_at) VALUES
-- Proyecto Alpha (ID 1)
(4, 1, 'gestor', '2024-05-20 10:10:00', '2024-05-20 10:10:00'), -- Andrea (Creador)
(5, 1, 'gestor', '2024-05-21 09:00:00', '2024-05-21 09:00:00'), -- Pablo
(7, 1, 'editor', '2024-05-21 09:30:00', '2024-05-21 09:30:00'), -- Francesc
(8, 1, 'editor', '2024-05-22 11:00:00', '2024-05-22 11:00:00'), -- Carlos
(6, 1, 'editor', '2024-05-23 14:00:00', '2024-05-23 14:00:00'), -- María
(3, 1, 'lector', '2024-05-24 10:00:00', '2024-05-24 10:00:00'), -- User
(2, 1, 'lector', '2024-05-25 15:00:00', '2024-05-25 15:00:00'), -- Admin

-- Proyecto Beta (ID 2)
(5, 2, 'gestor', '2024-06-20 10:00:00', '2024-06-20 10:00:00'), -- Pablo (Creador)
(4, 2, 'gestor', '2024-06-21 09:00:00', '2024-06-21 09:00:00'), -- Andrea
(7, 2, 'editor', '2024-06-22 12:00:00', '2024-06-22 12:00:00'), -- Francesc
(8, 2, 'editor', '2024-06-23 10:30:00', '2024-06-23 10:30:00'), -- Carlos
(6, 2, 'editor', '2024-06-24 11:00:00', '2024-06-24 11:00:00'), -- María

-- Proyecto Gamma (ID 3)
(4, 3, 'gestor', '2024-07-05 12:30:00', '2024-07-05 12:30:00'), -- Andrea (Creador)
(5, 3, 'gestor', '2024-07-06 09:00:00', '2024-07-06 09:00:00'), -- Pablo
(7, 3, 'editor', '2024-07-07 11:00:00', '2024-07-07 11:00:00'), -- Francesc
(8, 3, 'editor', '2024-07-08 14:00:00', '2024-07-08 14:00:00'), -- Carlos
(6, 3, 'editor', '2024-07-09 10:30:00', '2024-07-09 10:30:00'), -- María

-- Proyecto Delta (ID 4)
(2, 4, 'gestor', '2024-07-25 15:30:00', '2024-07-25 15:30:00'), -- Admin (Creador)
(3, 4, 'gestor', '2024-07-26 11:00:00', '2024-07-26 11:00:00'), -- User
(4, 4, 'gestor', '2024-07-27 09:00:00', '2024-07-27 09:00:00'), -- Andrea
(5, 4, 'gestor', '2024-07-28 14:00:00', '2024-07-28 14:00:00'), -- Pablo
(6, 4, 'gestor', '2024-07-29 10:30:00', '2024-07-29 10:30:00'), -- María
(7, 4, 'gestor', '2024-07-30 12:00:00', '2024-07-30 12:00:00'), -- Francesc

-- Proyecto Epsilon (ID 5)
(3, 5, 'gestor', '2024-08-05 09:00:00', '2024-08-05 09:00:00'), -- User (Creador)
(4, 5, 'gestor', '2024-08-05 10:00:00', '2024-08-05 10:00:00'), -- Andrea
(5, 5, 'gestor', '2024-08-05 11:00:00', '2024-08-05 11:00:00'), -- Pablo
(6, 5, 'editor', '2024-08-05 12:00:00', '2024-08-05 12:00:00'), -- María

-- Proyecto Zeta (ID 6)
(2, 6, 'gestor', '2024-07-30 11:00:00', '2024-07-30 11:00:00'), -- Admin
(3, 6, 'gestor', '2024-07-30 11:15:00', '2024-07-30 11:15:00'), -- User (Creador)
(7, 6, 'editor', '2024-07-31 09:00:00', '2024-07-31 09:00:00'), -- Francesc
(8, 6, 'editor', '2024-08-01 10:30:00', '2024-08-01 10:30:00'), -- Carlos

-- Proyecto Kappa (ID 7)
(3, 7, 'gestor', '2024-08-04 11:30:00', '2024-08-04 11:30:00'), -- User (Creador)

-- Proyecto Theta (ID 8)
(2, 8, 'gestor', '2024-05-15 09:30:00', '2024-05-15 09:30:00'), -- Admin (Creador)
(3, 8, 'editor', '2024-05-16 10:00:00', '2024-05-16 10:00:00'), -- User
(4, 8, 'editor', '2024-05-17 11:30:00', '2024-05-17 11:30:00'), -- Andrea
(5, 8, 'editor', '2024-05-18 13:00:00', '2024-05-18 13:00:00'), -- Pablo

-- Proyecto "Sistemas Distribuidos" (ID 9)
(5, 9, 'gestor', '2024-02-01 09:15:00', '2024-02-01 09:15:00'), -- Pablo
(4, 9, 'editor', '2024-02-01 09:30:00', '2024-02-01 09:30:00'), -- Andrea
(6, 9, 'editor', '2024-02-01 09:45:00', '2024-02-01 09:45:00'), -- María
(7, 9, 'editor', '2024-02-01 10:00:00', '2024-02-01 10:00:00'), -- Fran
(8, 9, 'editor', '2024-02-01 10:15:00', '2024-02-01 10:15:00'), -- Carlos
(17, 9, 'lector', '2024-02-01 10:15:00', '2024-02-01 10:15:00'), -- Pepe

-- Proyecto "TFG" (ID 10)
(4, 10, 'gestor', '2023-10-01 11:30:00', '2024-08-15 10:15:00'); -- Andrea


-- Insertar datos en Tareas
INSERT INTO Tareas (Titulo, Descripcion, FechaInicio, FechaFin, Prioridad, Estado, Created_at, Updated_at, IDUsuario, IDProyecto) VALUES
-- Proyecto Alpha (ID 1)
('Tarea 1 de Alpha', 'Descripción de la tarea 1 del Proyecto Alpha', '2024-05-01', '2024-05-20', 2, 'In progress', '2024-05-21 12:00:00', '2024-05-21 12:00:00', 4, 1),
('Tarea 2 de Alpha', 'Descripción de la tarea 2 del Proyecto Alpha', '2024-05-10', '2024-05-25', 1, 'To do', '2024-05-22 09:00:00', '2024-05-22 09:00:00', 5, 1),
('Tarea 3 de Alpha', 'Descripción de la tarea 3 del Proyecto Alpha', NULL, NULL, 3, 'Blocked', '2024-05-23 10:00:00', '2024-05-23 10:00:00', NULL, 1),
('Tarea 4 de Alpha', 'Descripción de la tarea 4 del Proyecto Alpha', '2024-05-20', '2024-06-05', 2, 'Done', '2024-05-24 08:00:00', '2024-06-06 14:00:00', 6, 1),
('Tarea 5 de Alpha', 'Descripción de la tarea 5 del Proyecto Alpha', '2024-05-25', NULL, 1, 'To do', '2024-05-25 11:00:00', '2024-05-25 11:00:00', 7, 1),
('Tarea 6 de Alpha', 'Descripción de la tarea 6 del Proyecto Alpha', NULL, '2024-06-15', 2, 'In progress', '2024-05-30 12:00:00', '2024-05-30 12:00:00', 8, 1),
('Tarea 7 de Alpha', 'Descripción de la tarea 7 del Proyecto Alpha', '2024-06-05', '2024-06-20', 3, 'To do', '2024-06-01 09:00:00', '2024-06-01 09:00:00', 4, 1),

-- Proyecto Beta (ID 2)
('Tarea 1 de Beta', 'Descripción de la tarea 1 del Proyecto Beta', '2024-05-07', '2024-05-25', 3, 'To do', '2024-06-22 10:00:00', '2024-06-22 10:00:00', 5, 2),
('Tarea 2 de Beta', 'Descripción de la tarea 2 del Proyecto Beta', '2024-06-01', '2024-06-30', 2, 'In progress', '2024-06-23 08:00:00', '2024-06-23 08:00:00', 7, 2),
('Tarea 3 de Beta', 'Descripción de la tarea 3 del Proyecto Beta', NULL, NULL, 2, 'Blocked', '2024-06-24 11:00:00', '2024-06-24 11:00:00', NULL, 2),
('Tarea 4 de Beta', 'Descripción de la tarea 4 del Proyecto Beta', '2024-06-10', '2024-06-25', 3, 'Done', '2024-06-25 15:00:00', '2024-06-25 15:00:00', 8, 2),
('Tarea 5 de Beta', 'Descripción de la tarea 5 del Proyecto Beta', '2024-06-15', NULL, 1, 'To do', '2024-06-26 09:00:00', '2024-06-26 09:00:00', 5, 2),
('Tarea 6 de Beta', 'Descripción de la tarea 6 del Proyecto Beta', '2024-06-20', '2024-07-05', 2, 'In progress', '2024-06-27 08:00:00', '2024-06-27 08:00:00', 7, 2),
('Tarea 7 de Beta', 'Descripción de la tarea 7 del Proyecto Beta', NULL, '2024-07-10', 3, 'To do', '2024-06-28 12:00:00', '2024-06-28 12:00:00', 8, 2),

-- Proyecto Gamma (ID 3)
('Tarea 1 de Gamma', 'Descripción de la tarea 1 del Proyecto Gamma', '2024-06-01', '2024-06-15', 3, 'Blocked', '2024-07-07 10:00:00', '2024-07-07 10:00:00', 4, 3),
('Tarea 2 de Gamma', 'Descripción de la tarea 2 del Proyecto Gamma', NULL, '2024-06-20', 1, 'Done', '2024-07-08 12:00:00', '2024-07-08 12:00:00', 5, 3),
('Tarea 3 de Gamma', 'Descripción de la tarea 3 del Proyecto Gamma', '2024-06-15', '2024-06-25', 2, 'In progress', '2024-07-09 14:00:00', '2024-07-09 14:00:00', 7, 3),
('Tarea 4 de Gamma', 'Descripción de la tarea 4 del Proyecto Gamma', '2024-06-20', '2024-06-30', 2, 'To do', '2024-07-10 10:00:00', '2024-07-10 10:00:00', NULL, 3),
('Tarea 5 de Gamma', 'Descripción de la tarea 5 del Proyecto Gamma', '2024-06-25', NULL, 2, 'Done', '2024-07-11 11:00:00', '2024-07-11 11:00:00', 8, 3),
('Tarea 6 de Gamma', 'Descripción de la tarea 6 del Proyecto Gamma', NULL, '2024-07-15', 2, 'Blocked', '2024-07-12 09:00:00', '2024-07-12 09:00:00', 4, 3),
('Tarea 7 de Gamma', 'Descripción de la tarea 7 del Proyecto Gamma', '2024-07-05', '2024-07-20', 3, 'Done', '2024-07-13 08:00:00', '2024-07-13 08:00:00', 5, 3),

-- Proyecto Delta (ID 4)
('Tarea 1 de Delta', 'Descripción de la tarea 1 del Proyecto Delta', '2024-08-01', '2024-08-15', 2, 'To do', '2024-07-26 10:00:00', '2024-07-26 10:00:00', 2, 4),
('Tarea 2 de Delta', 'Descripción de la tarea 2 del Proyecto Delta', NULL, NULL, 3, 'In progress', '2024-07-27 09:00:00', '2024-07-27 09:00:00', 3, 4),
('Tarea 3 de Delta', 'Descripción de la tarea 3 del Proyecto Delta', '2024-08-10', '2024-08-25', 1, 'Blocked', '2024-07-28 11:00:00', '2024-07-28 11:00:00', NULL, 4),
('Tarea 4 de Delta', 'Descripción de la tarea 4 del Proyecto Delta', '2024-08-15', '2024-08-30', 2, 'Done', '2024-07-29 14:00:00', '2024-07-29 14:00:00', 4, 4),
('Tarea 5 de Delta', 'Descripción de la tarea 5 del Proyecto Delta', NULL, '2024-08-05', 3, 'To do', '2024-07-30 16:00:00', '2024-07-30 16:00:00', 5, 4),
('Tarea 6 de Delta', 'Descripción de la tarea 6 del Proyecto Delta', '2024-08-25', '2024-08-10', 1, 'In progress', '2024-07-31 12:00:00', '2024-07-31 12:00:00', 7, 4),
('Tarea 7 de Delta', 'Descripción de la tarea 7 del Proyecto Delta', NULL, NULL, 2, 'Blocked', '2024-08-01 09:00:00', '2024-08-01 09:00:00', 8, 4),

-- Proyecto Epsilon (ID 5)
('Tarea 1 de Epsilon', 'Descripción de la tarea 1 del Proyecto Epsilon', '2024-08-01', '2024-08-15', 1, 'To do', '2024-08-05 09:00:00', '2024-08-05 09:00:00', 3, 5),  -- User asignado
('Tarea 2 de Epsilon', 'Descripción de la tarea 2 del Proyecto Epsilon', NULL, '2024-08-20', 3, 'In progress', '2024-08-05 10:00:00', '2024-08-05 10:00:00', 3, 5),
('Tarea 3 de Epsilon', 'Descripción de la tarea 3 del Proyecto Epsilon', '2024-08-10', '2024-08-25', 1, 'Blocked', '2024-08-05 11:00:00', '2024-08-05 11:00:00', 4, 5),
('Tarea 4 de Epsilon', 'Descripción de la tarea 4 del Proyecto Epsilon', '2024-08-15', NULL, 2, 'Done', '2024-08-05 12:00:00', '2024-08-05 12:00:00', 5, 5),
('Tarea 5 de Epsilon', 'Descripción de la tarea 5 del Proyecto Epsilon', '2024-08-20', NULL, 3, 'To do', '2024-08-05 13:00:00', '2024-08-05 13:00:00', 6, 5),
('Tarea 6 de Epsilon', 'Descripción de la tarea 6 del Proyecto Epsilon', NULL, '2024-09-10', 1, 'In progress', '2024-08-05 14:00:00', '2024-08-05 14:00:00', 7, 5),
('Tarea 7 de Epsilon', 'Descripción de la tarea 7 del Proyecto Epsilon', '2024-08-30', '2024-09-15', 2, 'Blocked', '2024-08-05 15:00:00', '2024-08-05 15:00:00', 8, 5),

-- Proyecto Zeta (ID 6) - Todas las tareas deben tener IDUsuario = NULL
('Tarea 1 de Zeta', 'Descripción de la tarea 1 del Proyecto Zeta', '2024-09-01', '2024-09-15', 2, 'To do', '2024-08-01 10:00:00', '2024-08-01 10:00:00', NULL, 6),
('Tarea 2 de Zeta', 'Descripción de la tarea 2 del Proyecto Zeta', NULL, '2024-09-20', 3, 'In progress', '2024-08-02 11:00:00', '2024-08-02 11:00:00', NULL, 6),
('Tarea 3 de Zeta', 'Descripción de la tarea 3 del Proyecto Zeta', '2024-09-10', '2024-09-25', 1, 'Blocked', '2024-08-03 12:00:00', '2024-08-03 12:00:00', NULL, 6),
('Tarea 4 de Zeta', 'Descripción de la tarea 4 del Proyecto Zeta', '2024-09-15', NULL, 2, 'Done', '2024-08-04 13:00:00', '2024-08-04 13:00:00', NULL, 6),
('Tarea 5 de Zeta', 'Descripción de la tarea 5 del Proyecto Zeta', '2024-09-20', NULL, 3, 'To do', '2024-08-05 14:00:00', '2024-08-05 14:00:00', NULL, 6),
('Tarea 6 de Zeta', 'Descripción de la tarea 6 del Proyecto Zeta', NULL, '2024-10-10', 1, 'In progress', '2024-08-06 15:00:00', '2024-08-06 15:00:00', NULL, 6),
('Tarea 7 de Zeta', 'Descripción de la tarea 7 del Proyecto Zeta', '2024-09-30', '2024-10-15', 2, 'Blocked', '2024-08-07 16:00:00', '2024-08-07 16:00:00', NULL, 6),

-- Proyecto Theta (ID 8) - Todas las tareas deben tener IDUsuario = NULL
('Tarea 1 de Theta', 'Descripción de la tarea 1 del Proyecto Theta', '2024-05-20', '2024-05-30', 2, 'Done', '2024-05-15 09:30:00', '2024-05-25 10:00:00', NULL, 8),
('Tarea 2 de Theta', 'Descripción de la tarea 2 del Proyecto Theta', '2024-05-25', '2024-06-05', 1, 'Blocked', '2024-05-16 10:00:00', '2024-05-27 11:00:00', NULL, 8),
('Tarea 3 de Theta', 'Descripción de la tarea 3 del Proyecto Theta', '2024-05-30', NULL, 3, 'To do', '2024-05-17 11:30:00', '2024-06-01 11:30:00', NULL, 8),
('Tarea 4 de Theta', 'Descripción de la tarea 4 del Proyecto Theta', NULL, '2024-06-10', 2, 'In progress', '2024-05-18 13:00:00', '2024-06-01 13:00:00', NULL, 8),

-- Proyecto "Sistemas Distribuidos" (ID 9)
('Revisar Ejercicios Bloque 1', 'Revisión de los ejercicios del Bloque 1 de la asignatura.', '2024-09-02', '2024-09-05', 2, 'In progress', '2024-09-02 09:00:00', '2024-09-02 09:00:00', 4, 9),
('Hacer EPD 1', 'Completar la EPD 1 de la asignatura.', '2024-09-03', '2024-09-04', 1, 'Done', '2024-09-03 10:00:00', '2024-09-04 11:00:00', 5, 9),
('Hacer EPD 2', 'Completar la EPD 2 de la asignatura.', '2024-09-04', '2024-09-05', 1, 'To do', '2024-09-04 09:00:00', '2024-09-04 09:00:00', NULL, 9),
('Revisar Ejercicios Bloque 2', 'Revisión de los ejercicios del Bloque 2 de la asignatura.', '2024-09-05', '2024-09-07', 3, 'Blocked', '2024-09-05 10:00:00', '2024-09-05 10:00:00', NULL, 9),
('Hacer EPD 3', 'Completar la EPD 3 de la asignatura.', '2024-09-07', '2024-09-09', 1, 'In progress', '2024-09-07 11:00:00', '2024-09-07 11:00:00', 6, 9),
('Entregar Proyecto Final', 'Entrega del proyecto final de la asignatura.', '2024-12-10', '2024-12-15', 1, 'To do', '2024-12-10 12:00:00', '2024-12-10 12:00:00', 7, 9),
('Estudiar para Examen Bloque 1', 'Estudio del Bloque 1 para el examen.', '2024-11-05', '2024-11-08', 2, 'To do', '2024-11-05 14:00:00', '2024-11-05 14:00:00', 8, 9),
('Estudiar para Examen Bloque 2', 'Estudio del Bloque 2 para el examen.', '2024-12-08', '2024-12-10', 3, 'To do', '2024-12-08 15:00:00', '2024-12-08 15:00:00', NULL, 9),
('Revisar Ejercicios Bloque 3', 'Revisión de los ejercicios del Bloque 3 de la asignatura.', NULL, NULL, 2, 'Blocked', '2025-01-10 16:00:00', '2025-01-10 16:00:00', 4, 9),
('Estudiar para Examen Bloque 3', 'Estudio del Bloque 3 para el examen.', '2025-01-10', '2025-01-12', 3, 'To do', '2025-01-10 17:00:00', '2025-01-10 17:00:00', 5, 9),

-- Proyecto "TFG" (ID 10)
    -- Fase 1: Planificación y Diseño
('Definición de Requisitos', 'Enumerar las funcionalidades y características deseadas de la web.', '2023-10-10', '2023-10-17', 1, 'Done', '2023-10-10 09:00:00', '2023-10-17 10:00:00', 4, 10),
('Investigación de Herramientas', 'Elegir las versiones adecuadas de Angular, Python y otras herramientas necesarias.', '2023-10-18', '2023-10-25', 2, 'Done', '2023-10-18 10:00:00', '2023-10-25 11:00:00', 4, 10),
('Diseño de la Interfaz de Usuario', 'Bocetar el diseño de las páginas, incluyendo la ventana de inicio, login, y menús.', '2023-10-26', '2023-11-02', 2, 'Done', '2023-10-26 09:00:00', '2023-11-02 12:00:00', 4, 10),
    -- Fase 2: Configuración del Entorno de Desarrollo
('Configuración del Entorno de Trabajo', 'Instalar Angular, Python y otras herramientas.', '2023-11-11', '2023-11-15', 2, 'Done', '2023-11-11 09:00:00', '2023-11-15 10:00:00', 4, 10),
('Creación del Repositorio de Código', 'Configurar un repositorio en GitHub para el control de versiones.', '2023-11-16', '2023-11-18', 2, 'Done', '2023-11-16 09:00:00', '2023-11-18 09:00:00', 4, 10),
    -- Fase 3: Desarrollo de Backend
('Implementación de la Base de Datos', 'Crear y configurar la base de datos.', '2023-12-03', '2023-12-10', 3, 'Done', '2023-12-03 09:00:00', '2023-12-10 16:00:00', 4, 10),
('Desarrollo de APIs', 'Crear APIs para la interacción entre el frontend y el backend.', '2023-12-11', '2023-12-20', 1, 'Done', '2023-12-11 09:00:00', '2023-12-20 18:00:00', 4, 10),
    -- Fase 4: Desarrollo de Frontend
('Diseño de componentes con Angular', 'Añadir components y pages para manejar eventos y datos en el frontend.', '2024-01-16', '2024-02-10', 3, 'Done', '2024-01-16 09:00:00', '2024-02-10 14:00:00', 4, 10),
('Conexión con el Backend', 'Integrar las APIs del backend con el frontend.', '2024-02-11', '2024-02-25', 1, 'Done', '2024-02-11 09:00:00', '2024-02-25 16:00:00', 4, 10),
('Pruebas de Interfaces', 'Realizar pruebas para asegurar que las interfaces funcionan correctamente.', '2024-02-26', '2024-03-10', 2, 'Done', '2024-02-26 09:00:00', '2024-03-10 12:00:00', 4, 10),
    -- Fase 5: Integración y Pruebas
('Pruebas de Funcionalidades', 'Realizar pruebas exhaustivas de todas las funcionalidades implementadas.', '2024-06-11', '2024-08-25', 2, 'In progress', '2024-03-11 09:00:00', '2024-03-25 12:00:00', 4, 10),
('Solución de Problemas y Optimización', 'Corregir errores y mejorar el rendimiento.', '2024-03-26', '2024-04-15', 3, 'Done', '2024-04-26 10:00:00', '2024-08-15 15:00:00', 4, 10),
    -- Fase 6: Documentación y Despliegue
('Redacción del Informe Final', 'Redactar el informe de cierre del proyecto TFG.', '2024-04-16', '2024-08-10', 3, 'In progress', '2024-04-16 10:00:00', '2024-08-10 15:00:00', 4, 10),
('Despliegue de la Aplicación', 'Desplegar la aplicación en un servidor para la revisión final.', '2024-08-11', '2024-08-15', 1, 'In progress', '2024-08-11 09:00:00', '2024-08-15 11:00:00', 4, 10),
    -- Fase 7: Revisión y Ajustes
('Redacción de Conclusiones', 'Redactar las conclusiones del TFG.', '2024-08-16', '2024-08-20', 2, 'To do', '2024-08-16 09:00:00', '2024-08-20 12:00:00', 4, 10),
('Preparación de la Defensa', 'Crear el PowerPoint para la defensa del TFG y ensayar la presentación.', '2024-08-21', '2024-09-10', 3, 'To do', '2024-08-21 10:00:00', '2024-09-10 14:00:00', 4, 10),
('Revisión Final y Entrega', 'Revisar todo el proyecto y preparar la entrega del TFG.', '2024-09-11', '2024-09-15', 1, 'To do', '2024-09-11 09:00:00', '2024-09-15 18:00:00', 4, 10);


-- Insertar datos en Comentarios
-- Proyecto Alpha (IDProyecto: 1) - 6 comentarios
INSERT INTO Comentarios (Contenido, Created_at, IDProyecto, IDUsuario) VALUES
('He revisado el avance del Proyecto Alpha y todo parece ir bien. ¿Alguien más ha detectado algún problema?', '2024-05-22 09:00:00', 1, 4),  -- Andrea
('Solo un pequeño detalle con la integración, pero creo que lo puedo solucionar rápido.', '2024-05-23 10:30:00', 1, 5),  -- Pablo
('Esto es un comentario en el Proyecto Alpha', '2024-05-24 11:00:00', 1, 6),  -- María
('Comentario de prueba', '2024-05-25 15:00:00', 1, 7),  -- Francesc
('Hola a todos! Me pongo con las tareas pendientes.', '2024-05-26 10:00:00', 1, 8),  -- Carlos
('Esto es un comentario en el Proyecto Alpha', '2024-05-27 09:30:00', 1, 4),  -- Andrea

-- Proyecto Beta (IDProyecto: 2) - 3 comentarios
('En el Proyecto Beta, he encontrado una forma de optimizar el proceso. ¿Podrían revisarlo?', '2024-06-22 09:00:00', 2, 5),  -- Pablo
('Comentario de prueba', '2024-06-23 11:30:00', 2, 7),  -- Francesc
('Esto es un comentario en el Proyecto Beta', '2024-06-24 10:00:00', 2, 8),  -- Carlos

-- Proyecto Gamma (IDProyecto: 3) - 7 comentarios
('Acabo de actualizar el documento con los últimos cambios del Proyecto Gamma. Por favor, revísenlo.', '2024-07-07 10:00:00', 3, 4),  -- Andrea
('Todo claro con los cambios, Andrea. Adjunto el documento finalizado en formato Word.', '2024-07-08 12:00:00', 3, 5),  -- Pablo
('Esto es un comentario en el Proyecto Gamma', '2024-07-09 14:00:00', 3, 6),  -- María
('Comentario de prueba', '2024-07-10 10:00:00', 3, 4),  -- Andrea
('Hola a todos! Me pongo con las tareas pendientes.', '2024-07-11 11:00:00', 3, 7),  -- Francesc
('Comentario de prueba', '2024-07-12 09:00:00', 3, 8),  -- Carlos
('Perfecto. Creo que con estos cambios estamos listos para la presentación.', '2024-07-13 08:00:00', 3, 6),  -- María

-- Proyecto Delta (IDProyecto: 4) - 2 comentarios
('Comentario de prueba', '2024-07-26 10:00:00', 4, 2),  -- Admin
('Esto es un comentario en el Proyecto Delta', '2024-07-27 09:00:00', 4, 3),  -- User

-- Proyecto Epsilon (IDProyecto: 5) - 2 comentarios
('Comentario de prueba', '2024-08-05 09:30:00', 5, 3),  -- User
('Esto es un comentario en el Proyecto Epsilon', '2024-08-05 10:00:00', 5, 5),  -- Pablo

-- Proyecto Kappa (IDProyecto: 7) - 3 comentarios
('Esto es un comentario en el Proyecto Kappa', '2024-08-04 12:00:00', 7, 3),  -- User
('Hola a todos! Me pongo con las tareas pendientes.', '2024-08-05 14:00:00', 7, 7),  -- Francesc
('Comentario de prueba', '2024-08-06 16:00:00', 7, 8),  -- Carlos

-- Proyecto Theta (IDProyecto: 8) - 6 comentarios
('El Proyecto Theta está casi completo, solo necesitamos finalizar algunos detalles.', '2024-05-15 10:00:00', 8, 2),  -- Admin
('Comentario de prueba', '2024-05-16 11:00:00', 8, 3),  -- User
('He añadido un par de notas finales. Adjunto una imagen que ilustra el diseño final.', '2024-05-17 12:00:00', 8, 4),  -- Andrea
('Esto es un comentario en el Proyecto Theta', '2024-05-18 13:00:00', 8, 5),  -- Pablo
('Comentario de prueba', '2024-05-19 14:00:00', 8, 3),  -- User
('Hola a todos! Me pongo con las tareas pendientes.', '2024-05-20 15:00:00', 8, 7),  -- Francesc

-- Proyecto "Sistemas Distribuidos" (ID 9)
('Estoy revisando los ejercicios del Bloque 1. ¿Alguien los ha visto ya?', '2024-09-02 11:00:00', 9, 4), -- Andrea
('He encontrado un error en la solución del ejercicio 3 del Bloque 1.', '2024-09-03 09:30:00', 9, 5), -- Pablo
('He terminado la EPD 1, lo he dejado guardado en Drive.', '2024-09-04 14:00:00', 9, 6), -- María
('Perfecto, ya tengo el archivo. Adjunto aquí luego el documento de la revisión.', '2024-09-05 16:00:00', 9, 7), -- Fran
('Subo la última versión del archivo con las respuestas del Bloque 1.', '2024-09-06 18:00:00', 9, 8), -- Carlos
('He revisado el archivo del Bloque 1 y parece que está todo correcto. En clase de EPD vemos si tenéis alguna duda.', '2024-09-11 18:00:00', 9, 17), -- Pepe

-- Proyecto "TFG" (ID 10)
('Completada la fase de definición de requisitos.', '2023-10-25 14:00:00', 10, 4), -- Andrea
('El proyecto finalmente será en Angular y Python.', '2023-11-19 15:00:00', 10, 4), -- Andrea
('Plan del proyecto en PDF.', '2024-08-20 10:00:00', 10, 4), -- Andrea
('Imágenes que pueden venir bien para la interfaz:', '2024-08-20 12:30:00', 10, 4), -- Andrea
('Repositorio en GitHub listo. Revisar ramas en local y hacer primer commit.', '2024-03-23 17:00:00', 10, 4); -- Andrea


-- Insertar datos en Archivos
INSERT INTO Archivos (Nombre, Ruta, IDComentario) VALUES
('Archivo de Proyecto Alpha', 'file1.txt', 6),  -- Proyecto Alpha, asociado al comentario de Andrea
('Archivo de Proyecto Beta', 'file2.txt', 9),  -- Proyecto Beta, asociado al comentario de Carlos
('Archivo PNG de progreso', 'progress.png', 14),  -- Proyecto Gamma, asociado al comentario de Francesc
('Documento de Proyecto Gamma', 'Proyecto Gamma.docx', 12),  -- Proyecto Gamma, asociado al comentario de Pablo
('PDF de Proyecto Gamma', 'Proyecto Gamma.pdf', 13),  -- Proyecto Gamma, asociado al comentario de María
('Imagen de usabilidad', 'usabilidad.png', 19),  -- Proyecto Kappa, asociado al comentario de Francesc
('Bloque1.txt', 'Bloque1.txt', (SELECT ID FROM Comentarios WHERE Contenido LIKE '%Subo la última versión del archivo con las respuestas del Bloque 1.%')),
('Plan de Proyecto.pdf', 'Plan de Proyecto.pdf', (SELECT ID FROM Comentarios WHERE Contenido LIKE '%Plan del proyecto en PDF.%')),  -- Proyecto "TFG", asociado al comentario de Andrea
('usabilidad.png', 'usabilidad.png', (SELECT ID FROM Comentarios WHERE Contenido LIKE '%Imágenes que pueden venir bien para la interfaz:%'));  -- Proyecto "TFG", asociado al comentario de Andrea


-- Insertar datos en Mensajes
INSERT INTO Mensajes (Asunto, Contenido, Check_Leido, Created_at, Updated_at, IDEmisor, IDReceptor) VALUES
-- Comunicado global enviado por Panda Planning (IDEmisor: 1)
('Comunicado General', 'Estimados usuarios, nos complace informarles que hemos implementado nuevas funcionalidades en la plataforma. Estas mejoras están diseñadas para optimizar su experiencia y facilitar la gestión de proyectos. Les invitamos a explorar estas nuevas opciones y, como siempre, estamos disponibles para cualquier duda o consulta que puedan tener. Gracias por su continuo apoyo y colaboración. El equipo de Panda Planning.', TRUE, '2024-07-01 08:00:00', '2024-07-01 08:00:00', 1, 2),  -- Admin
('Comunicado General', 'Estimados usuarios, nos complace informarles que hemos implementado nuevas funcionalidades en la plataforma. Estas mejoras están diseñadas para optimizar su experiencia y facilitar la gestión de proyectos. Les invitamos a explorar estas nuevas opciones y, como siempre, estamos disponibles para cualquier duda o consulta que puedan tener. Gracias por su continuo apoyo y colaboración. El equipo de Panda Planning.', TRUE, '2024-07-01 08:00:00', '2024-07-01 08:00:00', 1, 3),  -- User de prueba
('Comunicado General', 'Estimados usuarios, nos complace informarles que hemos implementado nuevas funcionalidades en la plataforma. Estas mejoras están diseñadas para optimizar su experiencia y facilitar la gestión de proyectos. Les invitamos a explorar estas nuevas opciones y, como siempre, estamos disponibles para cualquier duda o consulta que puedan tener. Gracias por su continuo apoyo y colaboración. El equipo de Panda Planning.', TRUE, '2024-07-01 08:00:00', '2024-07-01 08:00:00', 1, 4),  -- Andrea Fernández
('Comunicado General', 'Estimados usuarios, nos complace informarles que hemos implementado nuevas funcionalidades en la plataforma. Estas mejoras están diseñadas para optimizar su experiencia y facilitar la gestión de proyectos. Les invitamos a explorar estas nuevas opciones y, como siempre, estamos disponibles para cualquier duda o consulta que puedan tener. Gracias por su continuo apoyo y colaboración. El equipo de Panda Planning.', TRUE, '2024-07-01 08:00:00', '2024-07-01 08:00:00', 1, 5),  -- Pablo Casas
('Comunicado General', 'Estimados usuarios, nos complace informarles que hemos implementado nuevas funcionalidades en la plataforma. Estas mejoras están diseñadas para optimizar su experiencia y facilitar la gestión de proyectos. Les invitamos a explorar estas nuevas opciones y, como siempre, estamos disponibles para cualquier duda o consulta que puedan tener. Gracias por su continuo apoyo y colaboración. El equipo de Panda Planning.', TRUE, '2024-07-01 08:00:00', '2024-07-01 08:00:00', 1, 6),  -- María Varo
-- Chat de Andrea Fernández (IDEmisor: 4) con User de prueba (IDReceptor: 3)
('¡Bienvenido!', '¡Hola! Bienvenido al equipo. Me han comentado que acabas de entrar en el proyecto, quería presentarme y darte la bienvenida. Si necesitas algo no dudes en contactarme. ¡Un saludo!', TRUE, '2024-05-20 10:00:00', '2024-05-20 10:00:00', 4, 3),
('Gracias!', 'Hola Andrea! Muchas gracias por la bienvenida. Estoy encantado de ser parte del equipo. Si tengo alguna duda, te lo haré saber. ¡Nos vemos!', TRUE, '2024-05-20 10:05:00', '2024-05-20 10:05:00', 3, 4),
('Documento Subido', 'Hola Andrea, he subido un nuevo documento al proyecto Alpha. ¿Podrías revisarlo cuando tengas un momento?', TRUE, '2024-08-07 13:00:00', '2024-08-07 13:00:00', 3, 4),
('Re: Documento Subido', 'Hola, claro que sí, lo reviso ahora mismo. Gracias por el aviso.', FALSE, '2024-08-07 13:20:00', '2024-08-07 13:20:00', 4, 3),
-- Chat de Andrea Fernández (IDEmisor: 4) con Pablo Casas (IDReceptor: 5)
('Recordatorio', 'Hola Pablo, solo quería recordarte la reunión de mañana. ¡Nos vemos a las 10:00!', TRUE, '2024-05-21 12:00:00', '2024-05-21 12:00:00', 4, 5),
('Avance de Tareas', 'Hola Pablo, ¿cómo llevas la tarea asignada en el proyecto Beta? ¿Necesitas ayuda?', TRUE, '2024-08-07 14:00:00', '2024-08-07 14:00:00', 4, 5),
('Re: Avance de Tareas', 'Hola Andrea, todo bien, pero puede que necesite un par de días más para terminar. ¿Está bien?', TRUE, '2024-08-07 14:30:00', '2024-08-07 14:30:00', 5, 4),
('Re: Avance de Tareas', 'Por supuesto, tómate el tiempo que necesites. Gracias por mantenerme al tanto.', FALSE, '2024-08-07 14:45:00', '2024-08-07 14:45:00', 4, 5),
-- Chat de Andrea Fernández (IDEmisor: 4) con Jorge Martínez (IDReceptor: 9)
('Consulta Rápida', 'Hola Jorge, tengo una duda sobre el último informe que subiste. ¿Podrías echarle un vistazo cuando tengas tiempo?', TRUE, '2024-08-10 14:00:00', '2024-08-10 14:00:00', 4, 9),
-- Chat de Andrea Fernández (IDEmisor: 4) con Laura López (IDReceptor: 10)
('Cambio de Planes', 'Hola Laura, parece que tendremos que ajustar el cronograma del proyecto debido a algunos contratiempos. ¿Podemos hablar sobre esto?', TRUE, '2024-08-09 10:00:00', '2024-08-09 10:00:00', 4, 10),
-- Chat de Andrea Fernández (IDEmisor: 4) con Marta García (IDReceptor: 11)
('Documento Subido', 'Hola Marta, acabo de subir el documento final del proyecto Kappa. ¿Podrías revisarlo antes de la reunión?', TRUE, '2024-08-08 16:00:00', '2024-08-08 16:00:00', 4, 11),
-- Chat de Andrea Fernández (IDEmisor: 4) con María Varo (IDReceptor: 6)
('Planificación de Reunión', 'Hola María, necesitamos planificar la próxima reunión del equipo. ¿Te viene bien el miércoles a las 10:00 AM?', TRUE, '2024-08-08 09:00:00', '2024-08-08 09:00:00', 4, 6),
('Re: Planificación de Reunión', 'Hola Andrea, el miércoles está perfecto para mí. ¿Podríamos hacerla en la mañana?', TRUE, '2024-08-08 09:15:00', '2024-08-08 09:15:00', 6, 4),
('Confirmación de Reunión', 'Perfecto, entonces lo dejamos para el miércoles a las 10:00. Enviaré la invitación.', TRUE, '2024-08-08 09:30:00', '2024-08-08 09:30:00', 4, 6),
('Gracias', 'Genial, gracias Andrea. Estaré lista.', FALSE, '2024-08-08 09:45:00', '2024-08-08 09:45:00', 6, 4),
-- Chat del Administrador (IDEmisor: 2) con Pablo Casas (IDReceptor: 5)
('Revisión de Proyecto', 'Hola Pablo, por favor revisa los avances del Proyecto Gamma para nuestra reunión del viernes. Gracias.', TRUE, '2024-08-05 11:00:00', '2024-08-05 11:00:00', 2, 5),
('Actualización de Sistema', 'Pablo, el sistema de seguimiento de tareas se ha actualizado. Asegúrate de que todo esté funcionando correctamente.', TRUE, '2024-08-05 11:30:00', '2024-08-05 11:30:00', 2, 5),
('Tareas Completas', 'Recuerda revisar las tareas completadas antes del cierre del sprint.', FALSE, '2024-08-05 12:00:00', '2024-08-05 12:00:00', 2, 5),
-- Chat del Administrador (IDEmisor: 2) con María Varo (IDReceptor: 6)
('Control de Calidad', 'Hola María, asegúrate de que todas las pruebas estén completas antes de la fecha límite.', TRUE, '2024-08-06 13:00:00', '2024-08-06 13:00:00', 2, 6),
-- Chat del Administrador (IDEmisor: 2) con Francesc Rodríguez (IDReceptor: 7)
('Actualización de Proyecto', 'Fran, necesitamos una actualización del proyecto Beta para la próxima reunión.', TRUE, '2024-08-07 10:00:00', '2024-08-07 10:00:00', 2, 7);


-- Insertar datos en Reuniones
INSERT INTO Reuniones (Titulo, Descripcion, FechaHora, Duracion, Modalidad, Created_at, IDCreador) VALUES
('Reunión de Planificación', 'Reunión para planificar el próximo sprint', '2024-09-01 09:00:00', 90, 'Virtual', '2024-08-01 09:00:00', 4),
('Reunión de Retrospectiva', 'Reunión para discutir la retrospectiva del sprint anterior', '2024-09-05 14:00:00', 60, 'Presencial', '2024-08-02 11:00:00', 5),
('Reunión de Diseño', 'Reunión para discutir el diseño del nuevo módulo', '2024-09-10 11:00:00', 120, 'Virtual', '2024-08-03 12:00:00', 6),
('Reunión de Revisión', 'Reunión para revisar el progreso del proyecto', '2024-09-15 16:00:00', 45, 'Presencial', '2024-08-04 13:00:00', 7),
('Reunión de Kickoff', 'Reunión de inicio del nuevo proyecto', '2024-09-20 10:00:00', 60, 'Virtual', '2024-08-05 14:00:00', 8),
('Reunión de Planificación Inicial', 'Definir el plan de trabajo para Sistemas Distribuidos.', '2024-09-05 10:00:00', 60, 'Virtual', '2024-09-01 09:00:00', 4),
('Reunión de Revisión Intermedia', 'Revisión de progreso a mitad del proyecto.', '2024-11-10 14:00:00', 90, 'Presencial', '2024-11-01 09:00:00', 5),
('Reunión de Preparación para Exámenes', 'Discutir la estrategia de estudio y repasar los contenidos más importantes.', '2024-12-15 16:00:00', 120, 'Virtual', '2024-12-01 10:00:00', 6);


-- Insertar datos en ParticipantesReunion
INSERT INTO ParticipantesReunion (IDReunion, IDUsuario, Respuesta, Created_at, Updated_at) VALUES
-- Reunión de Planificación (IDReunion: 1)
(1, 4, 'ACEPTADA', '2024-08-01 09:00:00', '2024-08-01 09:00:00'), -- Andrea (Creador)
(1, 5, 'PENDIENTE', '2024-08-01 09:15:00', '2024-08-01 09:15:00'), -- Pablo
(1, 6, 'RECHAZADA', '2024-08-01 09:30:00', '2024-08-01 09:30:00'), -- María
(1, 2, 'ACEPTADA', '2024-08-01 10:00:00', '2024-08-01 10:00:00'), -- Admin

-- Reunión de Retrospectiva (IDReunion: 2)
(2, 5, 'ACEPTADA', '2024-08-02 11:00:00', '2024-08-02 11:00:00'), -- Pablo (Creador)
(2, 4, 'ACEPTADA', '2024-08-02 11:30:00', '2024-08-02 11:30:00'), -- Andrea
(2, 7, 'PENDIENTE', '2024-08-02 12:00:00', '2024-08-02 12:00:00'), -- Francesc
(2, 3, 'ACEPTADA', '2024-08-02 13:00:00', '2024-08-02 13:00:00'), -- User

-- Reunión de Diseño (IDReunion: 3)
(3, 6, 'ACEPTADA', '2024-08-03 12:00:00', '2024-08-03 12:00:00'), -- María (Creador)
(3, 4, 'ACEPTADA', '2024-08-03 12:30:00', '2024-08-03 12:30:00'), -- Andrea
(3, 8, 'PENDIENTE', '2024-08-03 13:00:00', '2024-08-03 13:00:00'), -- Carlos
(3, 2, 'PENDIENTE', '2024-08-03 14:00:00', '2024-08-03 14:00:00'), -- Admin

-- Reunión de Revisión (IDReunion: 4)
(4, 7, 'ACEPTADA', '2024-08-04 13:00:00', '2024-08-04 13:00:00'), -- Francesc (Creador)
(4, 4, 'ACEPTADA', '2024-08-04 13:30:00', '2024-08-04 13:30:00'), -- Andrea
(4, 5, 'RECHAZADA', '2024-08-04 14:00:00', '2024-08-04 14:00:00'), -- Pablo
(4, 3, 'PENDIENTE', '2024-08-04 15:00:00', '2024-08-04 15:00:00'), -- User

-- Reunión de Kickoff (IDReunion: 5)
(5, 8, 'ACEPTADA', '2024-08-05 14:00:00', '2024-08-05 14:00:00'), -- Carlos (Creador)
(5, 6, 'ACEPTADA', '2024-08-05 14:30:00', '2024-08-05 14:30:00'), -- María
(5, 7, 'PENDIENTE', '2024-08-05 15:00:00', '2024-08-05 15:00:00'), -- Francesc
(5, 2, 'ACEPTADA', '2024-08-05 16:00:00', '2024-08-05 16:00:00'), -- Admin

-- Reunión de Planificación Inicial (IDReunion: 6)
(6, 4, 'ACEPTADA', '2024-09-01 09:15:00', '2024-09-01 09:15:00'), -- Andrea (Creador)
(6, 5, 'ACEPTADA', '2024-09-01 09:30:00', '2024-09-01 09:30:00'), -- Pablo
(6, 6, 'PENDIENTE', '2024-09-01 09:45:00', '2024-09-01 09:45:00'), -- María
(6, 7, 'RECHAZADA', '2024-09-01 10:00:00', '2024-09-01 10:00:00'), -- Fran
(6, 8, 'ACEPTADA', '2024-09-01 10:15:00', '2024-09-01 10:15:00'), -- Carlos
(6, 17, 'ACEPTADA', '2024-09-01 10:30:00', '2024-09-01 10:30:00'), -- Pepe

-- Reunión de Revisión Intermedia (IDReunion: 7)
(7, 5, 'ACEPTADA', '2024-11-01 09:00:00', '2024-11-01 09:00:00'), -- Pablo (Creador)
(7, 4, 'ACEPTADA', '2024-11-01 09:30:00', '2024-11-01 09:30:00'), -- Andrea
(7, 6, 'RECHAZADA', '2024-11-01 10:00:00', '2024-11-01 10:00:00'), -- María
(7, 7, 'ACEPTADA', '2024-11-01 10:30:00', '2024-11-01 10:30:00'), -- Fran
(7, 8, 'PENDIENTE', '2024-11-01 11:00:00', '2024-11-01 11:00:00'), -- Carlos

-- Reunión de Preparación para Exámenes (IDReunion: 8)
(8, 6, 'ACEPTADA', '2024-12-01 10:00:00', '2024-12-01 10:00:00'), -- María (Creador)
(8, 4, 'ACEPTADA', '2024-12-01 10:30:00', '2024-12-01 10:30:00'), -- Andrea
(8, 5, 'PENDIENTE', '2024-12-01 11:00:00', '2024-12-01 11:00:00'), -- Pablo
(8, 7, 'RECHAZADA', '2024-12-01 11:30:00', '2024-12-01 11:30:00'), -- Fran
(8, 8, 'ACEPTADA', '2024-12-01 12:00:00', '2024-12-01 12:00:00'); -- Carlos