-- Sharur SAIC — scripts/init_db.sql
--
-- Inicialización reproducible de la base de datos.
-- Deja siempre el mismo estado conocido: borra lo anterior y lo recrea,
-- así que se puede ejecutar cuantas veces haga falta (idempotente).
--
-- Uso (Linux, como superusuario de PostgreSQL):
--     sudo -u postgres psql -f scripts/init_db.sql
--
-- Uso (Windows, en SQL Shell / psql conectado como postgres):
--     \i scripts/init_db.sql
--
-- Credenciales por defecto (coinciden con el DATABASE_URL de ejemplo del
-- README). Cambiarlas aquí y en el .env si se desea otra contraseña.

-- Kali/Debian rolling: alinear la versión de collation del template con la
-- de glibc. Evita el error "template database has a collation version
-- mismatch" al crear la base. Es un no-op si no hay desajuste.
ALTER DATABASE template1 REFRESH COLLATION VERSION;

-- Punto de partida limpio. Se borra la base antes que el rol porque el rol
-- es dueño de la base y no puede eliminarse mientras posea objetos.
DROP DATABASE IF EXISTS sharur_db;
DROP ROLE IF EXISTS sharur_user;

-- Rol de aplicación y base, con el rol como dueño.
CREATE USER sharur_user WITH PASSWORD 'sharur_pass';
CREATE DATABASE sharur_db OWNER sharur_user;
GRANT ALL PRIVILEGES ON DATABASE sharur_db TO sharur_user;

-- Permisos sobre el schema public de la base recién creada.
-- Necesario en PostgreSQL 15 o superior, donde public ya no es de
-- escritura abierta. Debe hacerse conectado a sharur_db, no a postgres.
\connect sharur_db
GRANT ALL ON SCHEMA public TO sharur_user;

\echo 'Sharur: base sharur_db y usuario sharur_user listos.'
