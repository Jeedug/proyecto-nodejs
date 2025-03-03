// models/config.js
const { createClient } = require('@libsql/client');

// Cargar variables de entorno desde .env
require('dotenv').config();

// Configuración de Turso
const tursoConfig = {
  url: process.env.TURSO_DATABASE_URL || "libsql://optimum-wendigo-jeedug.turso.io",
  authToken: process.env.TURSO_AUTH_TOKEN || "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NDAwMjk4MzcsImlkIjoiODQ1MGQwZDUtOWQ3My00M2UyLWFkZDktZjA4MjMzOTZkOTU5In0.9MjKayASDPleRopwwdi9U1qUoMlx5RtJbabMZ8vonFRm2ijSSGwvnjErfp8tqsbc88gwNqT4vyg3Uk6unmSLDA",
};

// Crear cliente de Turso
const client = createClient(tursoConfig);

module.exports = { client };