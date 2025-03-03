const { client } = require('../models/config');
const jwt = require('jsonwebtoken'); // Importar jsonwebtoken

// Clave secreta para firmar los tokens (puedes usar una variable de entorno)
const JWT_SECRET = process.env.JWT_SECRET_PASS || 'tu_clave_secreta';

// Función para registrar un usuario
async function registerUser(username, password, email) {
  try {
    // Verificar si el usuario ya existe
    const existingUserQuery = await client.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [email],
    });

    if (existingUserQuery.rows.length > 0) {
      throw new Error('El usuario ya existe');
    }

    // Insertar el nuevo usuario en la base de datos
    await client.execute({
      sql: 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      args: [username, email, password], // Usar username como name
    });

    return { success: true, message: 'Usuario registrado exitosamente' };
  } catch (error) {
    console.error('Error en registerUser:', error.message);
    return { success: false, message: error.message };
  }
}

// Función para iniciar sesión
async function loginUser(email, password) {
  try {
    // Buscar al usuario en la base de datos
    const userQuery = await client.execute({
      sql: 'SELECT * FROM users WHERE email = ?',
      args: [email],
    });

    const user = userQuery.rows[0];
    if (!user) {
      throw new Error('Credenciales incorrectas');
    }

    // Verificar la contraseña (en texto plano)
    if (user.password !== password) {
      throw new Error('Credenciales incorrectas');
    }

    // Generar un token JWT
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    return { success: true, message: 'Inicio de sesión exitoso', token };
  } catch (error) {
    console.error('Error en loginUser:', error.message);
    return { success: false, message: error.message };
  }
}

// Función para validar un token JWT
function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { valid: true, userId: decoded.userId, email: decoded.email };
  } catch (error) {
    return { valid: false, message: 'Token inválido o expirado' };
  }
}

module.exports = { registerUser, loginUser, verifyToken };