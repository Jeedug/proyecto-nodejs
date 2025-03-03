const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");
const { client } = require("./models/config"); // Importar el cliente de Turso
const { registerUser, loginUser, verifyToken } = require("./utils/auth");
const jwt = require("jsonwebtoken"); // Importar jsonwebtoken

const JWT_SECRET = process.env.JWT_SECRET_PASS || "tu_clave_secreta";

const PORT = process.env.PORT || 3000;

// Función para verificar si el usuario está autenticado
function isAuthenticated(cookies) {
  if (!cookies) return false;

  // Buscar el token en las cookies
  const token = cookies
    .split("; ")
    .find((row) => row.startsWith("token="))
    ?.split("=")[1];

  if (!token) return false;

  // Verificar el token
  const tokenVerification = verifyToken(token);
  return tokenVerification.valid;
}

function authenticateToken(cookies) {
  if (!cookies) return false;

  // Buscar el token en las cookies
  const token = cookies
    .split("; ")
    .find((row) => row.startsWith("token="))
    ?.split("=")[1];

  if (!token) return null; // Si no hay token, retornar null

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(decoded);
    return decoded.email; // Retornar el email del token
  } catch (err) {
    return null; // Si el token es inválido, retornar null
  }
}

// Crear el servidor
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Extraer las cookies
  const cookies = req.headers.cookie;

  // Verificar si el usuario está autenticado
  const authenticated = isAuthenticated(cookies);

  // Servir archivos estáticos
  if (pathname === "/" || pathname === "/login" || pathname === "/register") {
    // Si el usuario está autenticado, redirigir a /indexlogged
    if (authenticated) {
      res.writeHead(302, { Location: "/indexlogged" });
      res.end();
      return;
    }

    // Si el usuario no está autenticado, servir las páginas correspondientes
    let filePath = "";
    if (pathname === "/") {
      filePath = path.join(__dirname, "public", "index.html");
    } else if (pathname === "/login") {
      filePath = path.join(__dirname, "public", "login.html");
    } else if (pathname === "/register") {
      filePath = path.join(__dirname, "public", "register.html");
    }

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Error interno del servidor");
      } else {
        const ext = path.extname(filePath);
        let contentType = "text/html";
        if (ext === ".css") {
          contentType = "text/css";
        } else if (ext === ".js") {
          contentType = "application/javascript";
        }
        res.writeHead(200, { "Content-Type": contentType });
        res.end(data);
      }
    });
  }
  // Servir la página protegida /crud
  else if (pathname === "/crud") {
    // Si el usuario no está autenticado, redirigir a /login
    if (!authenticated) {
      res.writeHead(302, { Location: "/login" });
      res.end();
      return;
    }

    // Si el usuario está autenticado, servir la página /crud
    const filePath = path.join(__dirname, "public", "crud.html");
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Error interno del servidor");
      } else {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
      }
    });
  }
  // Servir la página /indexlogged para usuarios autenticados
  else if (pathname === "/indexlogged") {
    // Si el usuario no está autenticado, redirigir a /login
    if (!authenticated) {
      res.writeHead(302, { Location: "/login" });
      res.end();
      return;
    }

    // Si el usuario está autenticado, servir la página /indexlogged
    const filePath = path.join(__dirname, "public", "indexlogged.html");
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Error interno del servidor");
      } else {
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data);
      }
    });
  }
  // Manejar registro de usuarios
  // Manejar registro de usuario
  else if (pathname === "/api/register" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", async () => {
      const { username, password, email } = JSON.parse(body);

      try {
        // Llamar a la función de registro
        const result = await registerUser(username, password, email);

        // Registrar log de registro
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: ["CREATE", `Usuario registrado: ${email}`, email, "usuarios"],
        });

        res.writeHead(result.success ? 201 : 400, {
          "Content-Type": "application/json",
        });
        res.end(JSON.stringify({ message: result.message }));
      } catch (error) {
        console.error("Error al registrar usuario:", error.message);

        // Registrar log de error
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "ERROR",
            `Error al registrar usuario: ${error.message}`,
            email || "unknown",
            "usuarios",
          ],
        });

        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Error al registrar usuario" }));
      }
    });
  }
  // Manejar inicio de sesión
  else if (pathname === "/api/login" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", async () => {
      const { email, password } = JSON.parse(body);

      try {
        // Llamar a la función de inicio de sesión
        const result = await loginUser(email, password);

        if (result.success) {
          // Configurar la cookie con el token JWT
          res.writeHead(200, {
            "Set-Cookie": `token=${result.token}; HttpOnly; Path=/; Max-Age=3600`, // Token válido por 1 hora
            "Content-Type": "application/json",
          });

          // Registrar log de inicio de sesión exitoso
          await client.execute({
            sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
            args: [
              "LOGIN",
              `Inicio de sesión exitoso para: ${email}`,
              email,
              "usuarios",
            ],
          });

          res.end(JSON.stringify({ message: result.message }));
        } else {
          // Registrar log de inicio de sesión fallido
          await client.execute({
            sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
            args: [
              "LOGIN_FAILED",
              `Inicio de sesión fallido para: ${email}`,
              email,
              "usuarios",
            ],
          });

          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ message: result.message }));
        }
      } catch (error) {
        console.error("Error al iniciar sesión:", error.message);

        // Registrar log de error
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "ERROR",
            `Error al iniciar sesión: ${error.message}`,
            email || "unknown",
            "usuarios",
          ],
        });

        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Error al iniciar sesión" }));
      }
    });
  }
  // Proteger la ruta /api/crud
  else if (pathname === "/api/crud" && req.method === "GET") {
    // Si el usuario no está autenticado, devolver un error
    if (!authenticated) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Acceso no autorizado" }));
      return;
    }

    // Si el token es válido, devolver datos protegidos
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ message: "Datos protegidos" }));
  }
  // Cerrar sesión
  else if (pathname === "/logout") {
    const username = authenticateToken(cookies) || "desconocido"; // Obtener el email del token o usar "anonymous"
  
    try {
      // Registrar log de cierre de sesión
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: ["LOGOUT", `Cierre de sesión exitoso para: ${username}`, username, "usuarios"],
      });
  
      // Eliminar la cookie del token
      res.writeHead(302, {
        "Set-Cookie":
          "token=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT", // Expirar la cookie
        Location: "/", // Redirigir al usuario a la página principal
      });
      res.end();
    } catch (error) {
      console.error("Error al registrar log de cierre de sesión:", error.message);
  
      // Registrar log de error
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: ["ERROR", `Error al registrar log de cierre de sesión: ${error.message}`, username, "usuarios"],
      });
  
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: "Error al cerrar sesión" }));
    }
  }
  // Rutas para comentarios
  else if (pathname === "/api/comments" && req.method === "GET") {
    const username = authenticateToken(cookies) || "desconocido"; // Obtener el email del token o usar "anonymous"

    console.log(authenticateToken(cookies));
    try {
      const commentsQuery = await client.execute(
        "SELECT * FROM comments ORDER BY created_at DESC"
      );
      const comments = commentsQuery.rows;

      // Registrar log de lectura
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: [
          "READ",
          "Se obtuvieron todos los comentarios",
          username,
          "comments",
        ],
      });

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(comments));
    } catch (error) {
      console.error("Error al obtener comentarios:", error.message);

      // Registrar log de error
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: [
          "ERROR",
          `Error al obtener comentarios: ${error.message}`,
          username,
          "comments",
        ],
      });

      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Error al obtener comentarios" }));
    }
  } else if (pathname === "/api/comments" && req.method === "POST") {
    const username = authenticateToken(cookies) || "desconocido"; // Obtener el email del token o usar "anonymous"
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", async () => {
      const { title, description } = JSON.parse(body);

      try {
        // Crear un nuevo comentario
        const result = await client.execute({
          sql: "INSERT INTO comments (title, description, created_at) VALUES (?, ?, datetime('now'))",
          args: [title, description],
        });

        // Registrar log de creación
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "CREATE",
            `Comentario creado con ID: ${result.lastInsertRowid}`,
            username,
            "comments",
          ],
        });

        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Comentario creado exitosamente" }));
      } catch (error) {
        console.error("Error al crear el comentario:", error.message);

        // Registrar log de error
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "ERROR",
            `Error al crear comentario: ${error.message}`,
            username,
            "comments",
          ],
        });

        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Error al crear el comentario" }));
      }
    });
  } else if (pathname.startsWith("/api/comments/") && req.method === "PUT") {
    const username = authenticateToken(cookies) || "desconocido"; // Obtener el email del token o usar "anonymous"
    const id = pathname.split("/")[3]; // Extraer el ID del comentario
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", async () => {
      const { title, description } = JSON.parse(body);

      try {
        // Actualizar un comentario existente
        await client.execute({
          sql: "UPDATE comments SET title = ?, description = ? WHERE id = ?",
          args: [title, description, id],
        });

        // Registrar log de actualización
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "UPDATE",
            `Comentario actualizado con ID: ${id}`,
            username,
            "comments",
          ],
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ message: "Comentario actualizado exitosamente" })
        );
      } catch (error) {
        console.error("Error al actualizar el comentario:", error.message);

        // Registrar log de error
        await client.execute({
          sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
          args: [
            "ERROR",
            `Error al actualizar comentario con ID: ${id}: ${error.message}`,
            username,
            "comments",
          ],
        });

        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ message: "Error al actualizar el comentario" })
        );
      }
    });
  } else if (pathname.startsWith("/api/comments/") && req.method === "DELETE") {
    const username = authenticateToken(cookies) || "desconocido"; // Obtener el email del token o usar "anonymous"
    const id = pathname.split("/")[3]; // Extraer el ID del comentario

    try {
      // Eliminar un comentario
      await client.execute({
        sql: "DELETE FROM comments WHERE id = ?",
        args: [id],
      });

      // Registrar log de eliminación
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: [
          "DELETE",
          `Comentario eliminado con ID: ${id}`,
          username,
          "comments",
        ],
      });

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Comentario eliminado exitosamente" }));
    } catch (error) {
      console.error("Error al eliminar el comentario:", error.message);

      // Registrar log de error
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: [
          "ERROR",
          `Error al eliminar comentario con ID: ${id}: ${error.message}`,
          username,
          "comments",
        ],
      });

      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "Error al eliminar el comentario" }));
    }
    
  }else if (pathname === '/api/logs' && req.method === 'GET') {
    try {
      // Consultar todos los logs
      const logsQuery = await client.execute("SELECT * FROM logs_nodejs ORDER BY timestamp DESC");
      const logs = logsQuery.rows;
  
      // Enviar los logs como respuesta en formato JSON
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(logs));
    } catch (error) {
      console.error("Error al obtener logs:", error.message);
  
      // Registrar log de error
      await client.execute({
        sql: "INSERT INTO logs_nodejs (action, details, username, table_name) VALUES (?, ?, ?, ?)",
        args: ["ERROR", `Error al obtener logs: ${error.message}`, "system", "logs_nodejs"],
      });
  
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: "Error al obtener logs" }));
    }
  } else {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Página no encontrada");
  }
});

// Iniciar el servidor
server.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
