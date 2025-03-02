---

# **Servidor express para el curso de backend avanzado 2 en coderhouse - Primer entrega**

Este servidor backend está diseñado en **Node.js** utilizando varias dependencias populares para la creación de una API RESTful que maneja la autenticación de usuarios mediante JWT (JSON Web Tokens) y la encriptación de contraseñas con **bcrypt**. El servidor usa **MongoDB** como base de datos para almacenar la información de los usuarios.

## **Dependencias**

Las dependencias principales utilizadas son:

- `nodemon`: Para reiniciar automáticamente el servidor durante el desarrollo.
- `express`: Framework de Node.js para crear la API.
- `jsonwebtoken`: Para generar y verificar tokens JWT para la autenticación.
- `bcrypt`: Para encriptar y comparar contraseñas de los usuarios.
- `mongoose`: ODM para MongoDB, facilita las interacciones con la base de datos.
- `passport`: Para implementar la autenticación basada en JWT y gestionar sesiones.

## **Estructura de Directorios**

La estructura de directorios para este backend es la siguiente:

```
/eCommerseBackendDos
│
├── /src
│   ├── /config
│   │   └── passport.js        # Estrategias de Passport
│   ├── /controllers
│   │   └── authController.js  # Controladores de autenticación
│   ├── /models
│   │   └── user.js            # Modelo de Usuario (User)
│   ├── /routes
│   │   └── authRoutes.js      # Rutas de autenticación
│   ├── /utils
│   │   └── bcrypt.js          # Utilidades de encriptación y comparación de contraseñas
│   └── server.js              # Archivo principal para levantar el servidor
├── package.json
├── .env                        # Variables de entorno (como JWT_SECRET)
└── nodemon.json                # Configuración de Nodemon
```

## **1. Instalación de Dependencias**

Para instalar todas las dependencias necesarias, corre el siguiente comando en tu terminal:

```bash
npm install nodemon express jsonwebtoken bcrypt mongoose passport passport-jwt dotenv
```

## **2. Modelo de Usuario (User Model)**

En **`src/models/user.js`** se define el esquema de MongoDB para los usuarios. La contraseña de cada usuario se almacena en formato hash, utilizando el paquete **bcrypt** para la encriptación.

```javascript
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

// Definición del esquema para el modelo de Usuario
const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: { type: String, unique: true, required: true },
  age: Number,
  password: String, // Contraseña en formato hash
  cart: { type: mongoose.Schema.Types.ObjectId, ref: 'Carts' },
  role: { type: String, default: 'user' }
});

// Middleware para encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', function (next) {
  if (!this.isModified('password')) return next();
  const salt = bcrypt.genSaltSync(10);
  this.password = bcrypt.hashSync(this.password, salt); // Encriptación de la contraseña
  next();
});

// Método para comparar la contraseña en texto claro con el hash guardado
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compareSync(password, this.password); // Comparación de la contraseña
};

// Crear y exportar el modelo de Usuario
const User = mongoose.model('User', userSchema);
export default User;
```

**Explicación**:
- **Schema**: Se define el esquema de usuario con los campos solicitados (`first_name`, `last_name`, `email`, `age`, `password`, etc.).
- **Pre-save Hook**: Antes de guardar un usuario, se encripta su contraseña si es que ha sido modificada.
- **Método `comparePassword`**: Este método se utiliza para comparar la contraseña ingresada con la versión encriptada almacenada en la base de datos.

## **3. Estrategias de Passport (passport.js)**

En **`src/config/passport.js`**, configuramos **Passport** para usar la estrategia JWT para la autenticación del usuario.

```javascript
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import User from '../models/user.js';
import dotenv from 'dotenv';

dotenv.config(); // Cargar las variables de entorno

// Opciones para la estrategia JWT
const opts = {
  jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.token]), // Extraer token de las cookies
  secretOrKey: process.env.JWT_SECRET, // Clave secreta para firmar el JWT
};

// Configurar la estrategia JWT
passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload.id); // Buscar al usuario con el ID del JWT
      if (!user) return done(null, false); // Si no se encuentra el usuario, devolver un error
      return done(null, user); // Si el usuario existe, devolverlo
    } catch (error) {
      return done(error, false); // Devolver error en caso de problemas
    }
  })
);
```

**Explicación**:
- **JWT Extraction**: La estrategia extrae el token desde las cookies utilizando `ExtractJwt.fromExtractors`.
- **JWT Secret**: La clave secreta se toma de las variables de entorno.
- **Verificación del Usuario**: La estrategia verifica si el usuario existe utilizando el ID presente en el payload del token.

## **4. Controladores de Autenticación (authController.js)**

El archivo **`src/controllers/authController.js`** contiene los controladores para registrar, iniciar sesión y obtener el usuario actual.

### **Registrar un Usuario**

```javascript
import User from '../models/user.js';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
  try {
    const { first_name, last_name, email, age, password } = req.body;

    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El usuario ya existe' });

    // Crear un nuevo usuario y guardarlo
    const newUser = new User({ first_name, last_name, email, age, password });
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error });
  }
};
```

### **Iniciar Sesión (Login)**

```javascript
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Buscar al usuario por su email
    const user = await User.findOne({ email });
    if (!user || !user.comparePassword(password)) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }
    
    // Crear y firmar el token JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true }); // Enviar el token en una cookie
    res.json({ message: 'Login exitoso', token });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error });
  }
};
```

### **Obtener el Usuario Actual**

```javascript
export const getCurrentUser = (req, res) => {
  res.json(req.user); // Devuelve el usuario asociado al token JWT
};
```

**Explicación**:
- **Register**: Si el usuario no existe, se crea un nuevo usuario con la contraseña encriptada.
- **Login**: El sistema verifica las credenciales del usuario y genera un JWT para autenticar futuras solicitudes.
- **Get Current User**: Extrae el usuario asociado al token JWT usando el middleware de Passport.

## **5. Rutas (authRoutes.js)**

El archivo **`src/routes/authRoutes.js`** contiene las rutas para registrarse, iniciar sesión y obtener el usuario actual.

```javascript
import express from 'express';
import passport from 'passport';
import { register, login, getCurrentUser } from '../controllers/authController.js';

const router = express.Router();

// Ruta para registrar un nuevo usuario
router.post('/register', register);

// Ruta para iniciar sesión
router.post('/login', login);

// Ruta para obtener el usuario actual
router.get('/current', passport.authenticate('jwt', { session: false }), getCurrentUser);

export default router;
```

**Explicación**:
- **`/register`**: Registra un nuevo usuario.
- **`/login`**: Permite que el usuario inicie sesión.
- **`/current`**: Utiliza Passport para verificar el JWT y devolver el usuario asociado.

## **6. Archivo Principal del Servidor (server.js)**

Finalmente, el archivo **`src/server.js`** es el punto de entrada para arrancar el servidor.

```javascript
import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import authRoutes from './routes/authRoutes.js';

dotenv.config(); // Cargar variables de entorno

// Crear la app de Express
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(passport.initialize()); // Inicializar Passport

// Conectar a MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB conectado'))
  .catch((error) => console.log('Error al conectar MongoDB', error));

// Usar las rutas de autenticación
app.use('/api/sessions', authRoutes);

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
```

---

