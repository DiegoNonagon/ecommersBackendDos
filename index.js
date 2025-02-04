import express from 'express';
import dotenv from 'dotenv';
import connectDB from './src/config/dataBase.js';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import passport from 'passport';
import './src/config/passport.js'; // Configuración de Passport
import sessionRoutes from './src/routes/sessions.js';

dotenv.config();
connectDB(); // Conectar a MongoDB

const app = express();

// Middlewares
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(passport.initialize());

// Rutas
app.use('/api/sessions', sessionRoutes);

// Inicializamos el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});