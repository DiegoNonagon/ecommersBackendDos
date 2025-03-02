//Controladores de autenticación
import User from '../models/user.js';
import { hashPassword, comparePassword } from '../utils/bcrypt.js';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
  try {
    const { first_name, last_name, email, age, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'El usuario ya existe' });
    
    const hashedPassword = hashPassword(password);
    const newUser = new User({ first_name, last_name, email, age, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error });
  }
};

export const login = async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(401).json({ message: 'Credenciales incorrectas' });
      }
  
      // Compara la contraseña ingresada con la almacenada en la base de datos
      if (!comparePassword(password, user.password)) {
        return res.status(401).json({ message: 'Credenciales incorrectas' });
      }
      
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.cookie('token', token, { httpOnly: true });
      res.json({ message: 'Login exitoso', token });
    } catch (error) {
      res.status(500).json({ message: 'Error en el servidor', error });
    }
  };

export const logout = (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logout exitoso' });
};

export const getCurrentUser = (req, res) => {
  res.json(req.user);
};

