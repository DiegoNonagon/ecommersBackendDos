//Funciones para manejar el hash de contraseñas
import bcrypt from 'bcrypt';

// Función para encriptar la contraseña
export const hashPassword = (password) => {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
};

// Función para comparar una contraseña con su hash
export const comparePassword = (password, hashedPassword) => {
  return bcrypt.compareSync(password, hashedPassword);
};
