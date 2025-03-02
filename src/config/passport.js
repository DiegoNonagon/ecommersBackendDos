//Configuración de Passport con JWT
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import User from '../models/user.js';
import dotenv from 'dotenv';

dotenv.config();

const opts = {
    jwtFromRequest: (req) => req.cookies.token, // Extrae el JWT desde la cookie
    secretOrKey: process.env.JWT_SECRET,
  };

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload.id);
      if (!user) return done(null, false);
      return done(null, user);
    } catch (error) {
      return done(error, false);
    }
  })
);
