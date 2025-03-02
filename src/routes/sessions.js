//Rutas de autenticación
import express from 'express';
import passport from 'passport';
import { register, login, logout, getCurrentUser } from '../controllers/sessions.controller.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.get('/current', passport.authenticate('jwt', { session: false }), getCurrentUser);

export default router;
