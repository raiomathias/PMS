// src/lib/sesion.js
// Login con "Nombre Apellido" + contrasena. Por dentro se usa Supabase Auth
// con un correo interno que nadie ve (nombre.apellido@pms.local).
import { supabase } from './supabase.js';

const DOMINIO = 'pms.local'; // debe ser el mismo que en la Edge Function

export function normalizarUsuario(nombreCompleto) {
  return nombreCompleto
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '');
}

export async function iniciarSesion(nombreCompleto, clave) {
  const correoInterno = `${normalizarUsuario(nombreCompleto)}@${DOMINIO}`;
  const { data, error } = await supabase.auth.signInWithPassword({
    email: correoInterno,
    password: clave,
  });
  if (error) throw new Error('Usuario o contraseña incorrectos');
  return data;
}

export async function cerrarSesion() {
  await supabase.auth.signOut();
}

// Devuelve el perfil (nombre, rol, activo) o null si no hay sesion
export async function cargarPerfil() {
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return null;
  const { data } = await supabase
    .from('perfiles')
    .select('id, nombre_completo, usuario, rol, activo')
    .eq('id', session.user.id)
    .single();
  return data?.activo ? data : null;
}

async function mensajeDeError(error) {
  try {
    const cuerpo = await error.context.json();
    return cuerpo.error ?? error.message;
  } catch {
    return error.message;
  }
}

// Gerencia y SysAdmin: usan la Edge Function crear_usuario
export async function crearUsuario(nombreCompleto, rol, clave) {
  const { data, error } = await supabase.functions.invoke('crear_usuario', {
    body: { accion: 'crear', nombre_completo: nombreCompleto, rol, clave },
  });
  if (error) throw new Error(await mensajeDeError(error));
  return data;
}

export async function cambiarClaveDeUsuario(usuarioId, claveNueva) {
  const { data, error } = await supabase.functions.invoke('crear_usuario', {
    body: { accion: 'cambiar_clave', usuario_id: usuarioId, clave: claveNueva },
  });
  if (error) throw new Error(await mensajeDeError(error));
  return data;
}

// Cualquier usuario cambia su propia clave
export async function cambiarMiClave(claveNueva) {
  const { error } = await supabase.auth.updateUser({ password: claveNueva });
  if (error) throw new Error(error.message);
}