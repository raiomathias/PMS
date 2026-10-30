import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const DOMINIO = 'pms.local';

const PUEDE_GESTIONAR: Record<string, string[]> = {
  administracion: ['recepcion', 'limpieza', 'administracion'],
  gerencia: ['recepcion', 'limpieza', 'administracion', 'gerencia'],
  sysadmin: ['recepcion', 'limpieza', 'administracion', 'gerencia', 'sysadmin'],
};

// Cabeceras CORS universales
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS, PUT, DELETE',
};

function normalizar(nombre: string): string {
  return nombre
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '.')
    .replace(/^\.+|\.+$/g, '');
}

function responder(cuerpo: unknown, estado = 200) {
  return new Response(JSON.stringify(cuerpo), {
    status: estado,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req) => {
  // 1. Responder de inmediato al preflight OPTIONS de CORS con 200 OK
  if (req.method === 'OPTIONS') {
    return new Response('ok', { status: 200, headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

    if (!supabaseUrl || !serviceRoleKey) {
      return responder({ error: 'Faltan variables de entorno en el servidor de Supabase' }, 500);
    }

    const admin = createClient(supabaseUrl, serviceRoleKey);

    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return responder({ error: 'Falta token de autenticación' }, 401);

    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error: authError } = await admin.auth.getUser(token);
    if (authError || !user) return responder({ error: 'No autenticado' }, 401);

    const { data: quien } = await admin
      .from('perfiles').select('rol, activo').eq('id', user.id).single();

    const permitidos = quien?.activo ? PUEDE_GESTIONAR[quien.rol] : undefined;
    if (!permitidos) return responder({ error: 'Sin permiso' }, 403);

    const { accion, nombre_completo, rol, clave, usuario_id } = await req.json();

    if (clave && (typeof clave !== 'string' || clave.length < 6)) {
      return responder({ error: 'La clave debe tener al menos 6 caracteres' }, 400);
    }

    if (accion === 'crear') {
      if (!nombre_completo || !rol || !clave) return responder({ error: 'Datos incompletos' }, 400);
      if (!permitidos.includes(rol)) {
        return responder({ error: `No puedes crear usuarios con el rol «${rol}»` }, 403);
      }

      const usuario = normalizar(nombre_completo);
      if (!usuario) return responder({ error: 'Nombre inválido' }, 400);

      const { data: existe } = await admin
        .from('perfiles').select('id').eq('usuario', usuario).maybeSingle();
      if (existe) {
        return responder({ error: 'Ya existe un usuario con ese nombre. Agrega el segundo apellido.' }, 409);
      }

      const { data: creado, error } = await admin.auth.admin.createUser({
        email: `${usuario}@${DOMINIO}`,
        password: clave,
        email_confirm: true,
      });
      if (error || !creado.user) return responder({ error: error?.message || 'Error al crear usuario' }, 400);

      const { error: errorPerfil } = await admin.from('perfiles').insert({
        id: creado.user.id, nombre_completo, usuario, rol,
      });

      if (errorPerfil) {
        await admin.auth.admin.deleteUser(creado.user.id);
        return responder({ error: errorPerfil.message }, 400);
      }
      return responder({ ok: true, usuario });
    }

    if (accion === 'cambiar_clave') {
      if (!usuario_id || !clave) return responder({ error: 'Faltan datos' }, 400);

      const { data: objetivo } = await admin
        .from('perfiles').select('rol').eq('id', usuario_id).single();
      if (!objetivo) return responder({ error: 'Usuario no encontrado' }, 404);

      if (!permitidos.includes(objetivo.rol)) {
        return responder({ error: `Sin permiso sobre un usuario con rol «${objetivo.rol}»` }, 403);
      }

      const { error } = await admin.auth.admin.updateUserById(usuario_id, { password: clave });
      if (error) return responder({ error: error.message }, 400);

      return responder({ ok: true });
    }

    return responder({ error: 'Acción desconocida' }, 400);

  } catch (err: any) {
    return responder({ error: err.message || 'Error interno' }, 500);
  }
});