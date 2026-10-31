-- Check-out y solicitud de limpieza requieren una sesión autenticada.
-- Se mantienen SECURITY INVOKER para respetar RLS y los permisos reales
-- del usuario que inició sesión.
BEGIN;

REVOKE ALL ON FUNCTION public.hacer_check_out(uuid,text,text)
  FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.hacer_check_out(uuid,text,text)
  TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.pedir_limpieza(uuid,text)
  FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.pedir_limpieza(uuid,text)
  TO authenticated, service_role;

COMMIT;
