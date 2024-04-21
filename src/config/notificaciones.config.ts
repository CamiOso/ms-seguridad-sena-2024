export namespace ConfiguracionNotificaciones {

  export const asunto2fa:string="Codigo de Verificacion";
  export const urlNotificaciones2fa:string="http://localhost:5187/Notificaciones/enviar-correo-2fa";
  export const urlNotificacionesSms:string="http://localhost:5187/Notificaciones/enviar-sms";
  export const urlValidacionCorreoFrontend:string="http://localhost:4200/seguridad/validar-hash-usuario-publico/";
  export const asuntoVerificacionCorreo: string = "Verificación de correo";
  export const claveAsignada: string = "Asignación de Clave";
}
