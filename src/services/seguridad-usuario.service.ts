import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {Usuario} from '../models/usuario.model';
import {repository} from '@loopback/repository';
import {LoginRepository, RolMenuRepository, RolRepository, UsuarioRepository} from '../repositories';
import {Credenciales, FactorDeAutenticacionPorCodigo, Login, RolMenu} from '../models';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
const generator = require('generate-password');
const md5 = require('crypto-js/md5');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository (LoginRepository)
    public repositorioLogin:LoginRepository,
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository,
  ) {}

  /**
   * Crear una clave aleatoria
   * @returns cadena aleatoria de n caracteres
   *
   */

  crearTextoAleatorio(n:number): string {
    let clave = generator.generate({
      length: n,
      numbers: true,
    });

    return clave;
  }

  /**
   *
   * @param cadena texto a cifrar
   * @returns cadena cifrada con md5
   */
  cifrarTexto(cadena: string): string {
    let cadenaCifrada = md5(cadena).toString();
    return cadenaCifrada;
  }


  /**
   * Se busca un usuario por sus credenciales de acceso
   * @param credenciales
   *
   * @returns usuario encontrado o null
   */

  async identificarUsuario(credenciales: Credenciales): Promise< Usuario | null> {
    let usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave,
        estadoValidacion: true,
        aceptado: true,
      },
    });

    return usuario as Usuario;

  }


  /**
   *  valida un codigo de 2fa para un usuario
   * @param credenciales2fa credenciales del usuario con el codigo del 2fa
   * @returns el registro de login o null
   */

  async validarCodigo2fa(credenciales2fa:FactorDeAutenticacionPorCodigo):Promise <Usuario|null >{
     let login=await this.repositorioLogin.findOne({
      where:{
        usuarioId:credenciales2fa.usuarioId,
        codigo2fa:credenciales2fa.codigo2fa,
        estadoCodigo2fa:false
      }
     });
     if(login){
      let usuario= await this.repositorioUsuario.findById(credenciales2fa.usuarioId);
      return usuario;
     }
     return null;


  }

  crearToken(usuario:Usuario):string{

    let datos={
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}` ,
      role:usuario.rolId,
      email:usuario.correo
    }
    let  token = jwt.sign(datos, ConfiguracionSeguridad.claveJWT);
    return token;
  }


  /**
   * valida y obtiene el rol de un  token
   * @param tk
   * @returns el _id del rol
   */
  obtenerRolDesdeToken(tk:string):string{
    let obj=jwt.verify(tk,ConfiguracionSeguridad.claveJWT);
    return obj.role;

  }



  /**
   * Retorna los permiso del rol
   * @param idRol id del rol a buscar y que esta asociado al usuario
   */

  async ConsultaPermisosDeMenuPorUsuario(idRol:string):Promise <RolMenu[ ]>{

   let menu:RolMenu[ ]=await this.repositorioRolMenu.find({
      where:{
         listar:true,
         rolId:idRol
      }
   })

   return menu;


  }
}
