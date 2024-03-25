import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {Usuario} from '../models/usuario.model';
import {repository} from '@loopback/repository';
import {UsuarioRepository} from '../repositories';
import {Credenciales} from '../models';
const generator = require('generate-password');
const md5 = require('crypto-js/md5');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
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
      },
    });

    return usuario as Usuario;

  }
}
