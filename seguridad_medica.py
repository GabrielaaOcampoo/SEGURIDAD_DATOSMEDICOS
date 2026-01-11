"""
Sistema de Seguridad Digital para Proyectos de Ciencia de Datos Médicos
Implementa: Cifrado, Pseudonimización y Control de Acceso

Autor: [Tu nombre]
Fecha: Enero 2026
Curso: Cultura Digital y Sociedad - Ciencia de Datos
"""

# ============================================================================
# PARTE 1: CIFRADO DE DATOS SENSIBLES
# ============================================================================

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

class CifradoDatosMedicos:
    """
    Clase para cifrar y descifrar datos sensibles de pacientes
    usando AES-256 mediante Fernet
    """
    
    def __init__(self, password: str):
        """
        Inicializa el sistema de cifrado con una contraseña maestra
        
        Args:
            password: Contraseña para derivar la clave de cifrado
        """
        self.password = password.encode()
        self.salt = b'salt_medico_2026'  # En producción, usar os.urandom(16)
        self.key = self._derivar_clave()
        self.cipher = Fernet(self.key)
    
    def _derivar_clave(self) -> bytes:
        """Deriva una clave criptográfica robusta desde la contraseña"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,  # Recomendación OWASP 2024
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def cifrar_dato(self, dato: str) -> str:
        """
        Cifra un dato sensible
        
        Args:
            dato: Texto plano a cifrar
            
        Returns:
            Dato cifrado en formato string
        """
        dato_bytes = dato.encode()
        dato_cifrado = self.cipher.encrypt(dato_bytes)
        return dato_cifrado.decode()
    
    def descifrar_dato(self, dato_cifrado: str) -> str:
        """
        Descifra un dato previamente cifrado
        
        Args:
            dato_cifrado: Dato cifrado
            
        Returns:
            Texto plano original
        """
        dato_cifrado_bytes = dato_cifrado.encode()
        dato_descifrado = self.cipher.decrypt(dato_cifrado_bytes)
        return dato_descifrado.decode()
    
    def cifrar_registro_medico(self, registro: dict) -> dict:
        """
        Cifra campos sensibles de un registro médico completo
        
        Args:
            registro: Diccionario con datos del paciente
            
        Returns:
            Registro con campos sensibles cifrados
        """
        # Campos que deben cifrarse
        campos_sensibles = ['nombre', 'cedula', 'direccion', 'telefono', 
                           'diagnostico', 'tratamiento']
        
        registro_cifrado = registro.copy()
        
        for campo in campos_sensibles:
            if campo in registro_cifrado:
                registro_cifrado[campo] = self.cifrar_dato(str(registro_cifrado[campo]))
        
        return registro_cifrado


# Ejemplo de uso del cifrado
print("=" * 70)
print("DEMOSTRACIÓN 1: CIFRADO DE DATOS SENSIBLES")
print("=" * 70)

# Crear instancia del sistema de cifrado
cifrador = CifradoDatosMedicos(password="Clave_Segura_Hospital_2026!")

# Ejemplo 1: Cifrar un dato individual
nombre_original = "Juan Pérez García"
nombre_cifrado = cifrador.cifrar_dato(nombre_original)
nombre_descifrado = cifrador.descifrar_dato(nombre_cifrado)

print(f"\n✓ Cifrado de dato individual:")
print(f"  Original:    {nombre_original}")
print(f"  Cifrado:     {nombre_cifrado[:50]}...")
print(f"  Descifrado:  {nombre_descifrado}")

# Ejemplo 2: Cifrar un registro médico completo
registro_paciente = {
    'id': 'P001',
    'nombre': 'María López Fernández',
    'cedula': '1234567890',
    'edad': 45,
    'direccion': 'Av. Principal 123, Quito',
    'telefono': '0998765432',
    'diagnostico': 'Diabetes tipo 2',
    'tratamiento': 'Metformina 850mg',
    'fecha_ingreso': '2026-01-10'
}

print(f"\n✓ Cifrado de registro médico completo:")
print(f"\n  ANTES DEL CIFRADO:")
for campo, valor in registro_paciente.items():
    print(f"    {campo}: {valor}")

registro_cifrado = cifrador.cifrar_registro_medico(registro_paciente)

print(f"\n  DESPUÉS DEL CIFRADO:")
for campo, valor in registro_cifrado.items():
    if isinstance(valor, str) and len(valor) > 50:
        print(f"    {campo}: {valor[:50]}... [CIFRADO]")
    else:
        print(f"    {campo}: {valor}")


# ============================================================================
# PARTE 2: PSEUDONIMIZACIÓN Y ANONIMIZACIÓN
# ============================================================================

import hashlib
import pandas as pd
import numpy as np
from faker import Faker
from datetime import datetime, timedelta

class PseudonimizacionDatos:
    """
    Clase para pseudonimizar y anonimizar datos de pacientes
    manteniendo la utilidad analítica
    """
    
    def __init__(self, seed=42):
        """
        Inicializa el sistema de pseudonimización
        
        Args:
            seed: Semilla para reproducibilidad
        """
        self.fake = Faker('es_ES')
        Faker.seed(seed)
        np.random.seed(seed)
    
    def pseudonimizar_identificador(self, identificador: str, salt: str = "salt2026") -> str:
        """
        Pseudonimiza un identificador usando hash SHA-256
        
        Args:
            identificador: ID original del paciente
            salt: Sal criptográfica para el hash
            
        Returns:
            Hash pseudonimizado
        """
        dato_con_salt = f"{identificador}{salt}"
        hash_obj = hashlib.sha256(dato_con_salt.encode())
        return hash_obj.hexdigest()[:16]  # Primeros 16 caracteres
    
    def generar_nombre_sintetico(self) -> str:
        """Genera un nombre sintético realista"""
        return self.fake.name()
    
    def generalizar_edad(self, edad: int, rango: int = 10) -> str:
        """
        Generaliza la edad en rangos
        
        Args:
            edad: Edad exacta
            rango: Amplitud del rango
            
        Returns:
            Rango de edad (ej: "40-50")
        """
        inicio = (edad // rango) * rango
        fin = inicio + rango
        return f"{inicio}-{fin}"
    
    def generalizar_fecha(self, fecha: str, precision: str = 'mes') -> str:
        """
        Reduce la precisión temporal de una fecha
        
        Args:
            fecha: Fecha en formato YYYY-MM-DD
            precision: 'mes' o 'año'
            
        Returns:
            Fecha generalizada
        """
        try:
            fecha_obj = datetime.strptime(fecha, '%Y-%m-%d')
            if precision == 'mes':
                return fecha_obj.strftime('%Y-%m')
            elif precision == 'año':
                return fecha_obj.strftime('%Y')
            return fecha
        except:
            return fecha
    
    def agregar_ruido_numerico(self, valor: float, porcentaje: float = 0.05) -> float:
        """
        Agrega ruido estadístico controlado a un valor numérico
        
        Args:
            valor: Valor original
            porcentaje: Porcentaje de ruido (0.05 = 5%)
            
        Returns:
            Valor con ruido agregado
        """
        ruido = np.random.normal(0, valor * porcentaje)
        return round(valor + ruido, 2)
    
    def anonimizar_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aplica técnicas de anonimización a un dataset completo
        
        Args:
            df: DataFrame con datos de pacientes
            
        Returns:
            DataFrame anonimizado
        """
        df_anonimizado = df.copy()
        
        # Pseudonimizar IDs
        if 'id' in df_anonimizado.columns:
            df_anonimizado['id_pseudonimo'] = df_anonimizado['id'].apply(
                self.pseudonimizar_identificador
            )
            df_anonimizado = df_anonimizado.drop('id', axis=1)
        
        # Nombres sintéticos
        if 'nombre' in df_anonimizado.columns:
            df_anonimizado['nombre_sintetico'] = [
                self.generar_nombre_sintetico() 
                for _ in range(len(df_anonimizado))
            ]
            df_anonimizado = df_anonimizado.drop('nombre', axis=1)
        
        # Generalizar edad
        if 'edad' in df_anonimizado.columns:
            df_anonimizado['rango_edad'] = df_anonimizado['edad'].apply(
                self.generalizar_edad
            )
            df_anonimizado = df_anonimizado.drop('edad', axis=1)
        
        # Generalizar fechas
        if 'fecha_ingreso' in df_anonimizado.columns:
            df_anonimizado['periodo_ingreso'] = df_anonimizado['fecha_ingreso'].apply(
                lambda x: self.generalizar_fecha(x, 'mes')
            )
            df_anonimizado = df_anonimizado.drop('fecha_ingreso', axis=1)
        
        # Agregar ruido a valores numéricos de laboratorio
        columnas_numericas = ['glucosa', 'presion_sistolica', 'presion_diastolica']
        for col in columnas_numericas:
            if col in df_anonimizado.columns:
                df_anonimizado[col] = df_anonimizado[col].apply(
                    self.agregar_ruido_numerico
                )
        
        return df_anonimizado


# Ejemplo de uso de pseudonimización
print("\n\n" + "=" * 70)
print("DEMOSTRACIÓN 2: PSEUDONIMIZACIÓN Y ANONIMIZACIÓN")
print("=" * 70)

# Crear instancia del sistema de pseudonimización
pseudonimizador = PseudonimizacionDatos(seed=42)

# Ejemplo 1: Pseudonimizar identificador
print(f"\n✓ Pseudonimización de identificador:")
id_original = "PAC-2026-001234"
id_pseudo = pseudonimizador.pseudonimizar_identificador(id_original)
print(f"  ID Original:      {id_original}")
print(f"  ID Pseudonimizado: {id_pseudo}")

# Ejemplo 2: Generalización de edad
print(f"\n✓ Generalización de edad:")
edad_exacta = 47
rango_edad = pseudonimizador.generalizar_edad(edad_exacta)
print(f"  Edad exacta:  {edad_exacta} años")
print(f"  Rango edad:   {rango_edad} años")

# Ejemplo 3: Anonimizar dataset completo
print(f"\n✓ Anonimización de dataset completo:")

# Crear dataset de ejemplo
datos_pacientes = pd.DataFrame({
    'id': ['PAC001', 'PAC002', 'PAC003', 'PAC004', 'PAC005'],
    'nombre': ['Juan Pérez', 'María García', 'Carlos López', 
               'Ana Martínez', 'Luis Rodríguez'],
    'edad': [45, 52, 38, 61, 29],
    'glucosa': [120, 156, 98, 180, 92],
    'presion_sistolica': [130, 145, 118, 160, 115],
    'presion_diastolica': [85, 92, 75, 95, 70],
    'fecha_ingreso': ['2026-01-10', '2026-01-11', '2026-01-12', 
                      '2026-01-13', '2026-01-14']
})

print(f"\n  DATASET ORIGINAL:")
print(datos_pacientes.to_string(index=False))

datos_anonimizados = pseudonimizador.anonimizar_dataset(datos_pacientes)

print(f"\n  DATASET ANONIMIZADO:")
print(datos_anonimizados.to_string(index=False))


# ============================================================================
# PARTE 3: CONTROL DE ACCESO BASADO EN ROLES
# ============================================================================

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class SistemaControlAcceso:
    """
    Sistema de control de acceso basado en roles (RBAC) con autenticación
    """
    
    def __init__(self):
        """Inicializa el sistema de control de acceso"""
        self.usuarios = {}
        self.sesiones_activas = {}
        self.intentos_fallidos = {}
        self.log_auditoria = []
        
        # Definir roles y permisos
        self.roles_permisos = {
            'administrador': [
                'acceso_total', 'gestionar_usuarios', 'ver_logs',
                'modificar_datos', 'entrenar_modelos', 'exportar_datos'
            ],
            'cientifico_datos': [
                'ver_datos_pseudonimizados', 'entrenar_modelos', 
                'ejecutar_notebooks', 'ver_metricas'
            ],
            'analista': [
                'ver_datos_agregados', 'ver_visualizaciones', 'generar_reportes'
            ],
            'medico': [
                'consultar_predicciones', 'ver_pacientes_asignados'
            ],
            'auditor': [
                'ver_logs', 'ver_metricas', 'generar_reportes'
            ]
        }
    
    def _hashear_password(self, password: str, salt: str = None) -> tuple:
        """
        Hashea una contraseña usando PBKDF2-HMAC-SHA256
        
        Args:
            password: Contraseña en texto plano
            salt: Sal criptográfica (se genera si no se proporciona)
            
        Returns:
            Tupla (hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # Número de iteraciones
        )
        return password_hash.hex(), salt
    
    def crear_usuario(self, username: str, password: str, rol: str) -> bool:
        """
        Crea un nuevo usuario en el sistema
        
        Args:
            username: Nombre de usuario
            password: Contraseña
            rol: Rol asignado
            
        Returns:
            True si se creó exitosamente
        """
        if username in self.usuarios:
            print(f"✗ Error: El usuario '{username}' ya existe")
            return False
        
        if rol not in self.roles_permisos:
            print(f"✗ Error: Rol '{rol}' no válido")
            return False
        
        password_hash, salt = self._hashear_password(password)
        
        self.usuarios[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'rol': rol,
            'fecha_creacion': datetime.now(),
            'activo': True
        }
        
        self._registrar_auditoria('CREAR_USUARIO', username, 
                                 f"Usuario creado con rol {rol}")
        return True
    
    def autenticar(self, username: str, password: str) -> Optional[str]:
        """
        Autentica un usuario y crea una sesión
        
        Args:
            username: Nombre de usuario
            password: Contraseña
            
        Returns:
            Token de sesión si es exitoso, None si falla
        """
        # Verificar bloqueo por intentos fallidos
        if username in self.intentos_fallidos:
            if self.intentos_fallidos[username] >= 3:
                self._registrar_auditoria('AUTENTICACION_BLOQUEADA', username,
                                        "Cuenta bloqueada por intentos fallidos")
                print(f"✗ Cuenta bloqueada. Demasiados intentos fallidos.")
                return None
        
        # Verificar usuario existe
        if username not in self.usuarios:
            self._registrar_intento_fallido(username)
            self._registrar_auditoria('AUTENTICACION_FALLIDA', username,
                                     "Usuario no existe")
            return None
        
        usuario = self.usuarios[username]
        
        # Verificar usuario activo
        if not usuario['activo']:
            self._registrar_auditoria('AUTENTICACION_FALLIDA', username,
                                     "Usuario inactivo")
            return None
        
        # Verificar contraseña
        password_hash, _ = self._hashear_password(password, usuario['salt'])
        
        if password_hash != usuario['password_hash']:
            self._registrar_intento_fallido(username)
            self._registrar_auditoria('AUTENTICACION_FALLIDA', username,
                                     "Contraseña incorrecta")
            return None
        
        # Autenticación exitosa - crear sesión
        token = secrets.token_urlsafe(32)
        self.sesiones_activas[token] = {
            'username': username,
            'rol': usuario['rol'],
            'inicio': datetime.now(),
            'expira': datetime.now() + timedelta(hours=8)
        }
        
        # Limpiar intentos fallidos
        if username in self.intentos_fallidos:
            del self.intentos_fallidos[username]
        
        self._registrar_auditoria('AUTENTICACION_EXITOSA', username,
                                 "Sesión iniciada")
        return token
    
    def _registrar_intento_fallido(self, username: str):
        """Registra un intento fallido de autenticación"""
        if username not in self.intentos_fallidos:
            self.intentos_fallidos[username] = 0
        self.intentos_fallidos[username] += 1
    
    def verificar_permiso(self, token: str, permiso: str) -> bool:
        """
        Verifica si un usuario tiene un permiso específico
        
        Args:
            token: Token de sesión
            permiso: Permiso a verificar
            
        Returns:
            True si tiene el permiso
        """
        if token not in self.sesiones_activas:
            return False
        
        sesion = self.sesiones_activas[token]
        
        # Verificar expiración
        if datetime.now() > sesion['expira']:
            self._registrar_auditoria('SESION_EXPIRADA', sesion['username'],
                                     "Token expirado")
            del self.sesiones_activas[token]
            return False
        
        rol = sesion['rol']
        tiene_permiso = permiso in self.roles_permisos[rol]
        
        resultado = "PERMITIDO" if tiene_permiso else "DENEGADO"
        self._registrar_auditoria(f'ACCESO_{resultado}', sesion['username'],
                                 f"Permiso: {permiso}")
        
        return tiene_permiso
    
    def cerrar_sesion(self, token: str) -> bool:
        """Cierra una sesión activa"""
        if token in self.sesiones_activas:
            username = self.sesiones_activas[token]['username']
            del self.sesiones_activas[token]
            self._registrar_auditoria('CERRAR_SESION', username,
                                     "Sesión cerrada")
            return True
        return False
    
    def _registrar_auditoria(self, evento: str, usuario: str, detalles: str):
        """Registra eventos en el log de auditoría"""
        registro = {
            'timestamp': datetime.now(),
            'evento': evento,
            'usuario': usuario,
            'detalles': detalles
        }
        self.log_auditoria.append(registro)
    
    def obtener_log_auditoria(self, ultimos: int = 10) -> List[Dict]:
        """Obtiene los últimos registros del log de auditoría"""
        return self.log_auditoria[-ultimos:]


# Ejemplo de uso del sistema de control de acceso
print("\n\n" + "=" * 70)
print("DEMOSTRACIÓN 3: CONTROL DE ACCESO BASADO EN ROLES")
print("=" * 70)

# Crear instancia del sistema
sistema = SistemaControlAcceso()

# Crear usuarios con diferentes roles
print(f"\n✓ Creación de usuarios:")
sistema.crear_usuario('admin_hospital', 'Admin2026!', 'administrador')
sistema.crear_usuario('dr_martinez', 'Medico2026!', 'cientifico_datos')
sistema.crear_usuario('analista_lopez', 'Analista2026!', 'analista')
sistema.crear_usuario('dr_garcia', 'Doctor2026!', 'medico')

print(f"  • admin_hospital (administrador)")
print(f"  • dr_martinez (cientifico_datos)")
print(f"  • analista_lopez (analista)")
print(f"  • dr_garcia (medico)")

# Autenticar usuarios
print(f"\n✓ Autenticación de usuarios:")
token_admin = sistema.autenticar('admin_hospital', 'Admin2026!')
token_cientifico = sistema.autenticar('dr_martinez', 'Medico2026!')
token_analista = sistema.autenticar('analista_lopez', 'Analista2026!')

print(f"  • admin_hospital: {'✓ Autenticado' if token_admin else '✗ Fallido'}")
print(f"  • dr_martinez: {'✓ Autenticado' if token_cientifico else '✗ Fallido'}")
print(f"  • analista_lopez: {'✓ Autenticado' if token_analista else '✗ Fallido'}")

# Probar intento fallido
print(f"\n✓ Prueba de autenticación fallida:")
token_falso = sistema.autenticar('dr_martinez', 'password_incorrecta')

# Verificar permisos
print(f"\n✓ Verificación de permisos:")

permisos_prueba = [
    ('admin_hospital', token_admin, 'gestionar_usuarios'),
    ('admin_hospital', token_admin, 'entrenar_modelos'),
    ('dr_martinez', token_cientifico, 'entrenar_modelos'),
    ('dr_martinez', token_cientifico, 'gestionar_usuarios'),
    ('analista_lopez', token_analista, 'ver_datos_agregados'),
    ('analista_lopez', token_analista, 'modificar_datos')
]

for usuario, token, permiso in permisos_prueba:
    tiene = sistema.verificar_permiso(token, permiso)
    simbolo = "✓" if tiene else "✗"
    print(f"  {simbolo} {usuario}: {permiso} - {'PERMITIDO' if tiene else 'DENEGADO'}")

# Mostrar log de auditoría
print(f"\n✓ Log de auditoría (últimos 8 registros):")
logs = sistema.obtener_log_auditoria(ultimos=8)
for log in logs:
    tiempo = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    print(f"  [{tiempo}] {log['evento']:<25} | {log['usuario']:<20} | {log['detalles']}")

print("\n" + "=" * 70)
print("FIN DE LA DEMOSTRACIÓN")
print("=" * 70)
