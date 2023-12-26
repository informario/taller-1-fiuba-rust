use std::io::{BufRead, Error, ErrorKind, Result};

/// Struct que se encarga de la carga de las variables de configuración.
#[derive(Debug, Clone)]
pub struct Config {
    pub direcciones_dns: Vec<String>,
    pub puertos_dns: Vec<String>,
    pub version_protocolo_handshake: i32,
    pub fecha_inicial_descarga_de_bloques: String,
    pub block_broadcasting: bool,
    pub ips: Vec<String>,
    pub ruta_claves_usuario: String,
    pub interfaz: String,
    pub nodo: String,
    pub logger_level: String,
    pub logger_file: String,
    pub starting_block_header_hash: [u8; 32],
    pub genesis_block_header_hash: [u8; 32],
    pub start_from_genesis: bool,
    pub active_peers: i32,
}

impl Config {
    /// Crea una nueva instancia de Config a partir de una estructura que implemente el trait BufRead.
    ///
    /// # Argumentos
    ///
    /// * `lector` - trait BufRead que contiene la configuración a cargar.
    ///
    /// # Ejemplo
    ///
    /// ```
    ///
    /// use bitcoin_node_rust::config::Config;
    ///
    /// use std::io::BufReader;
    ///
    /// let archivo_cfg = "Direcciones DNS: dns1.com, dns2.com
    /// Protocolo de version de handshake: 5
    /// Fecha inicial de descarga de bloques: 05/04/2023
    /// Transmision de bloques: on
    /// IPs: 127.0.0.1, 8.8.8.8
    /// Puertos DNS: 3000, 8080";
    /// let lector = BufReader::new(archivo_cfg.as_bytes());
    /// let config_result = Config::new(lector);
    /// assert!(config_result.is_ok());
    /// let config = config_result.unwrap();
    /// assert_eq!(
    ///     format!("{:?}", config),
    ///     "Config { direcciones_dns: [\"dns1.com\", \"dns2.com\"], puertos_dns: [\"3000\", \"8080\"], version_protocolo_handshake: 5, fecha_inicial_descarga_de_bloques: \"05/04/2023\", block_broadcasting: true, ips: [\"127.0.0.1\", \"8.8.8.8\"] }"
    /// );
    /// ```
    pub fn new<R: BufRead>(lector: R) -> Result<Self> {
        let mut config = Config {
            direcciones_dns: Vec::new(),
            puertos_dns: Vec::new(),
            version_protocolo_handshake: 0,
            fecha_inicial_descarga_de_bloques: String::new(),
            block_broadcasting: true,
            ips: Vec::new(),
            ruta_claves_usuario: String::new(),
            interfaz: String::new(),
            nodo: String::new(),
            logger_level: String::new(),
            logger_file: String::new(),
            starting_block_header_hash: [0; 32],
            genesis_block_header_hash: [0; 32],
            start_from_genesis: false,
            active_peers: 0,
        };
        config.cargar_configuracion(lector)?;
        Ok(config)
    }

    /// Crea una nueva instancia de Config a partir de un archivo de configuración.
    ///
    /// # Argumentos
    ///
    /// * `path` - Path del archivo de configuración.
    ///
    /// ```
    pub fn new_from_file_path(path: &str) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let lector = std::io::BufReader::new(file);
        Self::new(lector)
    }

    /// private Carga la configuración linea por linea desde una estructura que implemente el trait BufRead.
    ///
    /// # Argumentos
    ///
    /// * `lector` - trait BufRead que contiene la configuración a cargar.
    ///
    fn cargar_configuracion<R: BufRead>(&mut self, lector: R) -> Result<()> {
        for linea in lector.lines() {
            let linea = linea?;
            self.actualizar_config(&linea)?;
        }
        Ok(())
    }

    /// private actualiza el campo correspondiente de configuración basado en la línea que recibe como input.
    ///
    ///
    /// # Argumentos
    ///
    /// * `linea` - La línea de configuración a parsear.
    ///
    /// # Info
    ///
    /// Los campos que admiten mas de un valor, por ej direcciones de IP son recibidas con este formato
    /// IPs: ip1, ip2
    ///
    /// Los posibles campos a configurar (El nombre tiene que coincidir exacto. Es case sensitive):
    /// --------
    /// Direcciones DNS
    /// Protocolo de version de handshake
    /// Fecha inicial de descarga de bloques
    /// Transmision de bloques
    /// IPs
    /// Puertos DNS
    /// --------
    fn actualizar_config(&mut self, linea: &str) -> Result<()> {
        let linea_sin_espacios = linea.trim();
        let mut linea_en_array = linea_sin_espacios.split(": ");
        let nombre_campo = linea_en_array.next().ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "[CONFIG] Formato de linea invalido")
        })?;
        let valor_campo = linea_en_array
            .next()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidData,
                    "[CONFIG] Valor de campo no encontrado",
                )
            })?
            .trim();
        match nombre_campo {
            "Direcciones DNS" => self
                .direcciones_dns
                .extend(valor_campo.split(", ").map(|s| s.to_string())),
            "Protocolo de version de handshake" => {
                self.version_protocolo_handshake = valor_campo
                    .parse()
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
            }
            "Fecha inicial de descarga de bloques" => {
                self.fecha_inicial_descarga_de_bloques = valor_campo.to_string()
            }
            "Transmision de bloques" => {
                self.block_broadcasting = valor_campo.to_lowercase() == "on"
            }
            "IPs" => self
                .ips
                .extend(valor_campo.split(", ").map(|s| s.to_string())),
            "Puertos DNS" => self
                .puertos_dns
                .extend(valor_campo.split(", ").map(|s| s.to_string())),
            "Ruta claves usuario" => self.ruta_claves_usuario = valor_campo.to_string(),
            "Cargar interfaz" => self.interfaz = valor_campo.to_string(),
            "Cargar nodo" => self.nodo = valor_campo.to_string(),
            "Logger level" => self.logger_level = valor_campo.to_string(),
            "Logger file" => self.logger_file = valor_campo.to_string(),
            "Starting block header hash" => {
                self.starting_block_header_hash = Self::decode_hex(valor_campo)
            }
            "Genesis block header hash" => {
                self.genesis_block_header_hash = Self::decode_hex(valor_campo)
            }
            "Start from genesis" => self.start_from_genesis = valor_campo.to_lowercase() == "si",
            "Active peers" => {
                self.active_peers = valor_campo
                    .parse()
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn decode_hex(s: &str) -> [u8; 32] {
        let mut result = vec![];
        let elements = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16));
        for element in elements {
            match element {
                Ok(value) => result.push(value),
                Err(_) => {
                    return [0; 32];
                }
            }
        }
        result.try_into().unwrap_or([0; 32])
    }
    /// Imprime todos los campos configurados con su valor actual.
    ///
    /// # Ejemplo
    ///
    /// ```
    /// use bitcoin_node_rust::config::Config;
    /// use std::io::BufReader;
    ///
    /// let archivo_cfg = "Direcciones DNS: dns1.com, dns2.com
    /// Protocolo de version de handshake: 5
    /// Fecha inicial de descarga de bloques: 05/04/2023
    /// Transmision de bloques: on
    /// IPs: 127.0.0.1, 8.8.8.8
    /// Puertos DNS: 3000, 8080";
    /// let lector = BufReader::new(archivo_cfg.as_bytes());
    /// let configuracion = Config::new(lector).unwrap();
    /// configuracion.log();
    /// ```
    pub fn log(&self) -> String {
        //TODO: hacerlo generico para que imprima a cualqiera que implemente trait de escribir
        format!("[CONFIG] Direcciones leidas: {:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    const ARCHIVO_CFG: &str = "Direcciones DNS: dns1.com, dns2.com
        Protocolo de version de handshake: 5
        Fecha inicial de descarga de bloques: 05/04/2023
        Transmision de bloques: on
        IPs: 127.0.0.1, 8.8.8.8
        Puertos DNS: 3000, 8080
        Cargar interfaz: Si
        Cargar nodo: Si";
    #[test]
    fn test_actualizar_config_con_linea_invalida_y_sin_campos_a_configurar_devuelve_error() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let resultado = config.actualizar_config("Nada para configurar");
        assert!(resultado.is_err());
        let error = resultado.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "[CONFIG] Valor de campo no encontrado");
    }

    #[test]
    fn test_actualizar_config_con_linea_vacia_devuelve_error() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let resultado = config.actualizar_config("");
        assert!(resultado.is_err());
        let error = resultado.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "[CONFIG] Valor de campo no encontrado");
    }

    #[test]
    fn test_actualizar_config_con_linea_valida_pero_sin_campos_a_configurar_devuelve_error() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let resultado = config.actualizar_config("Transmision de bloques:");
        assert!(resultado.is_err());
        let error = resultado.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "[CONFIG] Valor de campo no encontrado");
    }

    #[test]
    fn test_actualizar_config_con_direccion_dns_valida_y_campos_a_configurar_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let direcciones_dns: String = "Direcciones DNS: NUEVA_dns1.com, NUEVA_dns2.com".to_string();
        assert_ne!(
            config.direcciones_dns[config.direcciones_dns.len() - 1],
            "NUEVA_dns2.com"
        );
        assert_ne!(
            config.direcciones_dns[config.direcciones_dns.len() - 2],
            "NUEVA_dns1.com"
        );
        let resultado = config.actualizar_config(&direcciones_dns);
        assert!(resultado.is_ok());
        assert_eq!(
            config.direcciones_dns[config.direcciones_dns.len() - 1],
            "NUEVA_dns2.com"
        );
        assert_eq!(
            config.direcciones_dns[config.direcciones_dns.len() - 2],
            "NUEVA_dns1.com"
        );
    }

    #[test]
    fn test_actualizar_config_con_version_valida_y_campos_a_configurar_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let version: String = "Protocolo de version de handshake: 9".to_string();
        assert_ne!(config.version_protocolo_handshake, 9);
        let resultado = config.actualizar_config(&version);
        assert!(resultado.is_ok());
        assert_eq!(config.version_protocolo_handshake, 9);
    }

    #[test]
    fn test_actualizar_config_con_fecha_inicial_valida_y_campos_a_configurar_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let fecha_inicial: String = "Fecha inicial de descarga de bloques: 05/04/2024".to_string();
        assert_ne!(config.fecha_inicial_descarga_de_bloques, "05/04/2024");
        let resultado = config.actualizar_config(&fecha_inicial);
        assert!(resultado.is_ok());
        assert_eq!(config.fecha_inicial_descarga_de_bloques, "05/04/2024");
    }

    #[test]
    fn test_actualizar_config_con_switch_transmision_valida_y_campos_a_configurar_actualiza_la_config(
    ) {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let transmision: String = "Transmision de bloques: off".to_string();
        assert!(config.block_broadcasting);
        let resultado = config.actualizar_config(&transmision);
        assert!(resultado.is_ok());
        // block broadcasting es false
        assert!(!config.block_broadcasting);
    }

    #[test]
    fn test_actualizar_config_con_direccion_ip_valida_y_campos_a_configurar_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let direcciones_ip: String = "IPs: 111.222.333.444, 9.9.9.9".to_string();
        assert_ne!(config.ips[config.ips.len() - 1], "9.9.9.9");
        assert_ne!(config.ips[config.ips.len() - 2], "111.222.333.444");
        let resultado = config.actualizar_config(&direcciones_ip);
        assert!(resultado.is_ok());
        assert_eq!(config.ips[config.ips.len() - 1], "9.9.9.9");
        assert_eq!(config.ips[config.ips.len() - 2], "111.222.333.444");
    }

    #[test]
    fn test_actualizar_config_con_puertos_validos_y_campos_a_configurar_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let puertos: String = "Puertos: 4000, 9090".to_string();
        assert_ne!(config.puertos_dns[config.puertos_dns.len() - 1], "9090");
        assert_ne!(config.puertos_dns[config.puertos_dns.len() - 2], "4000");
        let resultado = config.actualizar_config(&puertos);
        assert!(resultado.is_ok());
        assert_eq!(config.puertos_dns[config.puertos_dns.len() - 1], "8080");
        assert_eq!(config.puertos_dns[config.puertos_dns.len() - 2], "3000");
    }

    #[test]
    fn test_actualizar_config_con_interfaz_habilitada_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let interfaz: String = "Cargar interfaz: No".to_string();
        assert_ne!(config.interfaz, "No");
        let resultado = config.actualizar_config(&interfaz);
        assert!(resultado.is_ok());
        assert_eq!(config.interfaz, "No");
    }

    #[test]
    fn test_actualizar_config_con_nodo_habilitado_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let nodo: String = "Cargar nodo: No".to_string();
        assert_ne!(config.nodo, "No");
        let resultado = config.actualizar_config(&nodo);
        assert!(resultado.is_ok());
        assert_eq!(config.nodo, "No");
    }

    #[test]
    fn test_actualizar_config_con_active_peers_actualiza_la_config() {
        let lector = BufReader::new(ARCHIVO_CFG.as_bytes());
        let config_result = Config::new(lector);
        assert!(config_result.is_ok());
        let mut config = config_result.unwrap();
        let active_peers: String = "Active peers: 9".to_string();
        assert_ne!(config.active_peers, 9);
        let resultado = config.actualizar_config(&active_peers);
        assert!(resultado.is_ok());
        assert_eq!(config.active_peers, 9);
    }
}
