extern crate dirs_next;
extern crate serde;
extern crate serde_yaml;

use self::dirs_next::config_dir;
use self::serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};

const CHECKPWN_CONFIG_FILE_NAME: &str = "checkpwn.yml";
const CHECKPWN_CONFIG_DIR: &str = "checkpwn";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub api_key: String,
}

#[derive(Debug)]
pub struct ConfigPaths {
    pub config_file_path: PathBuf,
}

impl Config {
    pub fn new() -> Config {
        Config {
            api_key: "".to_string(),
        }
    }

    pub fn get_config_path(&self) -> Option<ConfigPaths> {
        match config_dir() {
            Some(mut dir) => {
                dir.push(CHECKPWN_CONFIG_DIR);
                dir.push(CHECKPWN_CONFIG_FILE_NAME);
                Some(ConfigPaths {
                    config_file_path: dir,
                })
            }
            None => None,
        }
    }

    fn build_path(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut path = self
            .get_config_path()
            .expect("Failed to determine configuration file path.");
        path.config_file_path.pop(); //remove the filename so we don't accidentally create it as a directory
        fs::create_dir_all(&path.config_file_path)?;
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn load_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // If in CI, the key is in env. Local tests use the config file.
        match std::env::var("API_KEY") {
            Ok(api_key) => {
                self.api_key = api_key;
                Ok(())
            }
            Err(std::env::VarError::NotPresent) => {
                let path = self
                    .get_config_path()
                    .expect("Failed to determine configuration file path.");
                let config_string = fs::read_to_string(&path.config_file_path)?;
                let config_yml: Config = serde_yaml::from_str(&config_string)?;

                self.api_key = config_yml.api_key;
                Ok(())
            }
            _ => panic!("CI API KEY WAS NOT UTF8"),
        }
    }

    #[cfg(not(debug_assertions))]
    pub fn load_config(&mut self) {
        let path = self
            .get_config_path()
            .expect("Failed to determine configuration file path.");
        let config_string = fs::read_to_string(&path.config_file_path)?;
        let config_yml: Config = serde_yaml::from_str(&config_string)?;

        self.api_key = config_yml.api_key;
    }

    pub fn save_config(&self, api_key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path: ConfigPaths = self
            .get_config_path()
            .expect("Failed to determine configuration file path.");

        self.build_path()?;
        let new_config = Config {
            api_key: api_key.to_string(),
        };

        let config_to_write = serde_yaml::to_vec(&new_config)?;
        let mut config_file = fs::File::create(&path.config_file_path)?;
        config_file.write_all(&config_to_write)?;

        Ok(())
    }
}
