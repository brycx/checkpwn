extern crate serde;
extern crate dirs;
extern crate serde_yaml;

use std::{
    fs,
    io,
    io::{Write},
    path::{Path, PathBuf}
};
use self::serde::{Serialize, Deserialize};
use self::dirs::{config_dir};

const CHECKPWN_CONFIG_FILE_NAME: &str = "checkpwn.yml";
const CHECKPWN_CONFIG_DIR: &str = "checkpwn";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub api_key: String
}

#[derive(Debug)]
pub struct ConfigPaths {
    pub config_file_path: PathBuf,
}

impl Config {
    pub fn new() -> Config {
        Config {
            api_key: "".to_string()
        }
    }
    
    fn get_config_path(&self) -> Option<ConfigPaths> {
        match config_dir() {
            Some(mut dir) => {
                dir.push(CHECKPWN_CONFIG_DIR);
                dir.push(CHECKPWN_CONFIG_FILE_NAME);
                Some(
                    ConfigPaths {
                        config_file_path: dir.to_path_buf()
                    }
                )
            }
            None => None
        }
    }

    fn build_path(&self) -> Result<(), io::Error> {
        let mut path = self.get_config_path().expect("Failed to determine configuration file path.");
        path.config_file_path.pop(); //remove the filename so we don't accidentally create it as a directory
        fs::create_dir_all(&path.config_file_path).unwrap();
        Ok(())
    }

    pub fn load_config(&mut self) {
        let path = self.get_config_path().expect("Failed to determine configuration file path.");
        let config_string = fs::read_to_string(&path.config_file_path).unwrap();
        let config_yml: Config = serde_yaml::from_str(&config_string).unwrap();

        self.api_key = config_yml.api_key;
    }

    pub fn save_config(&self, api_key: &String) -> Result<(), io::Error> {
        let path: ConfigPaths = self.get_config_path().expect("Failed to determine configuration file path.");

        if !path.config_file_path.exists() {
            self.build_path().unwrap();
            let new_config = serde_yaml::to_vec(&api_key).unwrap();
            let mut config_file = fs::File::create(&path.config_file_path).unwrap();
            config_file.write_all(&new_config).unwrap();
        } else {
            print!("Configuration already exists.");
            // The configuration file already exists
            // Ask user if we want to overwrite it...
        }
        Ok(())
    }
}