use std::{
    fs,
    path::{Path, PathBuf}
};

// There might be a better approach here to handling configuration
// directories across platform. The crate `directories` looks like a nice
// option, but I noticed it had some `panics!()` within the code base.
const CHECKPWN_CONFIG_FILE_NAME: &str = "checkpwn.yml";
const CHECKPWN_CONFIG_DIR: &str = "checkpwn";

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

    pub fn get_or_build_path(&self) -> Result<ConfigPaths, ()> {
        // referenced from https://github.com/Rigellute/spotify-tui/blob/master/src/config.rs
        // I found it difficult to use the `directories` crate -- particularly converting the
        // `ProjectDirs` type to a `Path` type or a string
        match dirs::config_dir() {
            Some(config_dir) => {
                let path = Path::new(&config_dir);
                let app_config_dir = path.join(CHECKPWN_CONFIG_DIR);

                if !app_config_dir.exists() {
                    match fs::create_dir_all(&app_config_dir) {
                        Ok(path) => println!("Successfully created checkpwn configuration directories at {:?}", path),
                        Err(e) => {
                            panic!("Error creating checkpwn configuration directories: {:?}", e)
                        }
                    }
                }
                let config_file_path = &app_config_dir.join(CHECKPWN_CONFIG_FILE_NAME);

                let paths = ConfigPaths {
                    config_file_path: config_file_path.to_path_buf(),
                };

                Ok(paths)
            }
            // is there a better way to handle this failure?
            None => panic!("Could not find path for configuration file."),
        }
    }

    pub fn load_config(&mut self) {
        let path = match self.get_or_build_path() {
            Ok(p) => p,
            Err(e) => { panic!("Error retrieving configuration path: {:?}", e)}
        };




        if path.config_file_path.exists() {
            let config_string = match fs::read_to_string(&path.config_file_path.to_str().unwrap()) {
                Ok(p) => p,
                Err(e) => { panic!("Error parsing path of configuration file to string: {:?}", e)}
            };

            //TODO: handle the `std::result::Result` returned from `serde_yaml::from_str`
            //let config_yml: Config = serde_yaml::from_str(&config_string);
        }

    }
}
