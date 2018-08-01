## checkpwn
Check [Have I Been Pwned](https://haveibeenpwned.com/) and see if it's time for you to change passwords.


#### Usage demo

[![asciicast](https://asciinema.org/a/2LfYpj7V86CjbAB4tc2WcgJP6.png)](https://asciinema.org/a/2LfYpj7V86CjbAB4tc2WcgJP6)

### Getting started

#### Install
```
cargo install checkpwn
```

#### Update
```
cargo install --force checkpwn
```

#### Check an account, or list of accounts, for breaches:
```
checkpwn acc test@example.com
```

```
checkpwn acc daily_breach_check.ls
```

_NOTE: List files must have the .ls file exstension._

#### Check a password
```
checkpwn pass
```

### License
checkpwn is licensed under the MIT license. See the `LICENSE` file for more information.
