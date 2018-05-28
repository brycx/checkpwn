## checkpwn
Check [Have I Been Pwned](https://haveibeenpwned.com/) and see if it's time for you to change passwords.

### Getting started

#### Install
```cargo install checkpwn```

#### Check an account, or list of accounts, for breaches:
```checkpwn acc test@example.com```

```checkpwn acc daily_breach_check.ls```

_NOTE: List files must have the .ls file exstension._

#### Check a password
```checkpwn pass qwerty```

_NOTE: Passwords are hashed with SHA1 before calling the Have I Been Pwned API.
They store passwords as SHA1 hashes and will compute it themselves if this tool didn't.
If the password you want to check, is a SHA1 hash in itself, the `sha1pass` argument
should be used instead:_ ```checkpwn sha1pass b1b3773a05c0ed0176787a4f1574ff0075f7521e```

### License
checkpwn is licensed under the MIT license. See the `LICENSE` file for more information.
