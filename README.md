## checkpwn ![Build Status](https://travis-ci.org/brycx/checkpwn.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/checkpwn/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/checkpwn)
Check [Have I Been Pwned](https://haveibeenpwned.com/) and see if it's time for you to change passwords.


### Getting started

#### Install:
```
cargo install checkpwn
```

#### Update:
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

_NOTE: List files must have the .ls file extension._

When checking accounts, they will be run against both the HIBP "paste" and "account" database.

#### Check a password:
```
checkpwn pass
```

### License
checkpwn is licensed under the MIT license. See the `LICENSE` file for more information.
