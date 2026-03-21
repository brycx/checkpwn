## checkpwn ![Tests](https://github.com/brycx/checkpwn/workflows/Tests/badge.svg) ![Security Audit](https://github.com/brycx/checkpwn/workflows/Security%20Audit/badge.svg)

Check [Have I Been Pwned](https://haveibeenpwned.com/) and see if you need to change your passwords.

### Installation via Package Managers (Cargo or Homebrew)

Checkpwn is available from either Cargo or Homebrew for your convenience.

#### Cargo:
```
cargo install checkpwn
```
#### Homebrew:
```
brew install checkpwn
```
#### Update:
```
cargo install --force checkpwn
```
#### Register & update API key:
```
checkpwn register 123456789
```
This command creates a `checkpwn.yml` configuration file in the user's configuration directory and saves the API key. You must complete this step before making any calls to the account API (`checkpwn acc`).

#### Check an account, or list of accounts, for breaches:
```
checkpwn acc test@example.com
```
```
checkpwn acc daily_breach_check.ls
```
_NOTE: List files must have the .ls file extension._

When checking accounts, checkpwn runs them against both the HIBP "paste" and "account" databases.

#### Check a password:
```
checkpwn pass
```
### Changelog
See [here](https://github.com/brycx/checkpwn/releases).

### License
checkpwn is available under the MIT license. See the `LICENSE` file for more information.
