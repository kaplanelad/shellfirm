## Unreleased

* Add git-strict file commands. [PR-112](https://github.com/kaplanelad/shellfirm/pull/112)
* Add more git commands. [PR-112](https://github.com/kaplanelad/shellfirm/pull/112)
* Add Terraform commands. [PR-113](https://github.com/kaplanelad/shellfirm/pull/113)

## 0.2.5
IMPROVMENT
* create unites for regex checks. [PR-107](https://github.com/kaplanelad/shellfirm/pull/107)
* Remove contains method. [PR-108](https://github.com/kaplanelad/shellfirm/pull/108)
* check is folder or directory exists before prompt a message. [PR-109](https://github.com/kaplanelad/shellfirm/pull/109)

BRAKING CHANGES
* Change shellfirm configuration. [PR-103](https://github.com/kaplanelad/shellfirm/pull/103)

## 0.2.4
IMPROVMENT
* Check test. [PR-98](https://github.com/kaplanelad/shellfirm/pull/98)
* Remove vergen package. [PR-100](https://github.com/kaplanelad/shellfirm/pull/100)
* add .rustfmt.toml file. [PR-](https://github.com/kaplanelad/shellfirm/pull/101)

## 0.2.3
IMPROVMENT
* Support $XDG_CONFIG_HOME. [PR-87](https://github.com/kaplanelad/shellfirm/pull/87)
* Add xtask.[PR-95](https://github.com/kaplanelad/shellfirm/pull/95)
* Interactive menu in config reset command. [PR-96](https://github.com/kaplanelad/shellfirm/pull/96)

DOCS
* More installation examples. [PR-](https://github.com/kaplanelad/shellfirm/pull/94)

## 0.2.2
IMPROVMENT
* Adds crontab -r as a risky command. [PR-81](https://github.com/kaplanelad/shellfirm/pull/81)
* Decouple test from base checks. [PR-84](https://github.com/kaplanelad/shellfirm/pull/84)
* Decouple test from app version snapshots. [PR-85](https://github.com/kaplanelad/shellfirm/pull/85)
* Improve config tests. [PR-86](https://github.com/kaplanelad/shellfirm/pull/86)

BUG FIX
* Change title for fish installation instructions. [PR-82](https://github.com/kaplanelad/shellfirm/pull/82)

## 0.2.1
IMPROVMENTS:
* Add heroku risky patterns.[PR-75](https://github.com/kaplanelad/shellfirm/pull/75)

DOCS
* Spell correction for README typo. [PR-79](https://github.com/kaplanelad/shellfirm/pull/79)
* docs/checks/fs - clarify descriptions. [PR-77](https://github.com/kaplanelad/shellfirm/pull/77)

## 0.2.0
IMPROVMENTS:
* Replace / with path join.[PR-72](https://github.com/kaplanelad/shellfirm/pull/72)
* Bump crossbeam-utils from 0.8.5 to 0.8.10. [PR-74](https://github.com/kaplanelad/shellfirm/pull/74)


## 0.2.0
IMPROVMENTS:
* Improve test. [PR-71](https://github.com/kaplanelad/shellfirm/pull/71)
* replace / with path join. [PR-72](https://github.com/kaplanelad/shellfirm/pull/72)
* Text cleanuo. [PR-]https://github.com/kaplanelad/shellfirm/pull/66

## 0.1.6
IMPROVMENTS
* change ~ to home dir in IsFileExists FILTER. [PR-63](https://github.com/kaplanelad/shellfirm/pull/63)
* Fish shell support. [PR-61](https://github.com/kaplanelad/shellfirm/pull/61)

## 0.1.5 

IMPROVMENTS:
* Ading custom check - for check if file exsits before prompt a delete/flush verification. [PR-46](https://github.com/kaplanelad/shellfirm/pull/60)
* Support multiple commands in one line. [MR](https://github.com/kaplanelad/shellfirm/commit/c2c4d0633dcdac38b6b44d5351179f6e1421096d)

BUG
* Replace `~` char with home directory path. [PR-63](https://github.com/kaplanelad/shellfirm/pull/63)
## 0.1.4 

IMPROVMENTS:
* Update config file from baseline checks when `shellfirm` binary update. [PR-46](https://github.com/kaplanelad/shellfirm/pull/46)
* Show single prompt verification when multiple pattern is detected. [PR-51](https://github.com/kaplanelad/shellfirm/pull/51)
* Improve `rm` pattern. [PR-53](https://github.com/kaplanelad/shellfirm/pull/53)
* Improve `chmod` pattern. [PR-54](https://github.com/kaplanelad/shellfirm/pull/54)
* Adding reboot and shutdown risky pattern. [PR-56](https://github.com/kaplanelad/shellfirm/pull/56)

BUG:
* Ignore text between quotes. [PR-57](https://github.com/kaplanelad/shellfirm/pull/57)

## 0.1.3 

IMPROVEMENTS:
* Improve FS checks. [PR-30](https://github.com/kaplanelad/shellfirm/pull/30)
* Skip github actions on push (without PR) or on *.md file/docs folder. [PR-33](https://github.com/kaplanelad/shellfirm/pull/33) 
* Adding strict file sytem command. [PR-36](https://github.com/kaplanelad/shellfirm/pull/36)
* FS checks - adding to `rm`/`chmod` pattern the chars `.` and `./` as risky command. [PR-38](https://github.com/kaplanelad/shellfirm/pull/38)
* Adding a better error message when config file is invalid. [PR-42](https://github.com/kaplanelad/shellfirm/pull/42)
* Adding kubernetes strict risky patters. [PR-41](https://github.com/kaplanelad/shellfirm/pull/41)
* Allow to override deafult per pattern. [PR-43](https://github.com/kaplanelad/shellfirm/pull/43)

FEATURES:
* Promt message while using `config reset` + ading the option to backup file. [PR-31](https://github.com/kaplanelad/shellfirm/pull/31)

BREAKING CHANGES:
* Change `is` field in yaml file to `test`. [PR-32](https://github.com/kaplanelad/shellfirm/pull/32)

## 0.1.2 - (Jan 4, 2022)

IMPROVEMENTS:
* Mark history | sh/bash as risky command. [PR-27](https://github.com/kaplanelad/shellfirm/pull/27)
* Add 2 check for `fs` group. detect `chmod 777 /` and `find -delete`. [PR-28](https://github.com/kaplanelad/shellfirm/pull/28)

## 0.1.1 (Jan 3, 2022)

IMPROVEMENTS:

* Add application logger. [PR-24](https://github.com/kaplanelad/shellfirm/pull/24)

## 0.1.0 (Jan 2, 2022)
Initial release
