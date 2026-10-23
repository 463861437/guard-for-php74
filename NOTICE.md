# Copyright and third-party notices

The original orchestration code, original tests, and project documentation are licensed under the [MIT License](LICENSE). This does not relicense third-party material. Generated single-file tools contain both original code and embedded PHP test patches, and include the applicable notices and license texts in comments.

| Material | Copyright / license / origin |
|---|---|
| `src/`, original parts of `tests/`, launchers and documentation | Copyright 2026 Guard for PHP contributors; MIT, except embedded or quoted third-party portions below |
| `patches/php74-backport-tests.patch` and its embedded copy | PHP test context from the PHP Group and contributors, PHP-3.01; original additions by this project under MIT |
| `patches/php82-el7-openssl10-compat.patch` and its embedded copy | PHP Group and contributors, PHP-3.01; reuses the const ASN.1 accessor and API-version guard from signed PHP 8.2.35 `ext/openssl/openssl.c` in `xp_ssl.c`; original context retained |
| `tests/fixtures/php74-amzn2.spec` | Fedora/Amazon packaging contributors; the SPEC file itself explicitly declares MIT. Its full copyright/header/changelog is preserved |
| `tests/fixtures/php74-remi-el7.spec` | Fedora/Remi packaging contributors; the SPEC file itself explicitly declares MIT. Its full copyright/header/changelog is preserved |
| `tests/fixtures/php82-remi-el7-system.spec`, `tests/fixtures/php82-remi-el7-scl.spec` | Fedora/Remi packaging contributors; SPEC headers declare MIT; original headers and changelogs retained |
| `validation/baota-source/upstream-text-differences.patch` | PHP Group and contributors, PHP-3.01; comparison with the BaoTa source archive |
| `validation/ubuntu-ppa/0136-context-rebase.diff`, `0164-context-rebase.diff` | PHP `main/rfc1867.c` and upstream patch context, PHP-3.01; upstream patch authors include Ilija Tovilo and Arnaud Le Blanc; contextual adaptation by this project. The Apache acknowledgment below is retained |
| Quoted Debian packaging fragments | Ondřej Surý and Debian/PPA packaging contributors; Expat/MIT as declared for `debian/*` in the pinned source archive, without overriding the PHP source licenses |

License copies: [PHP-3.01](LICENSES/PHP-3.01.txt), [third-party MIT](LICENSES/THIRD-PARTY-MIT.txt), and [historical Apache license](LICENSES/Apache-1.0.txt).

This product includes PHP software, freely available from <http://www.php.net/software/>.

This product includes software developed by the Apache Group for use in the Apache HTTP server project (http://www.apache.org/).

Fixed source references:

- PHP commit: https://github.com/php/php-src/tree/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2
- PHP license at that commit: https://raw.githubusercontent.com/php/php-src/712e60f9edfd03f0960fc4fc3c2c375f42b90aa2/LICENSE
- Remi SPEC: https://git.remirepo.net/git/rpms/php/php74.git/plain/php74.spec?id=d3fb24595d6bcebd6bd29477bc59916f333f5233
- PHP 8.2.35 signed source: https://www.php.net/distributions/php-8.2.35.tar.xz
- Remi EL7 PHP 8.2 system packaging: https://git.remirepo.net/git/rpms/php/php82.git/tree/?id=1ab9a9ffc372334e3c063034087159eaa2b48093
- Remi EL7 PHP 8.2 SCL packaging: https://git.remirepo.net/git/rpms/scl-php82/php.git/tree/?id=475b78223d7a4bca5fc6d75aeee91f7be0613dc5
- BaoTa source archive: https://download.bt.cn/src/php-7.4.34.tar.gz
- Ondřej source packaging: https://launchpad.net/~ondrej/+archive/ubuntu/php/+sourcefiles/php7.4/1:7.4.33-31+ubuntu22.04.1+deb.sury.org+1/php7.4_7.4.33-31+ubuntu22.04.1+deb.sury.org+1.debian.tar.xz

Full PHP source archives, generated RPM/DEB packages, and their bundled libraries are not distributed in this repository. Downloads and locally built packages retain their own upstream licenses. The copyright notice in each original source file remains authoritative.

Guard for PHP 7.4 is an independent compatibility tool. It is not an official PHP, BaoTa, AWS, Canonical, Fedora, Remi, or Ondřej release. Historical executable names are retained for command-line compatibility.
