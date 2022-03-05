#!/usr/bin/env python3
# Program......: log4j-filescan.py
# Author.......: Renato Andalik
# Version......: 1.1.1 (12/01/2022)
# Description..: Scanner recursivo de arquivos desenvolvido em Python3 para varredura e localizacao de
#                versoes vulneraveis do Log4j, contemplando analise interna de arquivos JAR,WAR,EAR e ZIP
#                (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 e CVE-2021-44832)

# dependências
import os, io, sys, socket, fnmatch, time, zipfile, logging, argparse, hashlib, datetime, functools, itertools, collections
from pathlib import Path

# tupla com extensões suportadas
EXTENSIONS = (".jar", ".war", ".ear", ".zip")

# dicionário com hashes MD5 de múltiplas versões do log4j (JndiManager.class)
# versões vulneráveis do log4j
MD5_LOG4J_VULNERABLE = {
    "6b15f42c333ac39abacfeeeb18852a44": "Log4j 2.1, 2.2 ou 2.3: Log4Shell (CVE-2021-44228)",
    "2128ed66f0a5dbc8b5a81ec2376dfea0": "Log4j 2.3.1: Log4Shell (CVE-2021-44228)",
    "8b2260b1cce64144f6310876f94b1638": "Log4j 2.4, 2.4.1 ou 2.5: Log4Shell (CVE-2021-44228)",
    "3bd9f41b89ce4fe8ccbf73e43195a5ce": "Log4j 2.6, 2.6.1 ou 2.6.2: Log4Shell (CVE-2021-44228)",
    "415c13e7c8505fb056d540eac29b72fa": "Log4j 2.7, 2.8 ou 2.8.1: Log4Shell (CVE-2021-44228)",
    "a193703904a3f18fb3c90a877eb5c8a7": "Log4j 2.8.2: Log4Shell (CVE-2021-44228)",
    "04fdd701809d17465c17c7e603b1b202": "Log4j 2.9, 2.9.1, 2.10, 2.11, 2.11.1 ou 2.11.2: Log4Shell (CVE-2021-44228)",
    "5824711d6c68162eb535cc4dbf7485d3": "Log4j 2.12 ou 2.12.1: Log4Shell (CVE-2021-44228)",
    "102cac5b7726457244af1f44e54ff468": "Log4j 2.12.2: Log4Shell (CVE-2021-44228)",
    "5d058c91e71038ed3ba66f29a071994c": "Log4j 2.12.3: Log4Shell (CVE-2021-44228)",
    "21f055b62c15453f0d7970a9d994cab7": "Log4j 2.13, 2.13.1, 2.13.2 ou 2.13.3: Log4Shell (CVE-2021-44228)",
    "f1d630c48928096a484e4b95ccb162a0": "Log4j 2.14 ou 2.14.1: Log4Shell (CVE-2021-44228)",
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046
    "5d253e53fa993e122ff012221aa49ec3": "Log4j 2.15.0: RCE (CVE-2021-45046)",
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45105
    "ba1cf8f81e7b31c709768561ba8ab558": "Log4j 2.16.0: DoS (CVE-2021-45105)",
    # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44832
    "3dc5cf97546007be53b2f3d44028fa58": "Log4j 2.17.0: RCE (CVE-2021-44832)",
}
# versões não vulneráveis do log4j
MD5_LOG4J_NOT_VULNERABLE = {
    # log4j 2.3.2 - versão estável para uso com Java 6
    "a796bc9b7a227ec08e229b09ff0c1ff1": "Log4j 2.3.2: Ok (versão estável para uso com Java 6)",
    # log4j 2.12.4 - versão estável para uso com Java 7
    "909f3304825153542280d20a975d3114": "Log4j 2.12.4: Ok (versão estável para uso com Java 7)",
    # log4j 2.17.1 - versão estável para uso com Java 8
    "3c3a43af0930a658716b870e66db1569": "Log4j 2.17.1: Ok (versão estável para uso com Java 8)",
}

# banner
__version__ = "1.1.1"
BANNER = f"""\

                                                                 *%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          #%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(         *%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#          %%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%(         ,%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%          #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%/         *%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%           ,%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%.                   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%#                   ,%%%%%%%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%                    %%%%%%%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%(                   *%%%%%%%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%.                   #%%%%%%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%(                   *%%%%%%         
      %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.                   #         
      /////////////////////////////////////////////*                        


          █░░ █▀█ █▀▀ █░█ ░░█ ▄▄ █▀▀ █ █░░ █▀▀ █▀ █▀▀ ▄▀█ █▄░█
          █▄▄ █▄█ █▄█ ▀▀█ █▄█ ░░ █▀░ █ █▄▄ ██▄ ▄█ █▄▄ █▀█ █░▀█
          v{__version__}                  by Renato Andalik (@andalik)
"""

# modo verboso (INFO ou DEBUG)
logging.basicConfig(format="[%(asctime)s] %(levelname)s: %(message)s",datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

# lista de arquivos para procurar no filesystem 
# *no momento, procuramos apenas por JndiManager.class*
FILENAMES = [
    p.lower()
    for p in [
        "JndiManager.class",
    ]
]

# coloração do texto (dependencia da biblioteca colorama no Windows)
# pip install colorama
try:
    import colorama

    colorama.init()
    NO_COLOR = False
except ImportError:
    if sys.platform == "win32": 
        NO_COLOR = True 
    else:
        NO_COLOR = False

def red(s):
    if NO_COLOR:
        return s
    return f"\033[31m{s}\033[0m"

def green(s):
    if NO_COLOR:
        return s
    return f"\033[32m{s}\033[0m"

def yellow(s):
    if NO_COLOR:
        return s
    return f"\033[33m{s}\033[0m"

def cyan(s):
    if NO_COLOR:
        return s
    return f"\033[36m{s}\033[0m"

def bold(s):
    if NO_COLOR:
        return s
    return f"\033[1m{s}\033[0m"


# md5_digest
def md5_digest(fobj):
    d = hashlib.md5()
    for buf in iter(functools.partial(fobj.read, io.DEFAULT_BUFFER_SIZE), b""):
        d.update(buf)
    return d.hexdigest()

# iter_scandir
def iter_scandir(path, stats=None, exclude=None):
    p = Path(path)
    if p.is_file():
        if stats is not None:
            stats["files"] += 1
        yield p
        return
    if stats is not None:
        stats["directories"] += 1
    try:
        for entry in scantree(path, stats=stats, exclude=exclude):
            if entry.is_symlink():
                continue
            elif entry.is_file():
                name = entry.name.lower()
                if name.endswith(EXTENSIONS):
                    yield Path(entry.path)
                elif name in FILENAMES:
                    yield Path(entry.path)
    except IOError as e:
        log.debug(e)

# scantree
def scantree(path, stats=None, exclude=None):
    exclude = exclude or []
    try:
        with os.scandir(path) as it:
            for entry in it:
                if any(fnmatch.fnmatch(entry.path, exclusion) for exclusion in exclude):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if stats is not None:
                        stats["directories"] += 1
                    yield from scantree(entry.path, stats=stats, exclude=exclude)
                else:
                    if stats is not None:
                        stats["files"] += 1
                    yield entry
    except IOError as e:
        log.debug(e)

# iter_jarfile
def iter_jarfile(fobj, parents=None, stats=None):
    parents = parents or []
    try:
        with zipfile.ZipFile(fobj) as zfile:
            for zinfo in zfile.infolist():
                zpath = Path(zinfo.filename)
                if zpath.name.lower() in FILENAMES:
                    yield (zinfo, zfile, zpath, parents)
                elif zpath.name.lower().endswith(EXTENSIONS):
                    zfobj = zfile.open(zinfo.filename)
                    try:
                        zipfile.ZipFile(zfobj)
                    except zipfile.BadZipFile as e:
                        log.debug(f"{zinfo}: {e}")
                        zfobj = io.BytesIO(zfile.open(zinfo.filename).read())
                    yield from iter_jarfile(zfobj, parents=parents + [zpath])
    except IOError as e:
        log.debug(f"{fobj}: {e}")
    except zipfile.BadZipFile as e:
        log.debug(f"{fobj}: {e}")
    except RuntimeError as e:
        log.debug(f"{fobj}: {e}")

# check_vulnerable
def check_vulnerable(fobj, path_chain, stats, has_jndilookup=True):
    md5sum = md5_digest(fobj)
    first_path = bold(path_chain.pop(0))
    path_chain = " -> ".join(str(p) for p in path_chain)

    vulnerable = red("VULNERÁVEL")
    good = green("NÃO VULNERÁVEL")
    patched = cyan("MITIGADO")
    unknown = yellow("VERSÃO NÃO IDENTIFICADA DO LOG4J")

    dt = datetime.datetime.now().strftime('%H:%M:%S')

    if md5sum in MD5_LOG4J_VULNERABLE:
        comment = MD5_LOG4J_VULNERABLE[md5sum]
        if has_jndilookup:
            print(f"[{dt}] {vulnerable}: {first_path}")
            print(f"{' '*11}| {path_chain}")
            print(f"{' '*11}| {comment}")
            print(f"{' '*11}|___\n")
            stats["vulnerable"] += 1
        else:
            print(f"[{dt}] {patched}: {first_path}\n")
            stats["patched"] += 1
    elif md5sum in MD5_LOG4J_NOT_VULNERABLE:
        comment = MD5_LOG4J_NOT_VULNERABLE[md5sum]
        print(f"[{dt}] {good}: {first_path}\n")
        stats["good"] += 1
    else:
        print(f"[{dt}] {unknown}: {first_path}")
        print(f"{' '*11}| Hash MD5 desconhecido")
        print(f"{' '*11}| {md5sum}")
        print(f"{' '*11}|___\n")
        stats["unknown"] += 1


# corra Forrest, corra...
def main():
    parser = argparse.ArgumentParser(
        description="%(prog)s v{__version__} - Scanner recursivo de arquivos para localização de versões vulneráveis do Log4j2 (Log4Shell)",
        epilog="Contempla CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 e CVE-2021-44832",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,)
    parser.add_argument("path", metavar="PATH", nargs="*", default=["/"], help="Localização de arquivos e/ou diretórios para varredura",)
    parser.add_argument("-e", "--exclude", action='append', help="Exclusão de arquivos e/ou diretórios da varredura (pode ser usado múltiplas vezes)",metavar='PATTERN')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Debug (-v para INFO, -vv para DEBUG)",)
    args = parser.parse_args()

    if args.verbose == 1:
        log.setLevel(logging.INFO)
        log.info("Modo INFO habilitado")
    elif args.verbose >= 2:
        log.setLevel(logging.DEBUG)
        log.debug("Modo DEBUG habilitado")

    stats = {
        "scanned": 0,
        "files": 0,
        "directories": 0,
        "vulnerable": 0,
        "patched": 0,
        "good": 0,
        "unknown": 0,
    }
    start_time = time.monotonic()

    print(BANNER)
    for directory in args.path:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Escaneando {bold(socket.gethostname())}")
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Varredura recursiva iniciada em {directory}")
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Aguarde...\n")
        for p in iter_scandir(directory, stats=stats, exclude=args.exclude):
            if p.name.lower() in FILENAMES:
                stats["scanned"] += 1
                log.info(f"{p}")
                with p.open("rb") as fobj:
                    # se JndiManager.class for localizado, 
                    # confirmar a existência de JndiLookup.class (ação de mitigação padrão)
                    has_lookup = True
                    if p.name.lower().endswith("JndiManager.class".lower()):
                        lookup_path = p.parent.parent / "lookup/JndiLookup.class"
                        has_lookup = lookup_path.exists()
                    check_vulnerable(fobj, [p], stats, has_lookup)
            if p.suffix.lower() in EXTENSIONS:
                try:
                    log.info(f"{p}")
                    stats["scanned"] += 1
                    for (zinfo, zfile, zpath, parents) in iter_jarfile(p.open("rb"), parents=[p]):
                        log.info(f"{zinfo} ({parents}")
                        with zfile.open(zinfo.filename) as zf:
                            # se JndiManager.class for localizado, 
                            # confirmar a existência de JndiLookup.class (ação de mitigação padrão)
                            has_lookup = True
                            if zpath.name.lower().endswith("JndiManager.class".lower()):
                                lookup_path = zpath.parent.parent / "lookup/JndiLookup.class"
                                try:
                                    has_lookup = zfile.open(lookup_path.as_posix())
                                except KeyError:
                                    has_lookup = False
                            check_vulnerable(zf, parents + [zpath], stats, has_lookup)
                except IOError as e:
                    log.debug(f"{p}: {e}", e)

    elapsed_time = time.monotonic() - start_time
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Varredura concluída com sucesso!")

    print(f"\n{bold('Informações Gerais:')}")
    print(f"> Data da varredura: {datetime.datetime.now().strftime('%d/%m/%Y às %H:%M')}hs")
    print(f"> Hostname: {socket.gethostname()}")
    print(f"> Total de arquivos: {stats['files']}")
    print(f"> Arquivos analisados por versões vulneráveis do Log4j: {stats['scanned']}")
    print(f"> Tempo decorrido: {elapsed_time:.2f} segundos ")

    print(f"\n{bold('Resultado da Varredura:')}")
    if stats["vulnerable"] == 0 and stats["good"] == 0 and stats["unknown"] == 0:
        print("> Nenhum arquivo relacionado ao Log4j encontrado!")
    else:
        if stats["vulnerable"]:
            print(f"> Arquivos {red('VULNERÁVEIS')} encontrados: {stats['vulnerable']}")
        if stats["patched"]:
            print(f"> Arquivos {cyan('MITIGADOS')} encontrados: {stats['patched']}")
        if stats["good"]:
            print(f"> Arquivos {green('NÃO VULNERÁVEIS')} encontrados: {stats['good']}")
        if stats["unknown"]:
            print(f"> Arquivos com versões {yellow('NÃO IDENTIFICÁVEIS')} do Log4j encontrados: {stats['unknown']}")

    print(f"\n{bold('Versões do Log4j Não-Vulneráveis:')}")
    for log4j_md5,log4j_version in MD5_LOG4J_NOT_VULNERABLE.items():
        print(f"> {log4j_version}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrompido!")
