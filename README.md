<pre>
████████████████▀███████████████████████████████████████████████████████████████████
█▄─▄███─▄▄─█─▄▄▄▄█░█░████▄─▄█▀▀▀▀▀██▄─▄▄─█▄─▄█▄─▄███▄─▄▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
██─██▀█─██─█─██▄─█▄▄░██─▄█─██████████─▄████─███─██▀██─▄█▀█▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▄▄▄▀▀▀▀▀▀▀▀▀▀▄▄▄▀▀▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀
by Renato Andalik (@andalik)
</pre>

Simples e direto ao ponto... Não requer prática, nem tão pouco habilidade!  
Log4j-FileScan é um script desenvolvido em Python 3 para realizar a varredura completa de um filesystem buscando por versões vulneráveis do framework Log4j2 conforme descrito na CVE-2021-44228, CVE-2021-45046, CVE-2021-45105 e CVE-2021-44832.  
A varredura é realizada recursivamente tanto em disco quanto dentro de arquivos Java Archive (JARs).  

![log4j-filescan](https://github.com/andalik/log4j-filescan/blob/main/docs/screenshots/log4j-filescan1.png)

## Funcionamento

Para otimizar a velocidade da varredura, a busca ocorre SOMENTE nos arquivos relacionados ao problema:

 * Todos os arquivos com extensão `Java ARchive`:
    *  `*.jar`, `*.war`, `*.ear`

Se um arquivo com uma das extensões mencionadas acima é localizado, ocorre a varredura dos arquivos internos (tudo em memória).

## Download e Execução

O script pode ser baixado e utilizado de 2 formas distintas:  

### 1. Usando Binário (Piece of Cake Mode)

Para facilitar ainda mais, compilamos tudo e disponibilizamos um binário executável.  
Basta baixar a versão para seu Sistema Operacional, abrir o prompt de comando e executar:  

 * Windows: [log4j-filescan.exe](https://github.com/andalik/log4j-filescan/releases/download/v1.1.1/log4j-filescan.exe)  
   <span style="color:red">IMPORTANTE: Devido o uso do Pyinstaller para empacotar tudo em um executável, alguns antivirus podem disparar um alerta falso-positivo. Caso ocorra, inclua o arquivo executável na lista de Exclusões.</span>  
   
 * Linux: [log4j-filescan](https://github.com/andalik/log4j-filescan/releases/download/v1.1.1/log4j-filescan)  

No Linux, via console, você também pode utilizar o wget para obter o binário:  

```bash
wget https://github.com/andalik/log4j-filescan/releases/download/v1.1.1/log4j-filescan -O log4j-filescan
chmod +x log4j-filescan
sudo ./log4j-filescan
```

### 2. Usando Python 3

Para distribuições Linux com Python 3.6+ instalado, utilize um dos métodos abaixo:  

```bash
wget https://github.com/andalik/log4j-filescan/raw/main/log4j-filescan.py
export LC_ALL=$(locale -a | grep UTF-8)
sudo python3 log4j-filescan.py
```

## Criando executáveis

### Criando executável Windows

1. Baixar Python 3.6 ou superior em https://www.python.org/downloads/

   * Certifique-se, durante a instalacão, de selecionar a opção `Add Python 3.x to PATH`.

2. Abrir o prompt de comando e executar `pip` para instalar o `pyinstaller`:

   ```bash
   pip install pyinstaller
   pip install colorama
   ```

3. Baixar a última versão do script `log4j-filescan.py` e executar o PyInstaller:

   ```bash
   pyinstaller --onefile --hidden-import colorama log4j-filescan.py
   ```

O executável Windows será criado no diretório `dist`: `dist\log4j-filescan.exe`

### Criando executável Linux

Examplo para Debian 11:

```bash
sudo apt update
sudo apt install python3-pip git
pip3 install --user pyinstaller

git clone https://github.com/andalik/log4j-filescan
cd log4j-filescan
~/.local/bin/pyinstaller --onefile log4j-filescan.spec

./dist/log4j-finder --help
```

## Exemplos de Uso

1. Varredura em um diretório específico (padrão é /):  
```bash
$ python3 log4j-filescan.py
ou
$ python3 log4j-filescan.py /caminho/desejado
```

2. Varredura em um arquivo JAR:  
```bash
$ python3 log4j-filescan.py /caminho/arquivo.jar
```

3. Varredura em múltiplos diretórios e/ou arquivos:  
```bash
$ python3 log4j-filescan.py /caminho/dir1 /caminho/dir2 /caminho/arquivo.jar
```

4. Varredura excluindo alguns arquivos e/ou diretórios
```bash
$ python3 log4j-filescan.py / --exclude "/caminho/*.war"
```

4. Verbose ou Modo Debug:  
```bash
$ python3 log4j-filescan.py -v /caminho/desejado
$ python3 log4j-filescan.py -vv /caminho/desejado
```

## Notas Importantes

* No Windows, por padrão, a varredura ocorrerá apenas em `c:\`.  
Recomendamos especificar as unidades adicionais para varredura na linha de comando (as unidades inexistentes serão ignoradas):

```bash
log4j-filescan.exe c:\ d:\ e:\ f:\
```

* Arquivos e/ou diretórios que não puderem ser acessados (permissão de acesso negado) não serão listados.
