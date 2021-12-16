<pre>
████████████████▀███████████████████████████████████████████████████████████████████
█▄─▄███─▄▄─█─▄▄▄▄█░█░████▄─▄█▀▀▀▀▀██▄─▄▄─█▄─▄█▄─▄███▄─▄▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
██─██▀█─██─█─██▄─█▄▄░██─▄█─██████████─▄████─███─██▀██─▄█▀█▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▄▄▄▀▀▀▀▀▀▀▀▀▀▄▄▄▀▀▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀
by Renato Andalik
</pre>

Simples e direto ao ponto... Não requer prática, nem tão pouco habilidade!  
Log4j-FileScan é um script desenvolvido em Python 3 para realizar a varredura completa de um filesystem buscando por versões vulneráveis do framework Loj4j2 conforme descrito na CVE-2021-44228 e CVE-2021-45046.  
A varredura é realizada recursivamente tanto em disco quanto dentro de arquivos Java Archive (JARs).  

## Download e Execução

O script pode ser baixado e utilizado de 2 formas distintas:  

### 1. Usando Binário (Piece of Cake Mode)

Para facilitar ainda mais, compilamos tudo e disponibilizamos um binário executável.  
Basta baixar a versão para seu Sistema Operacional:  

 * Windows: [log4j-filescan.exe](https://github.com/andalik/log4j-filescan/releases/latest/download/log4j-filescan.exe)  
 * Linux: [log4j-filescan](https://github.com/andalik/log4j-filescan/releases/latest/download/log4j-filescan)  

No Linux, via console, você também pode utilizar o wget para obter o binário:  

```bash
wget https://github.com/andalik/log4j-filescan/releases/latest/download/log4j-filescan -O log4j-filescan
chmod +x log4j-filescan
sudo ./log4j-filescan
```

### 2. Usando Python 3

Para distribuições Linux com Python 3 instalado, utilize um dos métodos abaixo:  

```bash
wget https://github.com/andalik/log4j-filescan/raw/main/log4j-filescan.py
sudo python3 log4j-filescan.py
```

## Exemplos de Uso

1. Varredura em um diretório específico (padrão é /):  
```bash
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

4. Verbose ou Modo Debug:  
```bash
$ python3 log4j-filescan.py -v /caminho/desejado
$ python3 log4j-filescan.py -vv /caminho/desejado
```

## Notas Importantes

Arquivos e/ou diretórios que não puderem ser acessados (permissão de acesso negado) não serão listados.
