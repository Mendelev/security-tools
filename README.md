
# Ferramentas a investigar.



## Trivy - https://github.com/aquasecurity/trivy

- Boa para ser usada em CD

- Instalação do Trivy -> https://aquasecurity.github.io/trivy/v0.30.4/getting-started/installation/

- Estratégia de uso, verificar apenas vunerabilidades com correções conhecidas.
Exemplo: trivy image --ignore-unfixed nome_da_imagem

## Grype - https://github.com/anchore/grype

- Não é boa para ser usada em CD, apenas para análises detalhadas

- Similar ao Trivy, mas a única vantagem é que ele fornece análises mais detalhadas. Mas essas análises detalhadas são úteis para uma investigação e não para a automação de um pipeline.

- Instalação
sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin

- Análise simples: grype captcha_captcha-generic
- Análise detalhada: grype captcha_captcha-generic -o json

## SAST - Algumas ferramentas

Há ferramentas de análise estática focadas na segurança, seguem exemplos abaixo

- Ferramenta 1: Spectralops - https://spectralops.io/
- Boa para CD, mas com limitações, devido ao plano gratuito

Para usar, basta criar uma conta e seguir as instruções

- Ferramenta 2: Bandit - https://www.appsecsanta.com/bandit
- Boa para CD

Pode ser instalado com o pip.
Exemplos de uso: 
* bandit -r Bots/
* bandit -f json -r Bots/ -o bots.json 


## OWASP ZAP - https://www.zaproxy.org/download/

- Não é boa para CD, mas é bastante útil para propósitos gerais.

* Faça download clicando no Linux Installer e rode o comando no terminal:
sudo bash ZAP_2_11_1_unix.sh

* Exercite o scan automático em um ambiente controlado
https://www.zaproxy.org/getting-started/#zap-desktop-ui


## Jaeles - https://jaeles-project.github.io

- Não é boa para CD, apenas para análises detalhadas

Instalação - https://jaeles-project.github.io/installation/

Baixe o binário jaeles e coloque no /usr/bin para pder executar os comandos no terminal


Uso geral - https://jaeles-project.github.io/usage/

Signatures para usar no scan
* https://github.com/jaeles-project/jaeles/tree/master/test-signatures
* https://github.com/ghsec/ghsec-jaeles-signatures

Exemplo

jaeles scan -u https://URL -s ghsec-jaeles-signatures/host-header-injection.yaml


## Disearch - https://github.com/maurosoria/dirsearch

- Não é boa para CD, mas recomendo o uso com certa regularidade

* Melhor jeito de instalar, faça clone do repo
git clone https://github.com/maurosoria/dirsearch.git --depth 1 

* Rode a ferramenta:
python3 dirsearch.py -u https://URL

## Arjun - https://github.com/s0md3v/Arjun

- Não é boa para CD, mas recomendo uso com certa regularidade


* Instalação -> pip3 install arjun
* Exemplo de uso -> arjun -u https://URL -oT result.txt

## ParamSpider - https://github.com/devanshbatham/ParamSpider

Observação: Essa ferramenta não é muito útil para o Hub, mas é útil para sites como dominio.com.br

Instalação:


Note : Use python 3.7+

- git clone https://github.com/devanshbatham/ParamSpider
- cd ParamSpider
- pip3 install -r requirements.txt
- python3 paramspider.py --domain hackerone.com

*comentario: Pode ser combinada com ferramentas de envio de payload para XSS, como o ffuf
## Checkov 

Há ferramentas para análise de vulnerabilidades em script terraform
 - https://www.checkov.io/

Para usar, basta executar na pasta a ser analisada
 - checkov -f ./

Pode ser instalado com o pip. 

## Nuclei - https://github.com/projectdiscovery/nuclei
 Busca de vulnerabilidade
 - faça o pull da imagem docker segundo o site e rode
 - docker run projectdiscovery/nuclei -update-templates -v
 - docker run projectdiscovery/nuclei -u dominio.com.br

 Retorna um log facilmente automatizado no CD, porém nao encontrou nenhuma vulnerabilidade
 
## Tsunami - https://github.com/google/tsunami-security-scanner
 
 Verifica por vulnerabilidades criticais de rede (faz scan nmap)
 
- faça download do projeto github e o build no docker
- suba os containers dockers com os projetos que quer analisar e execute
- docker run  --network="host" -v "$(pwd)/logs":/usr/tsunami/logs tsunami

 Retorna um log facilmente automatiza, porém tambem não encontrou nenhuma vulnerabilidade
 resultado final do log: '# of detected vulnerability: 0.'
 
 
## page-fetch - https://github.com/detectify/page-fetch

Ferramenta que busca na página alvo por elementos e tem a capacidade de executar um javascript arbitrário.

* Instalação da ferramenta:
- git clone https://github.com/detectify/page-fetch.git
- cd page-fetch
- go install

* Exemplo de uso: echo https://example.com | page-fetch

## Notify - https://github.com/projectdiscovery/notify

Ferramenta que envia a saída de qualquer comando como notificação em algum ambiente desejado, como Discord e Slack.

* Instalação
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

* Configurar discord como canal de notificação

Edite o arquivo $HOME/.config/notify/provider-config.yaml com o formato abaixo

```yaml
discord:
  - id: "crawl"
    discord_channel: "crawl"
    discord_username: "test"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/XXXXXXXX"
``` 
O id é um nome qualquer que você queira escolher pra identificar a notificação, já os demais parâmetros precisam ser preenchidos conforme forem criados no discord com exceção do discord_format, que pode ser deixado como {{data}}

* Exemplo de uso
```bash
sudo nmap -sS dominio.com.br | notify -id nmap
```

Neste caso eu quero que a notificação a ser usada, seja a que eu configurei com o id **nmap**

## Findomain
 Ferramenta paga, porém com versão gratuita, para ser usada junto de outros serviços. Para notificar quando um subdominio novo é encontrado. Não acho que faz tanto sentido ser usada para CD.
 
 "Findomain offers a subdomains monitoring service that provides: directory fuzzing/ports scan/vulnerabilities discovery (with Nuclei) - and more that allow you to monitor your target domains with multiple top tools (OWASP Amass, Sublist3r, Assetfinder and Subfinder) and send alerts to Discord, Slack, Telegram, Email or Push Notifications (Android/iOS/Smart Watch/Desktop) when new subdomains are found."

# Ferramentas de Content Security Policy (CSP) ou XSS Protection
 
  Segundo a mozilla, XSSProtection é depredado se o site usa uma forte Content Security Policy para se proteger de ataques. O dominio.com.br atualmente não tem nenhum header de Contenct Security Policy.
  
  
  Ferramentas para injeção de payload fornecida por usuario:
  
  - https://github.com/ferreiraklet/airixss (instalação por: go install github.com/ferreiraklet/airixss@latest)
  - https://github.com/ffuf/ffuf (instalação por: go install github.com/ffuf/ffuf@latest) 
  - https://github.com/R0X4R/bhedak (não recomendada)
  - XSSHunter*

Essas ferramentas não são integráveis ao CD e é preciso estudar mais sobre XSS.

## XSSHunter - https://xsshunter.com/

Versão Self Hosted da ferramenta - https://github.com/mandatoryprogrammer/xsshunter-express

Essa ferramenta permite hospedar os nossos próprios payloads para para exercitar ataques XSS

Meu Payload XSS Pessoal https://blazim.xss.ht/

## Dalfox - https://github.com/hahwul/dalfox

* Boa para CD

* Instalação - sudo snap install dalfox

* Exemplo de uso

dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://hahwul.xss.ht

O parâmetro do -b é o payload pra carregar o script no site alvo de ataque, matenha fixo e ajuste o URL COM CUIDADO para não derrubar nada de produção

## KXSS - https://github.com/Emoe/kxss

* Faz a mesma coisa que o Dalfox, só que pior. Ignorei essa ferramenta


## XSStrike - https://github.com/s0md3v/XSStrike

Pode ser usada de forma complementar ao Dalfox. É mais simples de utilizar e se encaixa bem em CD

* Instalação - git clone https://github.com/s0md3v/XSStrike.git

* Exemplos de uso

- Investigando as rotas: python3 xsstrike.py -u https://URL --crawl
- Deixar log verboso: python3 xsstrike.py -u https://URL --crawl --console-log-level DEBUG
- Injetar headers (Escreva e salve no nano): python3 xsstrike.py -u https://URL/ --headers 


# Ferramentas para analise de subdominios, verificação de DNS e recursos na pagina

## Subfinder - https://github.com/projectdiscovery/subfinder

Ferramenta que descobre subdomínios a partir de um nome de domínio válido

Exemplo de utilização: subfinder -d hackerone -v
 
## Amass https://github.com/OWASP/Amass

Ferramenta para varredura de subdomínios a partir de um dado nome de domínio. Útil para reconsiderar se as aplicações expostas estão de fato protegidas.
Não é útil para CD, mas eventualmente pode ser utilizada para outros testes.

- Instalação: sudo snap install amass
- Exemplo básico de uso: amass enum -d dominio.com.br

saida: https://gist.github.com/agojunior/a50de3c116a52cdb32f864d760516e8c

## DNSGen + (MassDNS, Filter-Resolve)
 Ferramenta que gera diferentes subdominios dns de forma aleatoria baseada em palavras chaves do site e padrões comuns.
 Esta lista de dns depois precisa ser validada por um serviço como MassDNS (mais popular) ou Filter-resolve (Mais simples. Instalação: < go get github.com/tomnomnom/hacks/filter-resolved https://github.com/tomnomnom/hacks/tree/master/filter-resolved >, recebe uma lista de dns, e tem output quais são validos)
 Não acho muito util para o CD.

pip3 install dnsgen
cat domains.txt | dnsgen - | massdns -r /path/to/resolvers.txt -t A -o J --flush 2>/dev/null 

(colocar dominio.com.br no domains.txt) 

Feita baseado na ferramenta AltDNS (mais popular)

## Shuffledns

Essa ferramenta serve para validar se uma lista de subdomínios são válidos. Vejo uma utilidade nela principalmente quando combinada com um descobridor de subdomínios como o **assetfinder**, pois podemos ao mesmo tempo descobrir vários subdomínios e filtrar imediatamente apenas os subdomínios válidos. Serve como um pré-processamento para estabelecer uma superficie de ataque.

Não é útil para CD, mas tem sua utilidade para testes pontuais.

* Instalação do Pré-requisito MassDNS
- Primeiramente faça clone do repositório: git clone https://github.com/blechschmidt/massdns.git
- Entre na pasta: cd massdns
- Compile a solução: make
- Crie um link de símbolo (Substitua caminho pela localização da pasta onde o repo foi clonado): sudo ln -s /home/caminho/massdns/bin/massdns /usr/local/bin
- Teste a instalação do massdns digitando massdns no terminal e dando enter. Ele retornará as opções de uso.

* Instalação
- Rode: go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

* Exemplo de uso.
- Assumindo que você já instalou o assetfinder contido nesta lista, faça os passos abaixo.
- Rode o comando: assetfinder dominio.com.br > subdomains.txt
- Crie um arquivo chamado resolvers.txt contendo 8.8.8.8 (DNS Solver da Google, mas pode usar outros e aumentar a lista)
- Rode o comando: shuffledns -d dominio.com.br -list subdomains.txt -r resolvers.txt

## AssetFinder - https://github.com/tomnomnom/assetfinder

Assim como o Amass, essa ferramenta varre em busca de subdomínios a partir de um nome de domínio. Não é útil para o CD, mas essa ferramenta foi capaz de encontrar alguns subdomínios que o Amass não conseguiu e vice-versa. Assim, são complementares.

* Instalação:
- wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz
- tar -xzf assetfinder-linux-amd64-0.1.1.tgz
- sudo mv assetfinder /usr/local/bin

* Uso de exemplo: assetfinder dominio.com.br

## Cariddi
Baixe o projeto do release e execute na pasta:

docker build -t cariddi .
docker run cariddi -h

Busca extrair informações uteis do site, não acha nada muito relevante ao ser executado na pagina do dominio.com.br não logada. "Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more."

 Output: https://gist.github.com/agojunior/b3f6c99f18c195bc43a7f65776a7c345
 
 
## Naabu - https://github.com/projectdiscovery/naabu

Ferramenta que escaneia portas abertas. Não é interessante para CD mas pode ser útil para outras avaliações.

Para instalaar, só seguir o read me https://github.com/projectdiscovery/naabu/blob/master/README.md

## LinkFinder - https://github.com/GerbenJavado/LinkFinder

Ferramenta que busca vulnerabilidades a partir do código fonte da página web, como credenciais.

* Instalação: Basicamente clonar o repositório, instalar o requirements.txt pelo pip e rodar no terminal.

* Exemplo de uso: python3 linkfinder.py -i https://dominio.com.br -d


 ## Waybackurls - https://github.com/tomnomnom/waybackurls
 
 Ferramenta que serve para capturar todos os elementos possíveis em uma página Web que possuem URLs atreladas a eles.
 
 Exemplo de uso: echo dominio.com.br | waybackurls > dominio.txt
 
 ## Httpx - https://github.com/projectdiscovery/httpx
 
 Ferramente que serve para verificar se uma lista de urls possui alguma aplicação web de pé. essa Ferramenta é útil para uma lista grande de domínios, pois a verificação é extremamente rápida

* Exemplo de uso: httpx -list hosts.txt -silent -probe

Coloque a lista de domínios a serem verificados no hosts.txt

# Ferramentas de SQL Injection

## SQLMap
Ferramenta que tenta realizar injeções SQL. É bem completa, mas requer um conhecimento razoável para utilizá-la apropriadamente

Exemplo de utilização: python3 sqlmap.py -u https://site-alvo --dbs

# Ferramentas que buscam segredos de aplicação

## SecretFinder - https://github.com/m4ll0k/SecretFinder

Ferramenta que varre o código fonte da página em busca de secrets, não achei a ferramenta muito boa, mas tem alguma utilidade.
Esta ferramenta não tem aplicação para CD, apenas para testes pontuais.

Exemplos de uso:
* python3 SecretFinder.py -i https://dominio.com.br
* python3 SecretFinder.py -c csrftoken=blablabla -c sessionid=blabla -i https://dominio.com.br/discover

# Combinação de ferramentas

## Exemplo 1

Usar o assetfinder para gerar uma lista de subdomínios válida.

* assetfinder dominio.com.br > domains.txt

Na sequência, criar um arquivo resolvers.txt com 8.8.8.8

Por seguinte, rodar o shuffledns para filtrar a lista anterior

shuffledns -d dominio.com.br -list domains.txt -r resolvers.txt > updated_domains.txt

Por fim, rodar o Naabu para fazer uma varredura de portas na lista de domínios válidos

* naabu -l updated_domains.txt > output.txt


# Extras (ferramentas mencionadas em repositorios de bug bounty, porém sem muita utilidade para o hub ou com propositos hiper-especificos)

 
## CF-Check (https://github.com/dwisiswant0/cf-check)
Checa se um host é a cloudfare. Não é util para CD

go install github.com/dwisiswant0/cf-check@latest

echo "dominio.com.br" | cf-check

Não tem por que fazer um scan de portas (NMAP) se o host for cloudfare. Por sinal, o hub de prod é protegido pelo cloudfare, o hub do dev não, e por isso é possivel fazer um mapeamento de portas usando NMAP. (nmap -v -A dominio.com.br)
## Freq (https://github.com/takshal/freq)
 Ferramenta para fazer varias requests http, não tem instruções de uso (parece ruim). Buscar alternativas como https://github.com/fabiobento512/FRequest https://github.com/apache/jmeter, https://github.com/locustio/locust, https://github.com/wg/wrk .
  
## Gf https://github.com/tomnomnom/gf
 Ferramenta para auxiliar no uso de grep em verificações complexas e evitar erros de digitação. não é util para CD.

## Axiom https://github.com/pry0cc/axiom
 Sistema operacional com varias ferramentas de segurança pré instalada.

## Gargs https://github.com/brentp/gargs
 Ferramenta para execuções de comandos complexos via terminal, não faz sentido para CD.

## Gau https://github.com/lc/gau#usage
 Não é util para CD, não é util para o dominio.com.br (não retorna nada).
 Retorna urls alternativos conhecidos presentes em 'AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan' para um dominio.

## Dependency-check

* Ignorar pois é específica para Java

## MassDNS - https://github.com/blechschmidt/massdns

Ferramenta para resolver milhares de DNS rapidamente. Não tem muita utilidade para o Hub, mas serve como requisito para uso de outra ferramenta

## Log4j-scan - https://github.com/fullhunt/log4j-scan

Teoricamente serve para escanear vulnerabilidades a partir de um website, mas infelizmente não funcionou quando testei.

## KNOXSS - https://knoxss.me/

Ferramenta paga, então não foi possível testar.

## X8 - https://github.com/Sh1Yo/x8

Ferramenta usada para "chutar" vários parâmetros na URL na busca para encontrar algum escondido.
Em princípio não tem nenhuma utilidade para o hub

## ToJson - https://github.com/tomnomnom/hacks/tree/master/tojson

Ferramenta que pega as linhas do stdin e converte para json. Em princípio não tem utilidade, mas pode ser útil em algum futuro, dependendo do que se cogite ser feito

## Goop - https://github.com/nyancrimew/goop

Uma ferramenta que acessa um website e tenta localizar nos arquivos do site o ".git" para extrair o código fonte. Essa ferramenta foi inspirada em outra chamada git-dumper (https://github.com/arthaud/git-dumper) que faz exatamente a mesma coisa.

Testei ambas e não encontrei nada no Hub, sendo assim, não tem nenhuma utilidade para os projetos existentes, porém pode vir a ter em outros projetos futuros.

## Wingman - https://xsswingman.com/dashboard/plans/

Ferramenta para teste de XSS que é paga. Eles fornecem um trial onde é necessário cadastrar um cartão para utilizar.



## urldedupe - https://github.com/ameenmaali/urldedupe

Uma ferramenta para fazer a deduplicação de urls. Esta ferramenta sozinha não tem utilidade, serve pra ser utilizada em conjunto com alguma outra que encontre links na página por exemplo.

O objetivo desta ferramenta é eliminar URLs similares do mesmo endereço. Exemplo, as URLs
* https://site.com/api/users/123
* https://site.com/api/users/222

Se tornam apenas 
* https://site.com/api/users/123

## unfurl - https://github.com/tomnomnom/unfurl

Ferramenta que extrai partes de uma URL, como domínio, paths e etc. Essa ferramenta sozinha não tem utilidade, mas faz sentido usá-la em conjunto com alguma outra ferramenta que gere uma lista de URLs


## subjs - https://github.com/lc/subjs

Teoricamente extrai os arquivos js de aplicações web, mas não funcionou quando eu testei

## Rush - https://github.com/shenwei356/rush

Ferramenta que serve para executar comandos complexos no terminal. Necessário maior conhecimento para utilizá-la, mas em princípio, ela não é necessária para o Hub

## qsreplace - https://github.com/tomnomnom/qsreplace

Ferramenta que serve para trocar parâmetros em URLs. Sozinha não tem utilidade alguma, mas é útil para ser utilizada em conjunto com alguma ferramenta na tentativa de descobrir parâmetros escondidos em URLs

## metabigor - https://github.com/j3ssie/metabigor

Não funcionou quando testei, mas teoricamente serve para descobrir o IP de alguma aplicação Web. Não acho que seja necessária uma ferramenta pra isso se ela não for capaz de burlar o proxy de um website

## Kxss - https://github.com/Emoe/kxss

Uma das muitas ferramentas disponíveis para testes XSS, mas não entendi como funciona.



## Jsubfinder - https://github.com/ThreatUnkown/jsubfinder

A ferramenta procura subdomínios e secrets escondidos no código fonte da página

A instalação descrita na página não funcionou pra mim. Eis o que eu fiz:
1. wget https://raw.githubusercontent.com/ThreatUnkown/jsubfinder/master/.jsf_signatures.yaml && mv .jsf_signatures.yaml ~/.jsf_signatures.yaml
2. git clone https://github.com/ThreatUnkown/jsubfinder.git 
3. cd jsubfinder
4. go build
5. sudo ln -s  /home/yurex/Security-Tools/jsubfinder/jsubfinder /usr/local/bin

Os exemplos de uso da ferramenta são bons, mas não consegui encotnrar nada no Hub

## html-tool - https://github.com/tomnomnom/hacks/tree/master/html-tool

Não consegui instalar nem usar
