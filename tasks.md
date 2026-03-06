Perfeito, so que deve fazer a analisar em tempo real, mostrando os logs, veriicar a fundo se o site analisado possui alguma brecha de sgurança, dados sesiveis no codigo fonte, alguma rota quebrada, mostrar rotas ocultas, verificar se não possui alguma vulnerabilidade extrema no site e codigo fonte. Verificar se possui algum erros em cada codigo de cada arquivo (isso deve ser feito de forma real e sem ser ficiticio, deve fazer de forma bem completa e avancada)

---

Deve ser possivel gerar varios tipos de graficos que ajudam a entender a vulnerabilidade do site analisado, deve colocar tabelas, trazer insights valiosos, deve colocar uma tabela com as rotas ocultas, deve mostrar o Score de Seguranca, Stack Detectado, gerar o relatorio de insidencias cibernéticas no formato em PDF de forma elegante com um template profissional e tambem gerar um relatorio com graficos e numeros em HTML com css e js. Deve listar os Arquivos Sensiveis, deve mostrar "O que verificamos" e se possivel tambem gerar uma pasta no formato .zip com o codigo fonte do site analisado utilizando o script js so que melhorado:

const scrape = require('website-scraper').default;
const PuppeteerPlugin = require('website-scraper-puppeteer').default;
const path = require('path');


scrape({
    urls: ['site'],
    directory: path.resolve(__dirname, 'pasta-do-site'),

    plugins: [ 
    new PuppeteerPlugin({
        launchOptions: { 
            headless: true
        },
        scrollToBottom: {
            timeout: 10000, 
            viewportN: 10 
        }
    })
]
});

Depois de analisar o site, deve ter uma rota com varias informacoes da auditoria que traz informacoes preciosas para o desenvolvedor alvo melhorar o site.