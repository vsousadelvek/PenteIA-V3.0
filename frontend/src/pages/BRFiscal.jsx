import React, { useState, useEffect } from 'react'
import {
  Flag, Play, X, Loader, AlertTriangle, ChevronDown, ChevronRight,
  ShieldAlert, BookOpen, BarChart2, Target, Lock, FileText, Zap, Globe
} from 'lucide-react'
import { useToast } from '../components/Toast'
import api from '../api'

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const SEV_COLOR = {
  Critical: 'text-red-400',
  High:     'text-orange-400',
  Medium:   'text-yellow-400',
  Low:      'text-blue-400',
}
const SEV_BG = {
  Critical: 'bg-red-900/70 border border-red-600/50 text-red-300',
  High:     'bg-orange-900/70 border border-orange-600/50 text-orange-300',
  Medium:   'bg-yellow-900/70 border border-yellow-600/50 text-yellow-300',
  Low:      'bg-blue-900/70 border border-blue-600/50 text-blue-300',
}
const SEV_PT = {
  Critical: 'Crítico',
  High:     'Alto',
  Medium:   'Médio',
  Low:      'Baixo',
}
const TACTIC_COLOR = {
  'Credential Access':    'bg-purple-900/60 text-purple-300 border border-purple-700/40',
  'Initial Access':       'bg-red-900/60 text-red-300 border border-red-700/40',
  'Exfiltration':         'bg-orange-900/60 text-orange-300 border border-orange-700/40',
  'Impact':               'bg-rose-900/60 text-rose-300 border border-rose-700/40',
  'Defense Evasion':      'bg-teal-900/60 text-teal-300 border border-teal-700/40',
  'Persistence':          'bg-cyan-900/60 text-cyan-300 border border-cyan-700/40',
  'Collection':           'bg-amber-900/60 text-amber-300 border border-amber-700/40',
  'Discovery':            'bg-blue-900/60 text-blue-300 border border-blue-700/40',
  'Command and Control':  'bg-green-900/60 text-green-300 border border-green-700/40',
}
const getTacticColor = (t) => TACTIC_COLOR[t] || 'bg-gray-800 text-gray-400 border border-gray-600/40'

// ---------------------------------------------------------------------------
// FALLBACK scenarios — shown when API is unreachable
// ---------------------------------------------------------------------------
const FALLBACK_SCENARIOS = {
  nfe_sped: [
    {
      id: 'BR-NFE-001',
      name: 'NF-e XML Injection via SEFAZ',
      tactic: 'Initial Access',
      severity: 'Critical',
      description:
        'Injeta tags XML maliciosas no payload de emissão de NF-e enviado à SEFAZ para provocar falhas de parsing no sistema fiscal do alvo, permitindo rejeição em massa de notas ou acesso indevido ao histórico de operações.',
      regulatory_impact: ['LGPD Art. 46', 'BACEN 4.893', 'Manual SEFAZ NT 2024.001'],
      kill_chain: [
        'Enumeração de endpoints SEFAZ do alvo (webService.wsdl)',
        'Fuzzing de campos chave: <xNome>, <CNPJ>, <cNF>',
        'Injeção de payload XXE no campo <infNFe>',
        'Exfiltração do XML assinado para servidor externo',
        'Geração de NF-e duplicada / cancelamento silencioso',
      ],
      frameworks: ['SEFAZ Manual de Integração', 'LGPD Art. 46 §2', 'ISO 27001 A.8.24', 'NIST CSF PR.DS-1'],
    },
    {
      id: 'BR-NFE-002',
      name: 'SPED Contábil — Exfiltração de Dados Fiscais',
      tactic: 'Exfiltration',
      severity: 'High',
      description:
        'Explora credenciais SPED mal protegidas para acessar o arquivo ECD/ECF e exfiltrar o livro razão completo, balanço patrimonial e DRE, expondo dados sigilosos à concorrência ou fiscalização irregular.',
      regulatory_impact: ['RFB IN 1.774/2017', 'LGPD Art. 11', 'Lei 9.430/96'],
      kill_chain: [
        'Descoberta de credenciais SPED via phishing spear ao contador',
        'Autenticação no portal ReceitaNet / e-CAC',
        'Download do arquivo SPED Contábil (.txt, ~500MB)',
        'Extração de registros J100 (balanço) e I050 (plano de contas)',
        'Exfiltração via HTTPS para dropzone externo',
      ],
      frameworks: ['RFB IN 1.774/2017', 'LGPD Art. 11 §1', 'COBIT DSS06.03', 'ISO 27001 A.5.14'],
    },
    {
      id: 'BR-NFE-003',
      name: 'Man-in-the-Middle em Comunicação com SEFAZ',
      tactic: 'Collection',
      severity: 'High',
      description:
        'Intercepção de comunicação TLS entre o ERP do cliente e o webservice SEFAZ via ARP spoofing ou certificado raiz malicioso, permitindo captura de chaves de acesso de NF-e e tokens A1/A3.',
      regulatory_impact: ['PKI-Brasil ICP-Brasil', 'BACEN Circular 3.978', 'LGPD Art. 46'],
      kill_chain: [
        'ARP spoofing na rede interna do setor fiscal',
        'Instalação de certificado CA raiz no host alvo',
        'Captura do handshake TLS com o endpoint SEFAZ',
        'Descriptografia do payload SOAP e extração da chave de acesso',
        'Reenvio modificado para validar NF-e fraudulenta',
      ],
      frameworks: ['ICP-Brasil DOC-ICP-04', 'BACEN Circular 3.978', 'PCI DSS Req. 4.2', 'NIST SP 800-52'],
    },
    {
      id: 'BR-NFE-004',
      name: 'Certificado Digital A1 — Roubo e Uso Indevido',
      tactic: 'Credential Access',
      severity: 'Critical',
      description:
        'Exfiltração do certificado digital A1 (formato .pfx) armazenado localmente no ERP/PC do contador para assinar NF-e fraudulentas em nome da empresa vítima, gerando passivo fiscal milionário.',
      regulatory_impact: ['ICP-Brasil MP 2.200-2/2001', 'Código Penal Art. 171', 'LGPD Art. 46'],
      kill_chain: [
        'Acesso inicial via phishing ao host do contador',
        'Busca de arquivos .pfx e .p12 no sistema de arquivos',
        'Keylogging para captura da senha do certificado',
        'Exfiltração do par chave/certificado',
        'Emissão de 500+ NF-e fraudulentas com o certificado roubado',
      ],
      frameworks: ['ICP-Brasil MP 2.200-2/2001', 'DOC-ICP-04', 'Código Penal Arts. 171/298', 'LGPD Art. 46'],
    },
  ],
  drex: [
    {
      id: 'BR-DREX-001',
      name: 'DREX Smart Contract Exploit — Reentrancy',
      tactic: 'Impact',
      severity: 'Critical',
      description:
        'Exploração de vulnerabilidade de reentrância em smart contracts do DREX (Real Digital) implantados na rede DLT do BACEN, permitindo drenagem de saldo em Real Digital de carteiras institucionais.',
      regulatory_impact: ['BACEN Res. 4.893', 'SPB Circular 3.682', 'Marco Legal das Criptomoedas L14478/22'],
      kill_chain: [
        'Análise do bytecode EVM do contrato DREX via Etherscan/Tenderly',
        'Identificação de função withdraw() sem proteção mutex',
        'Deploy de contrato atacante com função fallback maliciosa',
        'Chamada recursiva drenando saldo antes de atualizar state',
        'Bridge para CEX e conversão para BTC via mixer',
      ],
      frameworks: ['BACEN Res. 4.893/2021', 'Marco Legal L14478/22', 'FATF Rec. 15', 'ISO 22739:2020'],
    },
    {
      id: 'BR-DREX-002',
      name: 'Ataque ao Nó Validador BACEN — Eclipse Attack',
      tactic: 'Defense Evasion',
      severity: 'Critical',
      description:
        'Isolamento de nó validador da rede piloto DREX para manipulação de consenso e eventual duplo gasto em transações de Real Digital no ambiente de testes do Sistema Financeiro Nacional.',
      regulatory_impact: ['BACEN Res. 4.893', 'SPB Lei 10.214/01', 'Acordo de Basileia III'],
      kill_chain: [
        'Mapeamento de peers P2P do nó BACEN via crawling',
        'Saturação de conexões com IPs controlados pelo atacante',
        'Isolamento do nó da rede principal (eclipse)',
        'Apresentação de versão alternativa do blockchain ao nó',
        'Confirmação falsa de transação de alto valor (R$ 10M+)',
      ],
      frameworks: ['BACEN Res. 4.893/2021', 'SPB Lei 10.214/01', 'CPMI PFMI Princípios', 'ISO 22739:2020'],
    },
    {
      id: 'BR-DREX-003',
      name: 'KYC/AML Bypass em Carteira DREX',
      tactic: 'Defense Evasion',
      severity: 'High',
      description:
        'Circumvenção dos controles de Know Your Customer implementados nas carteiras DREX de instituições participantes, utilizando identidades sintéticas e vulnerabilidades na integração com o sistema CPF/CNPJ da Receita Federal.',
      regulatory_impact: ['COAF Res. 36/2021', 'BACEN Circ. 3.978', 'Marco Legal L14478/22', 'FATF Rec. 10'],
      kill_chain: [
        'Geração de CPF sintético válido via algoritmo mod11',
        'Exploração de API RFB sem rate limiting adequado',
        'Criação de conta KYC-light com documentos forjados',
        'Abertura de carteira DREX em banco parceiro',
        'Lavagem de R$500K+ em micro-transações via mixing DLT',
      ],
      frameworks: ['COAF Res. 36/2021', 'BACEN Circ. 3.978/2020', 'FATF Recomendações 10-16', 'Lei 9.613/98'],
    },
    {
      id: 'BR-DREX-004',
      name: 'Front-Running em Transações DREX',
      tactic: 'Collection',
      severity: 'High',
      description:
        'Exploração da visibilidade das transações pendentes no mempool da rede DREX para executar ordens à frente de transações legítimas de alto valor, obtendo vantagem econômica indevida (MEV — Miner Extractable Value).',
      regulatory_impact: ['BACEN Res. 4.893', 'CVM Res. 30/2021', 'Lei 6.385/76 Art. 27'],
      kill_chain: [
        'Monitoramento do mempool da DLT DREX via nó full',
        'Identificação de transação de swap de alto valor pendente',
        'Submissão de transação idêntica com gas price superior',
        'Execução antes da vítima (block N vs block N+1)',
        'Lucro arbitrário extraído da diferença de preço',
      ],
      frameworks: ['BACEN Res. 4.893/2021', 'CVM Res. 30/2021', 'Lei 6.385/76', 'IOSCO Principles'],
    },
  ],
  govbr_serpro: [
    {
      id: 'BR-GOV-001',
      name: 'Gov.br — Account Takeover via OAuth Misconfiguration',
      tactic: 'Credential Access',
      severity: 'Critical',
      description:
        'Exploração de misconfiguration no fluxo OAuth 2.0 do Gov.br para sequestro de conta de cidadão ou servidor público, obtendo acesso a serviços críticos: Receita Federal, INSS, CNH, e-eSocial, CNS e Siga-doc.',
      regulatory_impact: ['LGPD Art. 46', 'Decreto 10.046/2019', 'IN SGD/ME 1/2019', 'ANPD Res. 2/2022'],
      kill_chain: [
        'Descoberta de redirect_uri sem validação estrita no authorize endpoint',
        'Construção de URL maliciosa com redirect para domínio atacante',
        'Envio via phishing ao usuário alvo (servidores públicos federais)',
        'Captura do authorization code no servidor do atacante',
        'Troca do code por access_token na API Gov.br',
        'Acesso completo a CPF, dados previdenciários e CNH digital',
      ],
      frameworks: ['LGPD Art. 46', 'Decreto 10.046/2019', 'ANPD Res. 2/2022', 'NIST SP 800-63B', 'RFC 6749 §10.6'],
    },
    {
      id: 'BR-GOV-002',
      name: 'Serpro API — Enumeração Massiva de CPF',
      tactic: 'Discovery',
      severity: 'High',
      description:
        'Abuso de APIs do Serpro (Receita Federal) com rate limiting insuficiente para enumeração massiva de CPFs válidos e consulta de dados pessoais sigilosos — nome completo, situação cadastral, data de nascimento e renda.',
      regulatory_impact: ['LGPD Art. 11 §1', 'Decreto 10.046/2019', 'RFB IN 1.968/2021', 'ANPD Res. 2/2022'],
      kill_chain: [
        'Obtenção de client_credentials via parceiro Serpro legítimo comprometido',
        'Script de enumeração gerando CPFs válidos (alg. mod11)',
        'Requisição paralela a /api-cpf/v2/cpf/{cpf} (5k req/s sem throttle)',
        'Coleta de {nome, nascimento, situacao, renda} para 2M+ CPFs',
        'Monetização em fóruns underground por R$2-50 por CPF',
      ],
      frameworks: ['LGPD Art. 11', 'Decreto 10.046/2019', 'RFB IN 1.968/2021', 'ANPD Res. 2/2022'],
    },
    {
      id: 'BR-GOV-003',
      name: 'e-Título / TSE — Manipulação de Biometria',
      tactic: 'Defense Evasion',
      severity: 'High',
      description:
        'Ataque de deepfake facial (spoofing biométrico) contra o sistema de autenticação do e-Título (TSE) e do Gov.br nível Prata/Ouro, utilizando GAN para gerar imagens faciais que enganam o liveness detection.',
      regulatory_impact: ['Res. TSE 23.659/2021', 'LGPD Art. 11 II-b', 'Decreto 10.046/2019'],
      kill_chain: [
        'Coleta de 100+ fotos da vítima via OSINT (LinkedIn, redes sociais)',
        'Treinamento de GAN (StyleGAN2) com dataset da vítima',
        'Geração de vídeo deepfake com movimentos de cabeça naturais',
        'Bypass do liveness detection via injeção de frame no stream V4L2',
        'Autenticação no Gov.br nível Ouro sem posse do celular da vítima',
      ],
      frameworks: ['Res. TSE 23.659/2021', 'LGPD Art. 11 II-b', 'ISO/IEC 30107-3 PAD', 'NIST SP 800-76-2'],
    },
    {
      id: 'BR-GOV-004',
      name: 'Serpro DataPrev — Fraude Previdenciária via API INSS',
      tactic: 'Impact',
      severity: 'Critical',
      description:
        'Exploração de falha de controle de acesso na API da DataPrev/INSS para alteração de dados cadastrais previdenciários, habilitando saques indevidos do FGTS, BPC e benefícios do INSS sem interação da vítima.',
      regulatory_impact: ['Lei 8.213/91', 'LGPD Art. 46', 'IN INSS 128/2022', 'Decreto 3.048/99'],
      kill_chain: [
        'Comprometimento de credencial de servidor DataPrev via spear-phishing',
        'Autenticação na rede interna DataPrev via VPN comprometida',
        'Identificação de endpoint PUT /api/v1/beneficiarios/{nb}/dados-bancarios sem 2FA',
        'Alteração de conta bancária para mula financeira',
        'Acionamento de saque automático em 300+ benefícios simultâneos',
        'Lavagem via PIX instantâneo fragmentado (smurfing)',
      ],
      frameworks: ['Lei 8.213/91', 'IN INSS 128/2022', 'LGPD Art. 46', 'Decreto 3.048/99', 'COAF Res. 36/2021'],
    },
    {
      id: 'BR-GOV-005',
      name: 'Conecta Gov — SSRF para Rede Interna Federal',
      tactic: 'Initial Access',
      severity: 'High',
      description:
        'Server-Side Request Forgery no portal Conecta Gov (plataforma de APIs do governo federal) para pivoting para redes internas de órgãos federais, incluindo ministérios, TCU, AGU e tribunais superiores.',
      regulatory_impact: ['Decreto 10.046/2019', 'LGPD Art. 46', 'IN SGD/ME 1/2019', 'NCIIPC Guidelines'],
      kill_chain: [
        'Identificação de parâmetro URL sem validação no Conecta Gov',
        'Envio de payload SSRF apontando para 169.254.169.254 (metadata)',
        'Enumeração de hosts internos via timing-based port scan',
        'Acesso a serviços sem autenticação na rede 10.0.0.0/8 federal',
        'Exfiltração de segredos AWS/Azure da infraestrutura de nuvem gov',
      ],
      frameworks: ['OWASP SSRF Prevention', 'LGPD Art. 46', 'IN SGD/ME 1/2019', 'Decreto 10.046/2019'],
    },
  ],
}

const CATEGORIES = [
  {
    key: 'nfe_sped',
    label: 'NF-e / SPED Fiscal',
    icon: FileText,
    color: 'orange',
    description: 'Ataques a sistemas de notas fiscais eletrônicas, SPED Contábil/Fiscal e integração com SEFAZ',
    apiPath: 'nfe-sped',
  },
  {
    key: 'drex',
    label: 'DREX / CBDC',
    icon: Zap,
    color: 'yellow',
    description: 'Ataques ao Real Digital brasileiro — smart contracts, nós validadores e KYC/AML da DLT BACEN',
    apiPath: 'drex',
  },
  {
    key: 'govbr_serpro',
    label: 'Gov.br / Serpro',
    icon: Globe,
    color: 'blue',
    description: 'Exploração de plataformas do governo federal: Gov.br, Serpro, DataPrev, Conecta Gov e e-Título',
    apiPath: 'govbr-serpro',
  },
]

// ---------------------------------------------------------------------------
// Kill chain step component
// ---------------------------------------------------------------------------
function KillChainSteps({ steps }) {
  return (
    <ol className="space-y-1.5 mt-2">
      {steps.map((step, i) => (
        <li key={i} className="flex gap-2.5 text-xs">
          <span className="flex-shrink-0 w-5 h-5 rounded-full bg-dark-600 border border-dark-500 flex items-center justify-center text-[10px] font-bold text-gray-400">
            {i + 1}
          </span>
          <span className="text-gray-400 leading-relaxed pt-0.5">{step}</span>
        </li>
      ))}
    </ol>
  )
}

// ---------------------------------------------------------------------------
// Regulatory Exposure Modal
// ---------------------------------------------------------------------------
function RegulatoryModal({ scenario, onClose }) {
  if (!scenario) return null
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-dark-800 border border-dark-500 rounded-xl max-w-lg w-full shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-start p-6 border-b border-dark-600">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-5 h-5 text-orange-400" />
              <h2 className="text-lg font-bold text-gray-100">Exposicao Regulatoria</h2>
            </div>
            <p className="text-xs text-gray-400">{scenario.name}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 transition mt-0.5">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Frameworks e Normas em Risco</p>
            <div className="flex flex-wrap gap-2">
              {scenario.frameworks.map(f => (
                <span
                  key={f}
                  className="text-xs px-3 py-1.5 rounded-lg bg-red-900/30 border border-red-700/40 text-red-300 font-medium"
                >
                  {f}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Impacto Regulatorio Direto</p>
            <div className="flex flex-wrap gap-2">
              {scenario.regulatory_impact.map(r => (
                <span
                  key={r}
                  className="text-xs px-3 py-1.5 rounded-lg bg-amber-900/30 border border-amber-700/40 text-amber-300 font-medium"
                >
                  {r}
                </span>
              ))}
            </div>
          </div>
          <div className="bg-dark-700 rounded-lg p-4 border border-dark-600">
            <p className="text-xs text-gray-400 leading-relaxed">
              A exploracao bem-sucedida deste cenario pode resultar em <strong className="text-red-400">autuacoes, multas e responsabilizacao criminal</strong> sob as normas listadas.
              A validacao proativa via BAS permite corrigir as exposicoes antes de um incidente real.
            </p>
          </div>
        </div>
        <div className="p-5 border-t border-dark-600 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg transition text-sm"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Simulate Modal
// ---------------------------------------------------------------------------
function SimulateModal({ scenario, onClose, onConfirm, loading }) {
  const [target, setTarget] = useState('')
  if (!scenario) return null
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-dark-800 border border-dark-500 rounded-xl max-w-md w-full shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-start p-6 border-b border-dark-600">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Target className="w-5 h-5 text-red-400" />
              <h2 className="text-lg font-bold text-gray-100">Simular Cenario</h2>
            </div>
            <p className="text-xs text-gray-500 font-mono">{scenario.id}</p>
            <p className="text-sm text-gray-300 mt-1">{scenario.name}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 transition mt-0.5">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Host / URL Alvo</label>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && target.trim() && onConfirm(scenario, target)}
              placeholder="ex: 192.168.1.10 ou https://sefaz.alvo.com.br"
              className="input-dark w-full"
              autoFocus
            />
          </div>
          <div className="bg-dark-700 rounded-lg p-3 text-xs text-gray-400 space-y-1 border border-dark-600">
            <p><span className="text-gray-500">Cenario:</span> <span className="text-gray-300 font-mono">{scenario.id}</span></p>
            <p><span className="text-gray-500">Severidade:</span> <span className={SEV_COLOR[scenario.severity]}>{SEV_PT[scenario.severity]}</span></p>
            <p><span className="text-gray-500">Tatica:</span> <span className="text-gray-300">{scenario.tactic}</span></p>
          </div>
          <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-3 text-xs text-red-400 flex gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>
              Execute <strong>apenas em ambientes autorizados</strong>. O uso indevido viola leis brasileiras —
              Lei 12.737/12 (Carolina Dieckmann), Codigo Penal Arts. 154-A/B.
            </span>
          </div>
        </div>
        <div className="flex justify-end gap-3 p-5 border-t border-dark-600">
          <button onClick={onClose} className="px-4 py-2 bg-dark-700 hover:bg-dark-600 text-gray-300 rounded-lg transition text-sm">
            Cancelar
          </button>
          <button
            onClick={() => target.trim() && onConfirm(scenario, target)}
            disabled={!target.trim() || loading}
            className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg transition text-sm font-medium"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            Iniciar Simulacao
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Scenario Card
// ---------------------------------------------------------------------------
function ScenarioCard({ scenario, onSimulate, onShowExposure }) {
  const [expanded, setExpanded] = useState(false)

  const borderColor = {
    Critical: 'border-l-4 border-red-600 hover:border-red-500',
    High:     'border-l-4 border-orange-600 hover:border-orange-500',
    Medium:   'border-l-4 border-yellow-600 hover:border-yellow-500',
    Low:      'border-l-4 border-blue-600 hover:border-blue-500',
  }[scenario.severity] || 'border-l-4 border-dark-500'

  const glowBg = {
    Critical: 'bg-red-950/20',
    High:     'bg-orange-950/20',
    Medium:   'bg-yellow-950/10',
    Low:      'bg-blue-950/10',
  }[scenario.severity] || ''

  return (
    <div className={`rounded-xl border border-dark-600 overflow-hidden transition-all duration-200 ${borderColor} ${glowBg}`}>
      {/* Card header */}
      <div className="p-5">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-2">
              {/* ID badge */}
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-dark-600 border border-dark-500 text-gray-400">
                {scenario.id}
              </span>
              {/* Severity */}
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${SEV_BG[scenario.severity]}`}>
                {SEV_PT[scenario.severity].toUpperCase()}
              </span>
              {/* Tactic */}
              <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${getTacticColor(scenario.tactic)}`}>
                {scenario.tactic}
              </span>
            </div>
            <h3 className="font-bold text-gray-100 text-base leading-snug">{scenario.name}</h3>
          </div>
        </div>

        <p className="text-sm text-gray-400 leading-relaxed mb-4">{scenario.description}</p>

        {/* Regulatory impact tags */}
        <div className="flex flex-wrap gap-1.5 mb-4">
          {scenario.regulatory_impact.map(tag => (
            <span
              key={tag}
              className="text-[10px] px-2 py-0.5 rounded bg-amber-900/20 border border-amber-700/30 text-amber-400"
            >
              {tag}
            </span>
          ))}
        </div>

        {/* Kill chain toggle */}
        <button
          onClick={() => setExpanded(e => !e)}
          className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition mb-1"
        >
          {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          <span className="font-medium">Kill Chain ({scenario.kill_chain.length} etapas)</span>
        </button>

        {expanded && <KillChainSteps steps={scenario.kill_chain} />}
      </div>

      {/* Card footer — action buttons */}
      <div className="flex gap-2 px-5 py-3 border-t border-dark-600/60 bg-dark-800/60">
        <button
          onClick={() => onSimulate(scenario)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-red-800 hover:bg-red-700 text-white rounded-lg text-xs font-semibold transition"
        >
          <Play className="w-3 h-3" />
          Simular
        </button>
        <button
          onClick={() => onShowExposure(scenario)}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-dark-600 hover:bg-dark-500 border border-dark-500 hover:border-orange-600/50 text-orange-400 rounded-lg text-xs font-medium transition"
        >
          <ShieldAlert className="w-3 h-3" />
          Exposicao Regulatoria
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Statistics Panel
// ---------------------------------------------------------------------------
function StatsPanel({ scenarios }) {
  const total = scenarios.length
  const bySev = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  scenarios.forEach(s => { if (s.severity in bySev) bySev[s.severity]++ })

  const pct = (n) => total > 0 ? ((n / total) * 100).toFixed(0) : 0

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {[
        { label: 'Total de Cenarios', value: total, color: 'text-gray-100', bg: 'bg-dark-700' },
        { label: 'Critico', value: bySev.Critical, color: 'text-red-400', bg: 'bg-red-950/40 border border-red-800/30' },
        { label: 'Alto', value: bySev.High, color: 'text-orange-400', bg: 'bg-orange-950/40 border border-orange-800/30' },
        { label: 'Medio', value: bySev.Medium, color: 'text-yellow-400', bg: 'bg-yellow-950/40 border border-yellow-800/30' },
      ].map(({ label, value, color, bg }) => (
        <div key={label} className={`rounded-xl p-4 ${bg}`}>
          <p className={`text-2xl font-black ${color}`}>{value}</p>
          <p className="text-xs text-gray-500 mt-0.5">{label}</p>
          {value > 0 && total > 0 && label !== 'Total de Cenarios' && (
            <div className="mt-2">
              <div className="h-1 bg-dark-600 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    label === 'Critico' ? 'bg-red-500' :
                    label === 'Alto'    ? 'bg-orange-500' :
                    label === 'Medio'   ? 'bg-yellow-500' : 'bg-blue-500'
                  }`}
                  style={{ width: `${pct(value)}%` }}
                />
              </div>
              <p className="text-[10px] text-gray-600 mt-1">{pct(value)}% dos cenarios</p>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------
export default function BRFiscal() {
  const toast = useToast()
  const [activeTab, setActiveTab] = useState('nfe_sped')
  const [scenarios, setScenarios] = useState(FALLBACK_SCENARIOS)
  const [loading, setLoading] = useState(true)
  const [simulating, setSimulating] = useState(false)
  const [simulateModal, setSimulateModal] = useState(null)
  const [exposureModal, setExposureModal] = useState(null)
  const [usingFallback, setUsingFallback] = useState(false)

  const activeCategory = CATEGORIES.find(c => c.key === activeTab)
  const activeScenarios = scenarios[activeTab] || []

  useEffect(() => {
    fetchScenarios()
  }, [])

  const fetchScenarios = async () => {
    setLoading(true)
    try {
      const results = {}
      await Promise.all(
        CATEGORIES.map(async (cat) => {
          const res = await api.get(`/api/br-fiscal/${cat.apiPath}/scenarios`)
          results[cat.key] = res.data.scenarios || FALLBACK_SCENARIOS[cat.key]
        })
      )
      setScenarios(results)
      setUsingFallback(false)
    } catch {
      setScenarios(FALLBACK_SCENARIOS)
      setUsingFallback(true)
    } finally {
      setLoading(false)
    }
  }

  const handleSimulate = async (scenario, target) => {
    setSimulating(true)
    try {
      await api.post(`/api/br-fiscal/scenarios/${scenario.id}/simulate`, { target })
      toast(`Simulacao "${scenario.name}" iniciada para ${target}`, 'success')
      setSimulateModal(null)
    } catch (err) {
      toast(
        'Erro ao simular: ' + (err.response?.data?.detail || err.message),
        'error'
      )
    } finally {
      setSimulating(false)
    }
  }

  const totalAll = Object.values(scenarios).flat().length
  const criticalAll = Object.values(scenarios).flat().filter(s => s.severity === 'Critical').length

  const tabColorMap = {
    orange: {
      active: 'bg-orange-900/40 border-b-2 border-orange-500 text-orange-300',
      inactive: 'text-gray-500 hover:text-gray-300 hover:bg-dark-700',
    },
    yellow: {
      active: 'bg-yellow-900/40 border-b-2 border-yellow-500 text-yellow-300',
      inactive: 'text-gray-500 hover:text-gray-300 hover:bg-dark-700',
    },
    blue: {
      active: 'bg-blue-900/40 border-b-2 border-blue-500 text-blue-300',
      inactive: 'text-gray-500 hover:text-gray-300 hover:bg-dark-700',
    },
  }

  return (
    <div className="space-y-8">
      {/* ------------------------------------------------------------------ */}
      {/* Header */}
      {/* ------------------------------------------------------------------ */}
      <div className="slide-in">
        <div className="flex items-center gap-3 mb-2">
          <h1 className="text-4xl font-bold text-gray-100">BAS Brasil</h1>
          <span className="text-3xl" role="img" aria-label="Bandeira do Brasil">🇧🇷</span>
          <span className="text-xs font-bold px-3 py-1.5 rounded-full bg-green-900/50 border border-green-600/60 text-green-400 uppercase tracking-widest">
            Exclusivo Brasil
          </span>
        </div>
        <p className="text-gray-400 leading-relaxed max-w-3xl">
          Cenarios de ataque exclusivos ao ecossistema fiscal e de infraestrutura critica brasileiro.
          Zero outras plataformas BAS no mundo cobrem NF-e, DREX e Gov.br.
        </p>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Competitive differentiator banner */}
      {/* ------------------------------------------------------------------ */}
      <div className="relative overflow-hidden rounded-2xl border border-green-700/30 bg-gradient-to-r from-green-950/60 via-dark-800 to-blue-950/40 p-6">
        <div className="absolute inset-0 bg-gradient-to-br from-green-900/10 to-transparent pointer-events-none" />
        <div className="relative flex flex-col sm:flex-row items-start sm:items-center gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <Flag className="w-5 h-5 text-green-400" />
              <span className="text-sm font-bold text-green-400 uppercase tracking-wide">Diferencial Competitivo</span>
            </div>
            <h2 className="text-xl font-bold text-gray-100 mb-1">
              Unico BAS com cobertura do ecossistema fiscal brasileiro
            </h2>
            <p className="text-sm text-gray-400">
              Mandiant, AttackIQ, Cymulate e Picus Security nao possuem cenarios para NF-e/SPED, DREX/CBDC,
              Gov.br e Serpro. A PenteIA e a primeira plataforma a cobrir o risco fiscal e regulatorio do mercado brasileiro.
            </p>
          </div>
          <div className="flex gap-6 text-center flex-shrink-0">
            <div>
              <p className="text-3xl font-black text-green-400">{totalAll}</p>
              <p className="text-xs text-gray-500">Cenarios BR</p>
            </div>
            <div>
              <p className="text-3xl font-black text-red-400">{criticalAll}</p>
              <p className="text-xs text-gray-500">Criticos</p>
            </div>
            <div>
              <p className="text-3xl font-black text-blue-400">3</p>
              <p className="text-xs text-gray-500">Categorias</p>
            </div>
          </div>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Fallback notice */}
      {/* ------------------------------------------------------------------ */}
      {usingFallback && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-amber-900/20 border border-amber-700/40 text-amber-400 text-xs">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>API indisponivel — exibindo cenarios de demonstracao. Os dados de simulacao nao serao persistidos.</span>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Category Tabs */}
      {/* ------------------------------------------------------------------ */}
      <div className="card-dark overflow-hidden">
        {/* Tab bar */}
        <div className="flex border-b border-dark-600">
          {CATEGORIES.map(cat => {
            const Icon = cat.icon
            const isActive = activeTab === cat.key
            const colors = tabColorMap[cat.color]
            const count = (scenarios[cat.key] || []).length
            return (
              <button
                key={cat.key}
                onClick={() => setActiveTab(cat.key)}
                className={`flex items-center gap-2 px-5 py-3.5 text-sm font-semibold transition-all duration-150 flex-1 justify-center ${
                  isActive ? colors.active : colors.inactive
                }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <span className="hidden sm:inline">{cat.label}</span>
                <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                  isActive
                    ? 'bg-dark-600 text-gray-300'
                    : 'bg-dark-700 text-gray-600'
                }`}>
                  {loading ? '…' : count}
                </span>
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="p-6 space-y-6">
          {/* Category description */}
          {activeCategory && (
            <div className="flex items-start gap-3 p-4 rounded-xl bg-dark-700 border border-dark-600">
              <BookOpen className="w-5 h-5 text-gray-400 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-gray-400 leading-relaxed">{activeCategory.description}</p>
            </div>
          )}

          {/* Statistics */}
          {!loading && activeScenarios.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <BarChart2 className="w-4 h-4 text-gray-500" />
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">
                  Distribuicao de Severidade — {activeCategory?.label}
                </h3>
              </div>
              <StatsPanel scenarios={activeScenarios} />
            </div>
          )}

          {/* Loading skeleton */}
          {loading && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {[1, 2, 3, 4].map(i => (
                <div key={i} className="rounded-xl border border-dark-600 p-5 animate-pulse">
                  <div className="h-4 bg-dark-700 rounded w-1/3 mb-3" />
                  <div className="h-6 bg-dark-700 rounded w-3/4 mb-4" />
                  <div className="h-16 bg-dark-700 rounded mb-4" />
                  <div className="flex gap-2">
                    <div className="h-4 bg-dark-700 rounded w-20" />
                    <div className="h-4 bg-dark-700 rounded w-24" />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Scenario cards */}
          {!loading && activeScenarios.length > 0 && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {activeScenarios.map(scenario => (
                <ScenarioCard
                  key={scenario.id}
                  scenario={scenario}
                  onSimulate={setSimulateModal}
                  onShowExposure={setExposureModal}
                />
              ))}
            </div>
          )}

          {!loading && activeScenarios.length === 0 && (
            <div className="text-center py-12 border border-dashed border-dark-600 rounded-xl">
              <Lock className="w-10 h-10 text-gray-700 mx-auto mb-3" />
              <p className="text-gray-500">Nenhum cenario disponivel nesta categoria.</p>
            </div>
          )}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Global coverage summary */}
      {/* ------------------------------------------------------------------ */}
      <div className="card-dark p-6">
        <div className="flex items-center gap-2 mb-4">
          <BarChart2 className="w-5 h-5 text-gray-400" />
          <h2 className="text-lg font-bold text-gray-100">Cobertura Total de Cenarios Brasileiros</h2>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {CATEGORIES.map(cat => {
            const catScenarios = scenarios[cat.key] || []
            const critical = catScenarios.filter(s => s.severity === 'Critical').length
            const high = catScenarios.filter(s => s.severity === 'High').length
            const Icon = cat.icon
            const colorMap = {
              orange: { text: 'text-orange-400', border: 'border-orange-700/40', bg: 'bg-orange-950/30' },
              yellow: { text: 'text-yellow-400', border: 'border-yellow-700/40', bg: 'bg-yellow-950/30' },
              blue:   { text: 'text-blue-400',   border: 'border-blue-700/40',   bg: 'bg-blue-950/30'   },
            }[cat.color]
            return (
              <div
                key={cat.key}
                className={`rounded-xl p-4 border cursor-pointer transition-all ${colorMap.bg} ${colorMap.border} ${
                  activeTab === cat.key ? 'ring-1 ring-inset ring-current' : 'hover:opacity-90'
                }`}
                onClick={() => setActiveTab(cat.key)}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Icon className={`w-4 h-4 ${colorMap.text}`} />
                  <span className={`text-xs font-semibold ${colorMap.text}`}>{cat.label}</span>
                </div>
                <div className="flex items-end gap-3">
                  <span className={`text-4xl font-black ${colorMap.text}`}>{catScenarios.length}</span>
                  <div className="pb-1 text-xs text-gray-500 space-y-0.5">
                    <p><span className="text-red-400 font-bold">{critical}</span> criticos</p>
                    <p><span className="text-orange-400 font-bold">{high}</span> altos</p>
                  </div>
                </div>
                <p className="text-xs text-gray-600 mt-2 leading-snug">{cat.description.split('.')[0]}.</p>
              </div>
            )
          })}
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Legal disclaimer */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex items-start gap-3 px-4 py-3 rounded-xl bg-red-900/15 border border-red-700/30 text-red-400 text-xs">
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <span>
          <strong>Aviso Legal:</strong> Todos os cenarios devem ser executados exclusivamente em ambientes
          com autorizacao formal documentada. O uso nao autorizado pode configurar crimes tipificados na
          Lei 12.737/12, Codigo Penal Arts. 154-A e 154-B, e sujeitar o responsavel a responsabilizacao
          civil e criminal.
        </span>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/* Modals */}
      {/* ------------------------------------------------------------------ */}
      {simulateModal && (
        <SimulateModal
          scenario={simulateModal}
          onClose={() => setSimulateModal(null)}
          onConfirm={handleSimulate}
          loading={simulating}
        />
      )}

      {exposureModal && (
        <RegulatoryModal
          scenario={exposureModal}
          onClose={() => setExposureModal(null)}
        />
      )}
    </div>
  )
}
