# PenteIA v4.0 - Frontend React

Frontend moderno do PenteIA v4.0 usando React, Vite e Tailwind CSS.

## 🚀 Instalação

```bash
cd frontend
npm install
```

## 📦 Desenvolvimento

```bash
npm run dev
```

Acesse em: `http://localhost:5173`

## 🏗️ Build

```bash
npm run build
```

## 🎨 Estrutura

```
src/
├── components/     # Componentes reutilizáveis
│   ├── Navbar.jsx
│   ├── Footer.jsx
│   ├── StatCard.jsx
│   └── ModuleCard.jsx
├── pages/         # Páginas principais
│   ├── Dashboard.jsx
│   ├── Recon.jsx
│   ├── DDoS.jsx
│   ├── Modules.jsx
│   └── ...
├── App.jsx        # App principal com Router
└── index.css      # Estilos Tailwind
```

## 🛠️ Tecnologias

- **React 18** - UI framework
- **Vite** - Build tool
- **Tailwind CSS** - Estilos
- **React Router** - Navegação
- **Lucide React** - Ícones
- **Axios** - HTTP client

## 🔗 API

O frontend conecta com a API FastAPI em `http://localhost:8000`:

- `GET /api/health` - Health check
- `GET /api/status` - Status do sistema
- `POST /api/recon/resolve` - Resolver domínio
- `POST /api/recon/scan` - Varrer portas
- `GET /api/ddos/methods` - Métodos DDoS
- E mais...

## 📝 Notas

- Design dark theme moderno
- Totalmente responsivo
- Componentes reutilizáveis
- Fast refresh com Vite
