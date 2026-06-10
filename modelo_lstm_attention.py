#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Motor neural opcional do PenteIA: BiLSTM + Attention (aditiva, estilo Zhou et al. 2016).

Arquitetura:
    Embedding -> BiLSTM -> Attention pooling (additive) -> Dense -> sigmoid

A camada de attention aprende um peso para cada passo de tempo (token) da saída do
BiLSTM e produz um vetor de contexto ponderado, em vez de usar apenas o último estado.
É o mecanismo de attention clássico aplicado a LSTM (NÃO é "Flash Attention", que é um
kernel de GPU para Transformers — irrelevante em CPU).

Roda em CPU (PyTorch). Expõe uma interface compatível com o scanner:
    modelo.predict_proba(lista_de_textos) -> np.ndarray shape (n, 2)

Artefatos salvos:
    modelos/penteia_lstm.pt          -> pesos + vocabulário + configuração
    modelos/model_meta.json          -> metadados (engine = pytorch-lstm-attention)
"""

import os
import re
import json
from datetime import datetime

import numpy as np

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

MODEL_DIR = "modelos"
LSTM_PATH = os.path.join(MODEL_DIR, "penteia_lstm.pt")
META_PATH = os.path.join(MODEL_DIR, "model_meta.json")

# Tokenização: mantém palavras E pontuação relevante para payloads (<, >, ', ;, |, &, $...)
_TOKEN_RE = re.compile(r"[a-z0-9_]+|[<>'\"/();=|&$`%.\\:\-\[\]{}!?]")

PAD, UNK = 0, 1


def tokenizar(texto, max_len):
    if not isinstance(texto, str):
        texto = str(texto)
    return _TOKEN_RE.findall(texto.lower())[:max_len]


def construir_vocab(textos, max_vocab, max_len):
    from collections import Counter
    contador = Counter()
    for t in textos:
        contador.update(tokenizar(t, max_len))
    vocab = {"<pad>": PAD, "<unk>": UNK}
    for tok, _ in contador.most_common(max_vocab - 2):
        vocab[tok] = len(vocab)
    return vocab


def textos_para_tensor(textos, vocab, max_len):
    seqs = []
    for t in textos:
        ids = [vocab.get(tok, UNK) for tok in tokenizar(t, max_len)]
        if not ids:
            ids = [UNK]
        seqs.append(ids)
    n = len(seqs)
    X = np.zeros((n, max_len), dtype=np.int64)
    mask = np.zeros((n, max_len), dtype=bool)
    for i, ids in enumerate(seqs):
        L = min(len(ids), max_len)
        X[i, :L] = ids[:L]
        mask[i, :L] = True
    return torch.from_numpy(X), torch.from_numpy(mask)


class AttnBiLSTM(nn.Module):
    """BiLSTM com camada de attention aditiva (Bahdanau-style) para pooling."""

    def __init__(self, vocab_size, emb_dim=128, hidden=128, dropout=0.3):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, emb_dim, padding_idx=PAD)
        self.lstm = nn.LSTM(emb_dim, hidden, batch_first=True, bidirectional=True)
        self.dropout = nn.Dropout(dropout)
        # Attention aditiva: score(h_t) = v^T tanh(W h_t)
        self.attn_W = nn.Linear(2 * hidden, 2 * hidden)
        self.attn_v = nn.Linear(2 * hidden, 1, bias=False)
        self.fc = nn.Linear(2 * hidden, 1)

    def forward(self, x, mask):
        e = self.dropout(self.emb(x))                  # (B, T, E)
        h, _ = self.lstm(e)                            # (B, T, 2H)
        # Pesos de attention por passo de tempo
        scores = self.attn_v(torch.tanh(self.attn_W(h))).squeeze(-1)  # (B, T)
        scores = scores.masked_fill(~mask, float("-inf"))
        alpha = torch.softmax(scores, dim=1).unsqueeze(-1)            # (B, T, 1)
        contexto = (h * alpha).sum(dim=1)              # (B, 2H) — pooling ponderado
        contexto = self.dropout(contexto)
        return self.fc(contexto).squeeze(-1)           # (B,) logit


class ModeloLSTM:
    """Wrapper com interface compatível com o scanner (predict_proba)."""

    def __init__(self, net, vocab, config):
        self.net = net
        self.vocab = vocab
        self.config = config
        self.max_len = config["max_len"]
        self.net.eval()

    @torch.no_grad()
    def predict_proba(self, textos):
        if isinstance(textos, str):
            textos = [textos]
        X, mask = textos_para_tensor(list(textos), self.vocab, self.max_len)
        probs = []
        bs = 128
        for i in range(0, len(X), bs):
            logits = self.net(X[i:i + bs], mask[i:i + bs])
            probs.append(torch.sigmoid(logits).cpu().numpy())
        p1 = np.concatenate(probs) if probs else np.array([])
        p1 = p1.reshape(-1)
        return np.column_stack([1.0 - p1, p1])

    def predict(self, textos):
        return (self.predict_proba(textos)[:, 1] >= 0.5).astype(int)


def treinar_lstm(textos, labels, epochs=8, batch_size=32, max_len=400,
                 max_vocab=20000, emb_dim=128, hidden=128, lr=1e-3,
                 val_split=0.2, seed=42, verbose=True):
    """Treina o BiLSTM+Attention e retorna (ModeloLSTM, acuracia_val)."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    # Usa GPU para TREINAR se disponível; a inferência/produção roda em CPU (ver carregar_lstm).
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if verbose:
        print(f"    Dispositivo de treino: {device}"
              + ("" if device.type == "cuda" else "  (instale o PyTorch com CUDA para usar a GPU)"))

    textos = [str(t) for t in textos]
    labels = np.asarray(labels, dtype=np.float32)

    vocab = construir_vocab(textos, max_vocab, max_len)
    X, mask = textos_para_tensor(textos, vocab, max_len)
    y = torch.from_numpy(labels)

    # Split treino/validação
    n = len(X)
    idx = np.random.permutation(n)
    n_val = max(1, int(n * val_split))
    val_idx, tr_idx = idx[:n_val], idx[n_val:]
    if len(tr_idx) == 0:
        tr_idx = idx

    ds_tr = TensorDataset(X[tr_idx], mask[tr_idx], y[tr_idx])
    dl_tr = DataLoader(ds_tr, batch_size=batch_size, shuffle=True)

    net = AttnBiLSTM(len(vocab), emb_dim=emb_dim, hidden=hidden).to(device)
    # class_weight via pos_weight para lidar com desbalanceamento
    n_pos = float(labels.sum())
    n_neg = float(len(labels) - n_pos)
    pos_weight = torch.tensor([n_neg / n_pos]).to(device) if n_pos > 0 else None
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optim = torch.optim.Adam(net.parameters(), lr=lr)

    # Tensores de validação no mesmo dispositivo
    Xval, mval = X[val_idx].to(device), mask[val_idx].to(device)
    yval_np = labels[val_idx].astype(int)

    melhor_acc, melhor_estado = 0.0, None
    for ep in range(epochs):
        net.train()
        perda_total = 0.0
        for xb, mb, yb in dl_tr:
            xb, mb, yb = xb.to(device), mb.to(device), yb.to(device)
            optim.zero_grad()
            logits = net(xb, mb)
            loss = criterion(logits, yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(net.parameters(), 5.0)
            optim.step()
            perda_total += float(loss) * len(xb)

        # Avaliação na validação
        net.eval()
        with torch.no_grad():
            vlogits = net(Xval, mval)
            vpred = (torch.sigmoid(vlogits) >= 0.5).int().cpu().numpy()
            acc = float((vpred == yval_np).mean())
        if verbose:
            print(f"    Época {ep+1}/{epochs} - loss: {perda_total/len(tr_idx):.4f} - val_acc: {acc*100:.2f}%")
        if acc >= melhor_acc:
            melhor_acc = acc
            melhor_estado = {k: v.detach().cpu().clone() for k, v in net.state_dict().items()}

    if melhor_estado is not None:
        net.load_state_dict(melhor_estado)

    # Move o modelo final para CPU: garante paridade com a produção (CPU) e salvamento portátil
    net.to("cpu")
    config = {"max_len": max_len, "emb_dim": emb_dim, "hidden": hidden, "max_vocab": max_vocab}
    return ModeloLSTM(net, vocab, config), melhor_acc


def salvar_lstm(modelo, acc, n_amostras):
    os.makedirs(MODEL_DIR, exist_ok=True)
    torch.save({
        "state_dict": modelo.net.state_dict(),
        "vocab": modelo.vocab,
        "config": modelo.config,
    }, LSTM_PATH)

    meta = {
        "version": "3.0-lstm-attention",
        "model_type": "bilstm+additive_attention",
        "engine": "pytorch-lstm-attention",
        "artifact": os.path.basename(LSTM_PATH),
        "trained_at": datetime.now().isoformat(),
        "n_samples": int(n_amostras),
        "accuracy": float(round(acc, 4)),
        "default_threshold": 0.8,
        "config": modelo.config,
        "input": "text",
        "output": "probabilidade de vulnerabilidade (classe 1)",
    }
    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4, ensure_ascii=False)
    return meta


def carregar_lstm(caminho=LSTM_PATH):
    """Carrega o modelo BiLSTM+Attention salvo e devolve um ModeloLSTM."""
    ckpt = torch.load(caminho, map_location="cpu", weights_only=False)
    vocab = ckpt["vocab"]
    config = ckpt["config"]
    net = AttnBiLSTM(len(vocab), emb_dim=config["emb_dim"], hidden=config["hidden"])
    net.load_state_dict(ckpt["state_dict"])
    return ModeloLSTM(net, vocab, config)
