# 🔐 Criptografador de Arquivos Rust

Aplicação desktop para criptografar e descriptografar arquivos TXT usando criptografia AES-256-GCM.

## ✨ Características

- Criptografia AES-256-GCM (padrão militar)
- Interface gráfica moderna e intuitiva
- Visualização de senha opcional
- Indicador de força de senha
- Feedback visual de operações

## 🛠️ Requisitos

- Rust 1.70 ou superior
- Cargo

## 📦 Instalação
```bash
git clone https://github.com/igorFerreiraB/criptografador.git
cd criptografador
cargo build --release
```

## 🚀 Uso
```bash
cargo run --release
```

### Como Criptografar

1. Selecione o modo "Criptografar"
2. Clique em "Buscar" e escolha seu arquivo .txt
3. Digite uma senha forte
4. Clique em "Criptografar Arquivo"
5. O arquivo criptografado será salvo com extensão `.encrypted`

### Como Descriptografar

1. Selecione o modo "Descriptografar"
2. Escolha o arquivo `.encrypted`
3. Digite a mesma senha usada na criptografia
4. Clique em "Descriptografar Arquivo"
5. O arquivo será salvo com extensão `.decrypted.txt`