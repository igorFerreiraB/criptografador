// Cargo.toml dependencies:
// [dependencies]
// eframe = "0.24"
// egui = "0.24"
// aes-gcm = "0.10"
// rand = "0.8"
// base64 = "0.21"
// rfd = "0.12"

use eframe::egui;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use rand::RngCore;
use std::fs;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_resizable(true),
        ..Default::default()
    };
    
    eframe::run_native(
        "Criptografador de Arquivos",
        options,
        Box::new(|_cc| Box::new(CryptoApp::default())),
    )
}

struct CryptoApp {
    mode: Mode,
    file_path: String,
    password: String,
    status_message: String,
    status_color: egui::Color32,
    show_password: bool,
}

#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl Default for CryptoApp {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            file_path: String::new(),
            password: String::new(),
            status_message: String::new(),
            status_color: egui::Color32::GRAY,
            show_password: false,
        }
    }
}

impl eframe::App for CryptoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.heading("🔐 Criptografador de Arquivos");
                ui.add_space(10.0);
                ui.label("Proteja seus arquivos com criptografia AES-256");
                ui.add_space(20.0);
            });

            ui.separator();
            ui.add_space(20.0);

            // Seleção de modo
            ui.horizontal(|ui| {
                ui.label("Modo:");
                ui.add_space(10.0);
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "🔒 Criptografar");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "🔓 Descriptografar");
            });

            ui.add_space(20.0);

            // Seleção de arquivo
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.label("Arquivo:");
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        let text_edit = egui::TextEdit::singleline(&mut self.file_path)
                            .hint_text("Selecione um arquivo...")
                            .desired_width(ui.available_width() - 100.0);
                        ui.add(text_edit);
                        
                        if ui.button("📁 Buscar").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Arquivos de texto", &["txt", "encrypted"])
                                .pick_file()
                            {
                                self.file_path = path.display().to_string();
                            }
                        }
                    });
                });
            });

            ui.add_space(20.0);

            // Campo de senha
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical(|ui| {
                    ui.label("Senha:");
                    ui.add_space(5.0);
                    
                    ui.horizontal(|ui| {
                        let password_edit = if self.show_password {
                            egui::TextEdit::singleline(&mut self.password)
                        } else {
                            egui::TextEdit::singleline(&mut self.password)
                                .password(true)
                        }
                        .hint_text("Digite uma senha forte...")
                        .desired_width(ui.available_width() - 100.0);
                        
                        ui.add(password_edit);
                        
                        let eye_icon = if self.show_password { "👁" } else { "👁‍🗨" };
                        if ui.button(eye_icon).clicked() {
                            self.show_password = !self.show_password;
                        }
                    });
                    
                    if !self.password.is_empty() {
                        ui.add_space(5.0);
                        let strength = password_strength(&self.password);
                        ui.horizontal(|ui| {
                            ui.label("Força:");
                            let (text, color) = match strength {
                                0..=2 => ("Fraca", egui::Color32::RED),
                                3..=4 => ("Média", egui::Color32::YELLOW),
                                _ => ("Forte", egui::Color32::GREEN),
                            };
                            ui.colored_label(color, text);
                        });
                    }
                });
            });

            ui.add_space(30.0);

            // Botão principal
            ui.vertical_centered(|ui| {
                let button_text = match self.mode {
                    Mode::Encrypt => "🔒 Criptografar Arquivo",
                    Mode::Decrypt => "🔓 Descriptografar Arquivo",
                };
                
                let button = egui::Button::new(button_text)
                    .min_size(egui::vec2(200.0, 40.0));
                
                let can_process = !self.file_path.is_empty() && !self.password.is_empty();
                
                ui.add_enabled_ui(can_process, |ui| {
                    if ui.add(button).clicked() {
                        self.process_file();
                    }
                });
                
                if !can_process {
                    ui.add_space(5.0);
                    ui.small("Preencha todos os campos");
                }
            });

            ui.add_space(20.0);

            // Mensagem de status
            if !self.status_message.is_empty() {
                ui.separator();
                ui.add_space(10.0);
                
                egui::Frame::none()
                    .fill(self.status_color.linear_multiply(0.1))
                    .rounding(5.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.colored_label(self.status_color, &self.status_message);
                    });
            }
        });
    }
}

impl CryptoApp {
    fn process_file(&mut self) {
        match self.mode {
            Mode::Encrypt => self.encrypt_file(),
            Mode::Decrypt => self.decrypt_file(),
        }
    }
    
    fn encrypt_file(&mut self) {
        let content = match fs::read_to_string(&self.file_path) {
            Ok(c) => c,
            Err(e) => {
                self.show_error(&format!("Erro ao ler arquivo: {}", e));
                return;
            }
        };
        
        let key = derive_key(&self.password);
        let cipher = Aes256Gcm::new(&key.into());
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = match cipher.encrypt(nonce, content.as_bytes()) {
            Ok(ct) => ct,
            Err(e) => {
                self.show_error(&format!("Erro ao criptografar: {}", e));
                return;
            }
        };
        
        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&ciphertext);
        let encoded = base64::encode(&combined);
        
        let output_path = format!("{}.encrypted", self.file_path);
        match fs::write(&output_path, encoded) {
            Ok(_) => self.show_success(&format!("✓ Arquivo criptografado: {}", output_path)),
            Err(e) => self.show_error(&format!("Erro ao salvar: {}", e)),
        }
    }
    
    fn decrypt_file(&mut self) {
        let encoded = match fs::read_to_string(&self.file_path) {
            Ok(c) => c,
            Err(e) => {
                self.show_error(&format!("Erro ao ler arquivo: {}", e));
                return;
            }
        };
        
        let combined = match base64::decode(encoded.trim()) {
            Ok(d) => d,
            Err(e) => {
                self.show_error(&format!("Erro ao decodificar: {}", e));
                return;
            }
        };
        
        if combined.len() < 12 {
            self.show_error("Arquivo inválido!");
            return;
        }
        
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let key = derive_key(&self.password);
        let cipher = Aes256Gcm::new(&key.into());
        
        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(pt) => pt,
            Err(_) => {
                self.show_error("✗ Senha incorreta ou arquivo corrompido!");
                return;
            }
        };
        
        let content = match String::from_utf8(plaintext) {
            Ok(s) => s,
            Err(e) => {
                self.show_error(&format!("Erro ao converter texto: {}", e));
                return;
            }
        };
        
        let output_path = self.file_path.replace(".encrypted", ".decrypted.txt");
        match fs::write(&output_path, content) {
            Ok(_) => self.show_success(&format!("✓ Arquivo descriptografado: {}", output_path)),
            Err(e) => self.show_error(&format!("Erro ao salvar: {}", e)),
        }
    }
    
    fn show_success(&mut self, message: &str) {
        self.status_message = message.to_string();
        self.status_color = egui::Color32::GREEN;
    }
    
    fn show_error(&mut self, message: &str) {
        self.status_message = message.to_string();
        self.status_color = egui::Color32::RED;
    }
}

fn derive_key(password: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut key = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let hash = hasher.finish();
    
    for i in 0..4 {
        let bytes = hash.wrapping_mul(i as u64 + 1).to_le_bytes();
        key[i*8..(i+1)*8].copy_from_slice(&bytes);
    }
    
    key
}

fn password_strength(password: &str) -> u8 {
    let mut strength = 0u8;
    
    if password.len() >= 8 { strength += 1; }
    if password.len() >= 12 { strength += 1; }
    if password.chars().any(|c| c.is_lowercase()) { strength += 1; }
    if password.chars().any(|c| c.is_uppercase()) { strength += 1; }
    if password.chars().any(|c| c.is_numeric()) { strength += 1; }
    if password.chars().any(|c| !c.is_alphanumeric()) { strength += 1; }
    
    strength
}