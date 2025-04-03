import plotly.express as px
import streamlit as st
import pandas as pd
from datetime import datetime
import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
import streamlit_authenticator as stauth
import logging
from sklearn.ensemble import GradientBoostingClassifier
import joblib
import yaml
import os
from datetime import datetime

# Configuração inicial da página (APENAS UMA VEZ, NO TOPO DO SCRIPT)
st.set_page_config(
    page_title="Painel de Fraudes",
    page_icon="🔍",
    layout="wide"
)

# --- Classe AnalisadorFraude ---
class AnalisadorFraude:
    def __init__(self):
        self.config = self.carregar_config()
        
    def carregar_config(self):
        config_padrao = {
            "regras": {
                "valor_alto": 100000,
                "horario_noturno": {"inicio": 22, "fim": 6}
            }
        }
        
        try:
            with open('config.yaml', 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or config_padrao
        except Exception as e:
            st.warning(f"⚠️ Erro no config.yaml: Usando regras padrão. Erro: {e}")
            return config_padrao

    def calcular_risco(self, transacao):
        try:
            risco = 0.0
            
            if isinstance(transacao["hora"], str):
                hora = datetime.strptime(transacao["hora"], "%H:%M").hour
            else:
                hora = transacao["hora"].hour
            
            if transacao["valor"] > self.config["regras"]["valor_alto"]:
                risco += 0.6
                
            if (hora >= self.config["regras"]["horario_noturno"]["inicio"] or 
                hora <= self.config["regras"]["horario_noturno"]["fim"]):
                risco += 0.3
                
            return min(risco, 1.0)
        except Exception as e:
            st.error(f"⚠️ Erro no cálculo de risco: {e}")
            return 0.0

class SistemaFraudeAvancado:
    def __init__(self):
        # Configura o logger primeiro
        self._logger = self._configurar_logging()
        self.logger.info("Inicializando sistema de detecção de fraudes...")
        
        # Inicializa os componentes
        self.modelo = None
        self.analisador = AnalisadorFraude()
        
        # Carrega o modelo apenas uma vez
        self._modelo_carregado = False
        self.carregar_modelo()

    def _configurar_logging(self):
        """Configuração privada do sistema de logging"""
        logger = logging.getLogger('FraudeLogger')
        logger.setLevel(logging.INFO)
        
        # Limpa handlers existentes para evitar duplicação
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # Configura handlers
        handlers = [
            logging.FileHandler('fraude_detection.log'),
            logging.StreamHandler()
        ]
        
        for handler in handlers:
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger

    def carregar_modelo(self, forcar_recarga=False):
        """Carrega o modelo com controle de estado"""
        if self._modelo_carregado and not forcar_recarga:
            return
            
        try:
            self.modelo = joblib.load('modelo_avancado.pkl')
            self._modelo_carregado = True
            self.logger.info("Modelo de fraude carregado com sucesso")
        except FileNotFoundError:
            self.logger.warning("Modelo não encontrado. Treinando novo modelo...")
            self._treinar_novo_modelo()
        except Exception as e:
            self.logger.error(f"Erro crítico ao carregar modelo: {str(e)}")
            raise

    def _treinar_novo_modelo(self):
        """Treina e salva um novo modelo"""
        try:
            self.logger.info("Iniciando treinamento do novo modelo...")
            
            self.modelo = GradientBoostingClassifier(
                n_estimators=150,  # Aumentado para melhor performance
                learning_rate=0.1,
                max_depth=4,
                random_state=42,
                verbose=1
            )
            
            # Dados de treino mais robustos
            dados_treino = pd.DataFrame({
                'valor': [100, 200, 300, 50, 5000, 150, 250, 100000, 75, 1200, 30000, 80, 350],
                'hora': [10, 14, 18, 9, 3, 12, 15, 4, 11, 2, 1, 8, 19],
                'tipo': [0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0]
            })
            
            alvo = [0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0]
            
            self.modelo.fit(dados_treino, alvo)
            
            # Tenta salvar o modelo em até 3 locais diferentes
            locais_tentativa = [
                'modelo_avancado.pkl',
                './modelo_avancado.pkl',
                os.path.join(os.path.dirname(__file__), 'modelo_avancado.pkl')
            ]
            
            for local in locais_tentativa:
                try:
                    joblib.dump(self.modelo, local)
                    self.logger.info(f"Modelo salvo com sucesso em: {local}")
                    self._modelo_carregado = True
                    break
                except Exception as e:
                    self.logger.warning(f"Falha ao salvar em {local}: {str(e)}")
            
            if not self._modelo_carregado:
                raise RuntimeError("Não foi possível salvar o modelo em nenhum local")
                
        except Exception as e:
            self.logger.error(f"Falha no treinamento: {str(e)}")
            raise

# =============================================
# FUNÇÕES DE BANCO DE DADOS
# =============================================
def criar_banco():
    conn = sqlite3.connect('fraudes.db')
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_hora DATETIME NOT NULL,
        valor REAL NOT NULL,
        hora TEXT NOT NULL,
        tipo TEXT NOT NULL,
        resultado TEXT NOT NULL,
        detalhes TEXT,
        ip_origem TEXT,
        dispositivo TEXT
    )
    """)
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_resultado ON transacoes (resultado)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_data ON transacoes (data_hora)")
    
    conn.commit()
    conn.close()

def conectar_banco():
    conn = sqlite3.connect('fraudes.db')
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def verificar_banco():
    db_path = 'fraudes.db'
    tabela_existe = False
    
    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transacoes'")
            tabela_existe = cursor.fetchone() is not None
            conn.close()
        except Exception as e:
            st.error(f"Erro ao verificar banco: {e}")
    
    if not tabela_existe:
        criar_banco()
        st.success("✅ Banco de dados criado com sucesso!")

def carregar_historico():
    try:
        with conectar_banco() as conexao:
            df = pd.read_sql("""
                SELECT 
                    datetime(data_hora) as data_hora, 
                    valor, 
                    hora, 
                    tipo, 
                    resultado, 
                    detalhes 
                FROM transacoes
                ORDER BY data_hora DESC
                LIMIT 1000
            """, conexao)
            
            if 'data_hora' in df.columns:
                df['data_hora'] = pd.to_datetime(df['data_hora'])
            return df
            
    except Exception as e:
        st.error(f"Erro ao carregar histórico: {str(e)}")
        return pd.DataFrame(columns=['data_hora', 'valor', 'hora', 'tipo', 'resultado', 'detalhes'])

def salvar_transacao(transacao):
    try:
        with conectar_banco() as conexao:
            cursor = conexao.cursor()
            cursor.execute("""
                INSERT INTO transacoes 
                (data_hora, valor, hora, tipo, resultado, detalhes)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                transacao['DataHora'],
                transacao['Valor'],
                transacao['Hora'],
                transacao['Tipo'],
                transacao['Resultado'],
                transacao['Detalhes']
            ))
            conexao.commit()
    except Exception as e:
        st.error(f"Erro ao salvar transação: {str(e)}")

# =============================================
# CONFIGURAÇÃO DE AUTENTICAÇÃO
# =============================================
def criar_hashes():
    try:
        hasher = stauth.Hasher(['senha123', 'analista456'])
        return hasher.generate()
    except (TypeError, AttributeError):
        import hashlib
        def hash_password(password):
            salt = "streamlit"
            return hashlib.sha256((password + salt).encode()).hexdigest()
        return [hash_password("senha123"), hash_password("analista456")]

hashed_passwords = criar_hashes()

usuarios = {
    "admin": {
        "nome": "Administrador",
        "senha": hashed_passwords[0]
    },
    "analista": {
        "nome": "Analista",
        "senha": hashed_passwords[1]
    }
}

credenciais = {
    "usernames": {
        username: {
            "name": info["nome"],
            "password": info["senha"]
        } for username, info in usuarios.items()
    }
}

authenticator = stauth.Authenticate(
    credenciais,
    "cookie_fraudes",
    "chave_secreta_aleatoria",
    30
)

# =============================================
# CONFIGURAÇÃO DE E-MAIL
# =============================================
EMAIL_CONFIG = {
    "FROM": "sistema@banco.com",
    "SMTP_SERVER": "smtp.banco.com",
    "SMTP_PORT": 587,
    "USER": "usuario",
    "PASSWORD": "senha"
}

def enviar_email(destinatario, assunto, corpo):
    try:
        msg = MIMEText(corpo)
        msg['Subject'] = assunto
        msg['From'] = EMAIL_CONFIG["FROM"]
        msg['To'] = destinatario

        with smtplib.SMTP(EMAIL_CONFIG["SMTP_SERVER"], EMAIL_CONFIG["SMTP_PORT"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["USER"], EMAIL_CONFIG["PASSWORD"])
            server.send_message(msg)
    except Exception as e:
        st.error(f"Erro ao enviar e-mail: {str(e)}")

# =============================================
# FUNÇÃO PRINCIPAL
# =============================================
def main():
    verificar_banco()
    
    name, authentication_status, username = authenticator.login('Login', 'main')
    
    if authentication_status is False:
        st.error("Credenciais inválidas")
        return
    elif authentication_status is None:
        return
    
    sistema = SistemaFraudeAvancado()
    
    if 'historico' not in st.session_state:
        st.session_state.historico = carregar_historico()
        if st.session_state.historico.empty:
            st.session_state.historico = pd.DataFrame(columns=[
                'data_hora', 'valor', 'hora', 'tipo', 'resultado', 'detalhes'
            ])
    
    authenticator.logout('Logout', 'sidebar')
    
    with st.sidebar:
        st.title(f"Bem-vindo, {name}!")
        st.divider()
        
        limite_suspeito = st.slider("Limite para alertas (R$)", 1000, 100000, 15000)
        alerta_email = st.text_input("E-mail para alertas", "seguranca@banco.com")
        
        st.divider()
        st.metric("Transações Hoje", len(st.session_state.historico))
        st.metric("Última Atualização", datetime.now().strftime("%H:%M:%S"))
    
    st.title("🕵️ Sistema de Detecção de Fraudes")
    
    with st.form("analise_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            valor = st.number_input("Valor (R$)", min_value=0.0, step=0.01, format="%.2f")
        
        with col2:
            hora = st.time_input("Horário", value=datetime.now().time())
        
        tipo = st.selectbox("Tipo de Transação", ["PIX", "TED", "DOC", "Cartão"])
        
        if st.form_submit_button("Analisar Transação"):
            with st.spinner("Processando..."):
                resultado = sistema.processar({
                    'valor': valor,
                    'hora': hora,
                    'tipo': tipo
                })
                
                if "ALERTA" in resultado:
                    status = "Fraude"
                elif "suspeita" in resultado:
                    status = "Suspeita"
                else:
                    status = "Normal"
                
                transacao = {
                    'DataHora': datetime.now(),
                    'Valor': valor,
                    'Hora': hora.strftime("%H:%M"),
                    'Tipo': tipo,
                    'Resultado': status,
                    'Detalhes': resultado
                }
                
                salvar_transacao(transacao)
                st.session_state.historico = carregar_historico()
                
                if "ALERTA" in resultado:
                    st.error(resultado)
                    enviar_email(
                        alerta_email,
                        "ALERTA DE FRAUDE DETECTADA",
                        f"""Valor: R$ {valor:,.2f}
Tipo: {tipo}
Hora: {hora.strftime("%H:%M")}
Detalhes: {resultado}"""
                    )
                elif "suspeita" in resultado:
                    st.warning(resultado)
                else:
                    st.success(resultado)
    
    st.divider()
    st.header("📊 Análises e Estatísticas")
    
    if not st.session_state.historico.empty:
        tab1, tab2, tab3 = st.tabs(["Distribuição", "Temporal", "Valores"])
        
        with tab1:
            fig = px.pie(
                st.session_state.historico,
                names='resultado',
                title='Distribuição de Transações',
                color='resultado',
                color_discrete_map={
                    'Normal': '#2ecc71', 
                    'Suspeita': '#f39c12', 
                    'Fraude': '#e74c3c'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            historico = st.session_state.historico.copy()
            historico['hora_num'] = pd.to_datetime(historico['hora'], format='%H:%M').dt.hour
            fig = px.histogram(
                historico,
                x='hora_num',
                color='resultado',
                nbins=24,
                title='Transações por Hora do Dia',
                color_discrete_map={
                    'Normal': '#2ecc71', 
                    'Suspeita': '#f39c12', 
                    'Fraude': '#e74c3c'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with tab3:
            st.dataframe(
                st.session_state.historico.sort_values('data_hora', ascending=False),
                column_config={
                    "data_hora": "Data/Hora",
                    "valor": st.column_config.NumberColumn("Valor", format="R$ %.2f"),
                },
                hide_index=True,
                use_container_width=True
            )
        
        col1, col2, col3 = st.columns(3)
        total = len(st.session_state.historico)
        
        with col1:
            st.metric("Total Transações", total)
        
        with col2:
            fraudes = len(st.session_state.historico[st.session_state.historico['resultado'] == 'Fraude'])
            st.metric("Taxa de Fraude", f"{fraudes/total:.2%}" if total > 0 else "0%")
        
        with col3:
            valor_risco = st.session_state.historico[st.session_state.historico['resultado'] == 'Fraude']['valor'].sum()
            st.metric("Valor em Risco", f"R$ {valor_risco:,.2f}")
    else:
        st.info("Nenhuma transação registrada ainda. Analise uma transação para começar.")
    
    time.sleep(30)
    st.rerun()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        st.error(f"Erro crítico: {str(e)}")
        time.sleep(5)
        st.rerun() 
