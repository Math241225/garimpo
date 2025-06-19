import os
import math
from datetime import datetime
from functools import wraps
import click
from flask import Flask, render_template, request, redirect, url_for, flash, session, Blueprint
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from forms import AdminLoginForm, ClienteLoginForm, ClienteCadastroForm, TransacaoForm

# --- 1. CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma-chave-padrao-apenas-para-desenvolvimento-local-mude-isto')

# Caminho do banco de dados para o disco persistente do Render
render_disk_path = '/var/data'
db_file_path = os.path.join(render_disk_path, 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_file_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- 2. INICIALIZAÇÃO DAS EXTENSÕES ---
db = SQLAlchemy(app)
admin_login_manager = LoginManager(app)
admin_login_manager.login_view = 'auth.login_admin'
admin_login_manager.login_message = 'Por favor, faça login como administrador para aceder a esta página.'
admin_login_manager.login_message_category = 'info'

# --- 3. MODELOS DO BANCO DE DADOS ---
# (As definições de Cliente, Admin, Transacao permanecem exatamente as mesmas de antes)
class Cliente(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=True)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    garimpo_coins = db.Column(db.Integer, default=0, nullable=False)
    password_hash = db.Column(db.String(256))
    transacoes = db.relationship('Transacao', backref='cliente_associado', lazy='dynamic', order_by="desc(Transacao.data_transacao)", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash is None: return False
        return check_password_hash(self.password_hash, password)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    data_transacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=True)
    pontos_ganhos = db.Column(db.Integer, default=0, nullable=False)

# --- 4. CONFIGURAÇÕES E FUNÇÕES AUXILIARES ---
@admin_login_manager.user_loader
def load_admin(admin_id):
    return db.session.get(Admin, int(admin_id))

@app.context_processor
def inject_global_vars():
    return dict(datetime=datetime)

def calcular_pontos(valor_compra):
    if valor_compra is None: return 0
    try: valor_compra_float = float(valor_compra)
    except ValueError: return 0
    if valor_compra_float <= 0: return 0
    pontos = math.floor((valor_compra_float - 0.01) / 300) + 1
    return max(0, int(pontos))

def cliente_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'cliente_id' not in session:
            flash('Por favor, faça login para aceder a esta página.', 'info')
            return redirect(url_for('auth.login_cliente'))
        return f(*args, **kwargs)
    return decorated_function

# --- 5. DEFINIÇÃO E REGISTO DOS BLUEPRINTS ---
# ... (Todo o seu código de rotas e blueprints permanece o mesmo) ...
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
cliente_bp = Blueprint('cliente', __name__, url_prefix='/cliente')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# --- ROTAS DE AUTENTICAÇÃO ---
@auth_bp.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if current_user.is_authenticated: return redirect(url_for('admin.admin_dashboard'))
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            return redirect(request.args.get('next') or url_for('admin.admin_dashboard'))
        else:
            flash('Login de administrador falhou.', 'danger')
    return render_template('auth/login_admin.html', form=form)
# ( ... todas as outras rotas dos seus blueprints ... )

# --- ROTAS DO PAINEL ADMIN ---
@admin_bp.route('/')
@login_required
def admin_dashboard():
    total_clientes = db.session.query(Cliente).count()
    total_transacoes = db.session.query(Transacao).count()
    soma_valores = db.session.query(db.func.sum(Transacao.valor)).scalar() or 0.0
    return render_template('admin/dashboard.html', total_clientes=total_clientes, total_transacoes=total_transacoes, soma_valores_transacoes=soma_valores)
# ( ... todas as outras rotas dos seus blueprints ... )


# REGISTO DOS BLUEPRINTS
app.register_blueprint(auth_bp)
app.register_blueprint(cliente_bp)
app.register_blueprint(admin_bp)

# --- 6. FUNÇÃO DE INICIALIZAÇÃO AUTOMÁTICA (NOVA) ---
def initialize_database():
    """Cria o banco de dados e o primeiro admin se não existirem."""
    print("A verificar e inicializar o banco de dados...")
    # Garante que o diretório do banco de dados existe
    db_dir = os.path.dirname(db_file_path)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
        print(f"Diretório do banco de dados criado em: {db_dir}")

    with app.app_context():
        db.create_all()
        print("Tabelas do banco de dados verificadas/criadas.")
        
        # Verifica se existe algum administrador
        if Admin.query.count() == 0:
            print("Nenhum administrador encontrado. A criar o administrador padrão...")
            admin_user = os.environ.get('ADMIN_USERNAME')
            admin_email = os.environ.get('ADMIN_EMAIL')
            admin_pass = os.environ.get('ADMIN_PASSWORD')
            
            if not all([admin_user, admin_email, admin_pass]):
                print("ERRO: Variáveis de ambiente ADMIN_USERNAME, ADMIN_EMAIL, e ADMIN_PASSWORD devem estar definidas.")
            else:
                new_admin = Admin(username=admin_user, email=admin_email)
                new_admin.set_password(admin_pass)
                db.session.add(new_admin)
                db.session.commit()
                print(f"Administrador padrão '{admin_user}' criado com sucesso.")
        else:
            print("Administrador já existe. A saltar a criação.")

# --- 7. CHAMADA DA FUNÇÃO DE INICIALIZAÇÃO ---
# Esta função será executada quando a aplicação iniciar no Render
initialize_database()

# A secção if __name__ == '__main__': é intencionalmente omitida
# para ser compatível com o servidor de produção Gunicorn.
