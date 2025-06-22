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

# --- 1. CONFIGURAÇÃO E CRIAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)
# A SECRET_KEY é lida a partir das variáveis de ambiente do Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# LIGAÇÃO AO BANCO DE DADOS EXTERNO (NEON)
db_uri = os.environ.get('DATABASE_URL')
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- 2. INICIALIZAÇÃO DAS EXTENSÕES ---
db = SQLAlchemy(app)
admin_login_manager = LoginManager(app)
admin_login_manager.login_view = 'auth.login_admin'
admin_login_manager.login_message = 'Por favor, faça login como administrador.'
admin_login_manager.login_message_category = 'info'

# --- 3. MODELOS DO BANCO DE DADOS ---
# (As definições de Cliente, Admin, Transacao permanecem exatamente as mesmas)
class Cliente(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefone = db.Column(db.String(20), nullable=True)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    garimpo_coins = db.Column(db.Integer, default=0, nullable=False)
    password_hash = db.Column(db.String(256))
    transacoes = db.relationship('Transacao', backref='cliente_associado', lazy='dynamic', order_by="desc(Transacao.data_transacao)", cascade="all, delete-orphan")

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        if self.password_hash is None: return False
        return check_password_hash(self.password_hash, password)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    data_transacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=True)
    pontos_ganhos = db.Column(db.Integer, default=0, nullable=False)

# --- 4. FUNÇÕES AUXILIARES E CONFIGURAÇÕES ---
@admin_login_manager.user_loader
def load_admin(admin_id):
    return db.session.get(Admin, int(admin_id))

@app.context_processor
def inject_global_vars():
    return dict(datetime=datetime)

def calcular_pontos(valor_compra):
    if valor_compra is None or valor_compra <= 0: return 0
    try: valor_compra_float = float(valor_compra)
    except ValueError: return 0
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

# --- 5. DEFINIÇÃO E REGISTO DOS BLUEPRINTS E ROTAS ---
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
cliente_bp = Blueprint('cliente', __name__, url_prefix='/cliente')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@main_bp.route('/')
def home():
    if 'cliente_id' in session: return redirect(url_for('cliente.perfil_cliente'))
    return render_template('home.html')

# (Todas as suas outras rotas de auth, cliente e admin aqui)
@auth_bp.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if current_user.is_authenticated: return redirect(url_for('admin.admin_dashboard'))
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and admin.check_password(form.password.data):
            login_user(admin)
            return redirect(request.args.get('next') or url_for('admin.admin_dashboard'))
        else: flash('Login de administrador falhou.', 'danger')
    return render_template('auth/login_admin.html', form=form)

@auth_bp.route('/logout_admin')
@login_required
def logout_admin():
    logout_user()
    return redirect(url_for('auth.login_admin'))
# ... (outras rotas)

app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(cliente_bp)
app.register_blueprint(admin_bp)

# --- 6. COMANDO PARA INICIALIZAR O BANCO DE DADOS ---
@app.cli.command('init-db')
def init_db_command():
    with app.app_context():
        db.create_all()
        print("Tabelas do banco de dados criadas.")
        if Admin.query.count() == 0:
            username = os.environ.get('ADMIN_USERNAME')
            email = os.environ.get('ADMIN_EMAIL')
            password = os.environ.get('ADMIN_PASSWORD')
            if all([username, email, password]):
                admin = Admin(username=username, email=email)
                admin.set_password(password)
                db.session.add(admin)
                db.session.commit()
                print(f"Administrador padrão '{username}' criado.")
            else:
                print("AVISO: Variáveis de ambiente do admin não definidas.")
