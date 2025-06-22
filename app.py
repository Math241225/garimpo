import os
import math
from datetime import datetime
from functools import wraps
import click
from flask import Flask, render_template, request, redirect, url_for, flash, session, Blueprint
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- 1. CONFIGURAÇÃO INICIAL E EXTENSÕES ---
# Inicializamos as extensões aqui, mas configuramo-las dentro da função create_app
db = SQLAlchemy()
admin_login_manager = LoginManager()
admin_login_manager.login_view = 'auth.login_admin'
admin_login_manager.login_message = 'Por favor, faça login como administrador para aceder a esta página.'
admin_login_manager.login_message_category = 'info'

# --- 2. MODELOS DO BANCO DE DADOS ---
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

# --- 3. FUNÇÕES AUXILIARES E DECORADORES ---
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

# --- 4. DEFINIÇÃO DOS BLUEPRINTS E ROTAS ---
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
cliente_bp = Blueprint('cliente', __name__, url_prefix='/cliente')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@main_bp.route('/')
def home():
    if 'cliente_id' in session: return redirect(url_for('cliente.perfil_cliente'))
    return render_template('home.html')

@auth_bp.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    from forms import AdminLoginForm
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

@auth_bp.route('/login_cliente', methods=['GET', 'POST'])
def login_cliente():
    from forms import ClienteLoginForm
    if 'cliente_id' in session: return redirect(url_for('cliente.perfil_cliente'))
    form = ClienteLoginForm()
    if form.validate_on_submit():
        cliente = Cliente.query.filter_by(email=form.email.data).first()
        if cliente and cliente.check_password(form.password.data):
            session['cliente_id'] = cliente.id
            session['cliente_nome'] = cliente.nome
            return redirect(url_for('cliente.perfil_cliente'))
        else: flash('Login falhou. Verifique seu email e senha.', 'danger')
    return render_template('auth/login_cliente.html', form=form)

@auth_bp.route('/cadastro_cliente', methods=['GET', 'POST'])
def cadastro_cliente():
    from forms import ClienteCadastroForm
    if 'cliente_id' in session: return redirect(url_for('cliente.perfil_cliente'))
    form = ClienteCadastroForm()
    if form.validate_on_submit():
        if Cliente.query.filter_by(email=form.email.data).first():
            flash('Este email já está registado.', 'warning')
        else:
            novo_cliente = Cliente(nome=form.nome.data, email=form.email.data, telefone=form.telefone.data)
            novo_cliente.set_password(form.password.data)
            db.session.add(novo_cliente)
            db.session.commit()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('auth.login_cliente'))
    return render_template('auth/cadastro_cliente.html', form=form)

@auth_bp.route('/logout_cliente')
def logout_cliente():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('main.home'))

@cliente_bp.route('/perfil')
@cliente_login_required
def perfil_cliente():
    cliente = db.session.get(Cliente, session.get('cliente_id'))
    if not cliente:
        session.clear()
        return redirect(url_for('auth.login_cliente'))
    page = request.args.get('page', 1, type=int)
    transacoes_paginadas = cliente.transacoes.paginate(page=page, per_page=5)
    return render_template('cliente/perfil_cliente.html', cliente=cliente, transacoes_paginadas=transacoes_paginadas)

@admin_bp.route('/')
@login_required
def admin_dashboard():
    total_clientes = db.session.query(Cliente).count()
    total_transacoes = db.session.query(Transacao).count()
    soma_valores = db.session.query(db.func.sum(Transacao.valor)).scalar() or 0.0
    return render_template('admin/dashboard.html', total_clientes=total_clientes, total_transacoes=total_transacoes, soma_valores_transacoes=soma_valores)

@admin_bp.route('/clientes/')
@login_required
def admin_listar_clientes():
    page = request.args.get('page', 1, type=int)
    clientes_paginados = Cliente.query.order_by(Cliente.nome).paginate(page=page, per_page=10)
    return render_template('admin/listar_clientes.html', clientes_paginados=clientes_paginados)

@admin_bp.route('/adicionar_transacao', methods=['GET', 'POST'])
@login_required
def admin_adicionar_transacao():
    from forms import TransacaoForm
    form = TransacaoForm()
    form.cliente_id.choices = [(c.id, c.nome) for c in Cliente.query.order_by('nome').all()]
    form.cliente_id.choices.insert(0, (0, '-- Selecione um Cliente --'))
    if form.validate_on_submit():
        cliente = db.session.get(Cliente, form.cliente_id.data)
        if not cliente: flash('Cliente inválido selecionado.', 'danger')
        else:
            valor = form.valor.data
            descricao = form.descricao.data
            pontos = calcular_pontos(valor)
            nova_transacao = Transacao(cliente_id=cliente.id, valor=valor, descricao=descricao, pontos_ganhos=pontos)
            db.session.add(nova_transacao)
            cliente.garimpo_coins += pontos
            db.session.commit()
            flash(f'Transação de R$ {valor:.2f} para {cliente.nome} registada! {pontos} Garimpo Coins adicionados.', 'success')
            return redirect(url_for('admin.admin_listar_clientes'))
    return render_template('admin/adicionar_transacao.html', form=form)

@admin_bp.route('/cadastrar_cliente_admin', methods=['GET', 'POST'])
@login_required
def admin_cadastrar_cliente():
    from forms import ClienteCadastroForm
    form = ClienteCadastroForm() # Pode reutilizar o formulário
    if form.validate_on_submit():
        if Cliente.query.filter_by(email=form.email.data).first():
            flash('Este email já está registado.', 'warning')
        else:
            novo_cliente = Cliente(nome=form.nome.data, email=form.email.data, telefone=form.telefone.data)
            novo_cliente.set_password(form.password.data)
            db.session.add(novo_cliente)
            db.session.commit()
            flash(f'Cliente {form.nome.data} cadastrado com sucesso!', 'success')
            return redirect(url_for('admin.admin_listar_clientes'))
    return render_template('admin/cadastrar_cliente_admin.html', form=form)
    
@admin_bp.route('/cliente/<int:cliente_id>/editar_coins', methods=['GET', 'POST'])
@login_required
def admin_editar_coins(cliente_id):
    # Esta rota pode ser refatorada com Flask-WTF no futuro
    cliente = db.session.get(Cliente, cliente_id)
    if not cliente:
        flash('Cliente não encontrado.', 'danger')
        return redirect(url_for('admin.admin_listar_clientes'))
    if request.method == 'POST':
        novos_coins_str = request.form.get('garimpo_coins')
        if novos_coins_str is None or not novos_coins_str.strip().isdigit() or int(novos_coins_str) < 0:
            flash('Valor de Garimpo Coins inválido.', 'danger')
        else:
            cliente.garimpo_coins = int(novos_coins_str)
            db.session.commit()
            flash(f'Garimpo Coins de {cliente.nome} atualizados!', 'success')
            return redirect(url_for('admin.admin_listar_clientes'))
    return render_template('admin/editar_coins.html', cliente=cliente)

@admin_bp.route('/cliente/<int:cliente_id>/excluir', methods=['POST'])
@login_required
def admin_excluir_cliente(cliente_id):
    cliente = db.session.get(Cliente, cliente_id)
    if not cliente:
        flash('Cliente não encontrado.', 'danger')
        return redirect(url_for('admin.admin_listar_clientes'))
    db.session.delete(cliente)
    db.session.commit()
    flash(f'Cliente "{cliente.nome}" e suas transações foram excluídos.', 'success')
    return redirect(url_for('admin.admin_listar_clientes'))

# --- 5. FÁBRICA DE APLICAÇÃO E COMANDOS CLI ---
def create_app():
    app = Flask(__name__)
    
    # Configurações
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    db_uri = os.environ.get('DATABASE_URL')
    if db_uri and db_uri.startswith("postgres://"):
        db_uri = db_uri.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicializa extensões
    db.init_app(app)
    admin_login_manager.init_app(app)

    # Regista Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(cliente_bp)
    app.register_blueprint(admin_bp)

    # Processador de Contexto
    @app.context_processor
    def inject_global_vars():
        return dict(datetime=datetime)

    # Comando CLI
    @app.cli.command('init-db')
    def init_db():
        """Cria tabelas e admin inicial."""
        db.create_all()
        print("Tabelas do banco de dados criadas.")
        if Admin.query.count() == 0:
            print("A criar o administrador padrão...")
            username = os.environ.get('ADMIN_USERNAME')
            email = os.environ.get('ADMIN_EMAIL')
            password = os.environ.get('ADMIN_PASSWORD')
            if all([username, email, password]):
                admin = Admin(username=username, email=email)
                admin.set_password(password)
                db.session.add(admin)
                db.session.commit()
                print(f"Administrador '{username}' criado.")
            else:
                print("AVISO: Variáveis de ambiente do admin não definidas.")
    
    return app

# Cria a instância da aplicação para ser encontrada pelo Gunicorn
app = create_app()
