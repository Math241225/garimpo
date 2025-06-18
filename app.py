import math
from datetime import datetime
from functools import wraps
import click
from flask import Flask, render_template, request, redirect, url_for, flash, session, Blueprint
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
# --- 1. CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma-chave-padrao-mas-ainda-segura-se-a-outra-falhar')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- 2. INICIALIZAÇÃO DAS EXTENSÕES ---
db = SQLAlchemy(app)
admin_login_manager = LoginManager(app)
admin_login_manager.login_view = 'auth.login_admin'
admin_login_manager.login_message = 'Por favor, faça login como administrador para aceder a esta página.'
admin_login_manager.login_message_category = 'info'

# --- 3. MODELOS DO BANCO DE DADOS ---
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

    def __repr__(self):
        return f'<Cliente {self.id} - {self.nome}>'

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Admin {self.username}>'

class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('cliente.id'), nullable=False)
    data_transacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    valor = db.Column(db.Float, nullable=False)
    descricao = db.Column(db.String(200), nullable=True)
    pontos_ganhos = db.Column(db.Integer, default=0, nullable=False)

    def __repr__(self):
        return f'<Transacao {self.id} - Cliente {self.cliente_id} - R$ {self.valor}>'

# --- 4. CONFIGURAÇÃO DO LOGIN MANAGER E PROCESSADORES DE CONTEXTO ---
@admin_login_manager.user_loader
def load_admin(admin_id):
    return db.session.get(Admin, int(admin_id))

@app.context_processor
def inject_global_vars():
    return dict(datetime=datetime)

# --- 5. FUNÇÕES AUXILIARES E DECORADORES ---
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

# --- 6. DEFINIÇÃO DOS BLUEPRINTS ---
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
cliente_bp = Blueprint('cliente', __name__, url_prefix='/cliente')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# --- 7. ROTAS ---

# Rotas Principais (sem blueprint)
@app.route('/')
def home():
    if 'cliente_id' in session:
        return redirect(url_for('cliente.perfil_cliente'))
    return render_template('home.html')

# Rotas de Autenticação (auth_bp)
@auth_bp.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if current_user.is_authenticated:
        return redirect(url_for('admin.admin_dashboard'))
    
    try:
        from forms import AdminLoginForm
    except ImportError:
        flash('Ficheiro de formulários não encontrado. Contacte o suporte.', 'danger')
        return "Erro de configuração do servidor.", 500

    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            flash('Login de administrador realizado com sucesso!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin.admin_dashboard'))
        else:
            flash('Login de administrador falhou. Verifique as credenciais.', 'danger')
    return render_template('auth/login_admin.html', form=form)

@auth_bp.route('/logout_admin')
@login_required
def logout_admin():
    logout_user()
    flash('Você foi desconectado da área administrativa.', 'info')
    return redirect(url_for('auth.login_admin'))

@auth_bp.route('/login_cliente', methods=['GET', 'POST'])
def login_cliente():
    if 'cliente_id' in session:
        return redirect(url_for('cliente.perfil_cliente'))
    
    try:
        from forms import ClienteLoginForm
    except ImportError:
        flash('Ficheiro de formulários não encontrado. Contacte o suporte.', 'danger')
        return "Erro de configuração do servidor.", 500

    form = ClienteLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        cliente = Cliente.query.filter_by(email=email).first()
        if cliente and cliente.check_password(password):
            session['cliente_id'] = cliente.id
            session['cliente_nome'] = cliente.nome
            flash(f'Bem-vindo de volta, {cliente.nome}!', 'success')
            return redirect(url_for('cliente.perfil_cliente'))
        else:
            flash('Login falhou. Verifique seu email e senha.', 'danger')
    return render_template('auth/login_cliente.html', form=form)

@auth_bp.route('/cadastro_cliente', methods=['GET', 'POST'])
def cadastro_cliente():
    if 'cliente_id' in session:
        return redirect(url_for('cliente.perfil_cliente'))
    
    try:
        from forms import ClienteCadastroForm
    except ImportError:
        flash('Ficheiro de formulários não encontrado. Contacte o suporte.', 'danger')
        return "Erro de configuração do servidor.", 500

    form = ClienteCadastroForm()
    if form.validate_on_submit():
        existing_user = Cliente.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Este email já está registado. Por favor, tente fazer login ou use outro email.', 'warning')
        else:
            try:
                novo_cliente = Cliente(nome=form.nome.data, email=form.email.data, telefone=form.telefone.data)
                novo_cliente.set_password(form.password.data)
                db.session.add(novo_cliente)
                db.session.commit()
                flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
                return redirect(url_for('auth.login_cliente'))
            except Exception as e:
                db.session.rollback()
                flash(f'Ocorreu um erro ao criar a sua conta: {e}', 'danger')
    return render_template('auth/cadastro_cliente.html', form=form)

@auth_bp.route('/logout_cliente')
def logout_cliente():
    session.pop('cliente_id', None)
    session.pop('cliente_nome', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('home'))

# Rotas do Portal do Cliente (cliente_bp)
@cliente_bp.route('/perfil')
@cliente_login_required
def perfil_cliente():
    cliente = db.session.get(Cliente, session.get('cliente_id'))
    if not cliente:
        session.clear()
        flash('Sessão inválida. Por favor, faça login novamente.', 'warning')
        return redirect(url_for('auth.login_cliente'))
    
    page = request.args.get('page', 1, type=int)
    transacoes_paginadas = cliente.transacoes.paginate(page=page, per_page=5)
    return render_template('cliente/perfil_cliente.html', cliente=cliente, transacoes_paginadas=transacoes_paginadas)

# Rotas do Painel Administrativo (admin_bp)
@admin_bp.route('/')
@login_required
def admin_dashboard():
    total_clientes = db.session.query(Cliente).count()
    total_transacoes = db.session.query(Transacao).count()
    soma_valores_transacoes = db.session.query(db.func.sum(Transacao.valor)).scalar() or 0.0
    return render_template('admin/dashboard.html', total_clientes=total_clientes, total_transacoes=total_transacoes, soma_valores_transacoes=soma_valores_transacoes)

@admin_bp.route('/clientes/')
@login_required
def admin_listar_clientes():
    page = request.args.get('page', 1, type=int)
    clientes_paginados = Cliente.query.order_by(Cliente.nome).paginate(page=page, per_page=10)
    return render_template('admin/listar_clientes.html', clientes_paginados=clientes_paginados)

@admin_bp.route('/cliente/<int:cliente_id>/editar_coins', methods=['GET', 'POST'])
@login_required
def admin_editar_coins(cliente_id):
    cliente = db.session.get(Cliente, cliente_id)
    if not cliente:
        flash('Cliente não encontrado.', 'danger')
        return redirect(url_for('admin.admin_listar_clientes'))
    
    # Este formulário ainda pode ser refatorado para Flask-WTF
    if request.method == 'POST':
        novos_coins_str = request.form.get('garimpo_coins')
        if novos_coins_str is None or not novos_coins_str.strip().isdigit():
            flash('Valor de Garimpo Coins inválido.', 'danger')
        else:
            novos_coins = int(novos_coins_str)
            if novos_coins < 0:
                flash('Garimpo Coins não podem ser negativos.', 'danger')
            else:
                cliente.garimpo_coins = novos_coins
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
    try:
        # A opção cascade="all, delete-orphan" no modelo já deve tratar isso, mas por segurança:
        # Transacao.query.filter_by(cliente_id=cliente.id).delete()
        db.session.delete(cliente)
        db.session.commit()
        flash(f'Cliente "{cliente.nome}" e suas transações foram excluídos.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir cliente: {str(e)}', 'danger')
    return redirect(url_for('admin.admin_listar_clientes'))

@admin_bp.route('/adicionar_transacao', methods=['GET', 'POST'])
@login_required
def admin_adicionar_transacao():
    try:
        from forms import TransacaoForm
    except ImportError:
        flash('Ficheiro de formulários não encontrado. Contacte o suporte.', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

    form = TransacaoForm()
    # CORREÇÃO APLICADA AQUI: O valor do placeholder agora é 0
    form.cliente_id.choices = [(c.id, c.nome) for c in Cliente.query.order_by('nome').all()]
    form.cliente_id.choices.insert(0, (0, '-- Selecione um Cliente --'))

    if form.validate_on_submit():
        try:
            cliente = db.session.get(Cliente, form.cliente_id.data)
            valor = form.valor.data
            descricao = form.descricao.data
            
            if not cliente:
                flash('Cliente inválido selecionado.', 'danger')
            else:
                pontos_desta_transacao = calcular_pontos(valor)
                nova_transacao = Transacao(cliente_id=cliente.id, valor=valor, descricao=descricao, pontos_ganhos=pontos_desta_transacao)
                db.session.add(nova_transacao)
                cliente.garimpo_coins += pontos_desta_transacao
                db.session.commit()
                flash(f'Transação de R$ {valor:.2f} para {cliente.nome} registada! {pontos_desta_transacao} Garimpo Coins adicionados.', 'success')
                return redirect(url_for('admin.admin_listar_clientes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao registar transação: {str(e)}', 'danger')
    return render_template('admin/adicionar_transacao.html', form=form)

@admin_bp.route('/cadastrar_cliente_admin', methods=['GET', 'POST'])
@login_required
def admin_cadastrar_cliente():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        telefone = request.form.get('telefone')
        garimpo_coins_str = request.form.get('garimpo_coins', '0')
        erros = []
        if not nome or not email: erros.append('Nome e Email são obrigatórios.')
        if Cliente.query.filter_by(email=email).first(): erros.append('Este email já está registado.')
        try:
            garimpo_coins = int(garimpo_coins_str)
            if garimpo_coins < 0: erros.append('Garimpo Coins não podem ser negativos.')
        except ValueError:
            erros.append('Valor de Garimpo Coins inválido.'); garimpo_coins = 0
        if erros:
            for erro in erros: flash(erro, 'danger')
        else:
            novo_cliente = Cliente(nome=nome, email=email, telefone=telefone, garimpo_coins=garimpo_coins)
            db.session.add(novo_cliente)
            db.session.commit()
            flash(f'Cliente {nome} cadastrado pelo admin com sucesso!', 'success')
            return redirect(url_for('admin.admin_listar_clientes'))
    return render_template('admin/cadastrar_cliente_admin.html')

# --- 8. REGISTO DOS BLUEPRINTS ---
app.register_blueprint(auth_bp)
app.register_blueprint(cliente_bp)
app.register_blueprint(admin_bp)

# --- 9. COMANDOS CLI (continuação) E EXECUÇÃO ---
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Cliente': Cliente, 'Admin': Admin, 'Transacao': Transacao}

@app.cli.command('create-dummy-data')
def create_dummy_data_command():
    with app.app_context():
        if Cliente.query.count() == 0:
            cliente1 = Cliente(nome="João Exemplo da Silva", email="joao.exemplo@example.com", telefone="11912345678", garimpo_coins=5)
            cliente2 = Cliente(nome="Maria Exemplo Oliveira", email="maria.exemplo@example.com", garimpo_coins=10)
            db.session.add_all([cliente1, cliente2])
            db.session.commit()
            print('Dados de exemplo para Clientes criados!')
        else:
            print('O banco de dados já contém clientes.')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
   app.run(debug=False)
