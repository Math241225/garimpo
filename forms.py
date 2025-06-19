from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange

# --- Formulários de Autenticação ---

class AdminLoginForm(FlaskForm):
    """Formulário de login para Administradores."""
    username = StringField('Nome de Usuário', validators=[DataRequired(message="O nome de usuário é obrigatório.")])
    password = PasswordField('Senha', validators=[DataRequired(message="A senha é obrigatória.")])
    submit = SubmitField('Entrar')

class ClienteCadastroForm(FlaskForm):
    """Formulário de cadastro para novos Clientes."""
    nome = StringField('Nome Completo', validators=[
        DataRequired(message="O nome é obrigatório."),
        Length(min=3, max=100)
    ])
    email = StringField('Email', validators=[
        DataRequired(message="O email é obrigatório."),
        Email(message="Email inválido.")
    ])
    telefone = StringField('Telefone (Opcional)')
    password = PasswordField('Senha', validators=[
        DataRequired(message="A senha é obrigatória."),
        Length(min=6, message="A senha deve ter pelo menos 6 caracteres.")
    ])
    confirm_password = PasswordField('Confirme a Senha', validators=[
        DataRequired(message="A confirmação de senha é obrigatória."),
        EqualTo('password', message="As senhas devem coincidir.")
    ])
    submit = SubmitField('Cadastrar')

class ClienteLoginForm(FlaskForm):
    """Formulário de login para Clientes."""
    email = StringField('Email', validators=[
        DataRequired(message="O email é obrigatório."),
        Email(message="Email inválido.")
    ])
    password = PasswordField('Senha', validators=[DataRequired(message="A senha é obrigatória.")])
    submit = SubmitField('Entrar')

# --- Formulário de Transação ---

class TransacaoForm(FlaskForm):
    """Formulário para adicionar uma nova transação."""
    # CORREÇÃO APLICADA AQUI: Adicionado NumberRange para validar que o ID do cliente não é 0
    cliente_id = SelectField('Cliente', coerce=int, validators=[
        NumberRange(min=1, message="Selecione um cliente válido.")
    ])
    valor = FloatField('Valor da Transação (R$)', validators=[
        DataRequired(message="O valor é obrigatório."),
        NumberRange(min=0.01, message="O valor deve ser positivo.")
    ])
    descricao = TextAreaField('Descrição (Opcional)')
    submit = SubmitField('Registar Transação')
