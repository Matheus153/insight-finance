from functools import wraps
from flask import Blueprint, abort, current_app, jsonify, render_template, request, redirect, url_for, flash
from app import db, login_manager, mail, API_KEY, create_app, cred, csrf
from app.models import Transacao, Categoria, User
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from firebase_admin import auth as firebase_auth
from firebase_admin import firestore, exceptions as firebase_exceptions
from itsdangerous import URLSafeTimedSerializer
from pytz import timezone
import firebase_admin
import plotly.express as px
import pandas as pd
import requests
import os
import re


main_routes = Blueprint('main', __name__)

# Configure LoginManager
login_manager.login_view = 'main.login'

# Sets the application's timezone
br_tz = timezone('America/New_York')

months = [
    (0, 'All months'),
    (1, 'January'),
    (2, 'February'),
    (3, 'March'),
    (4, 'April'),
    (5, 'May'),
    (6, 'June'),
    (7, 'July'),
    (8, 'August'),
    (9, 'September'),
    (10, 'October'),
    (11, 'November'),
    (12, 'December')
]

years = [(0, 'All years')] + [(year, year) for year in range(2020, datetime.now(br_tz).year + 2)]

# Reusable password validation function
def validar_senha(password):
    errors = []
    if len(password) < 6:
        errors.append("The password must be at least 6 characters long")
    if not re.search(r'[A-Z]', password):
        errors.append("The password must contain at least one capital letter")
    if not re.search(r'[^A-Za-z0-9]', password):
        errors.append("The password must contain at least one special character")
    if not re.search(r'[0-9]', password):
        errors.append("The password must contain at least one number")
    return errors

# Auxiliary function for obtaining date parameters
def get_filtro_data():
    selected_month = request.args.get('mes', datetime.now(br_tz).month, type=int)
    selected_year = request.args.get('ano', datetime.now(br_tz).year, type=int)
    return selected_month, selected_year

def verificar_saldos(app):
    with app.app_context():
        try:
            # Search all users
            users = firebase_auth.list_users().iterate_all()
            
            for user in users:
                uid = user.uid
                email = user.email
                db_firestore = firestore.client()
                user_doc = db_firestore.collection('usuarios').document(uid).get()
                
                # Calculate current month period
                hoje = datetime.now(br_tz)
                primeiro_dia_mes = hoje.replace(day=1, hour=0, minute=0, second=0)
                
                # Search transactions for the month
                transacoes = Transacao.query.filter(
                    Transacao.user_id == uid,
                    Transacao.data >= primeiro_dia_mes
                ).all()

                # Get custom meta or use default 10%
                user_data = user_doc.to_dict() if user_doc.exists else {}
                meta_alerta = user_data.get('meta_alerta', 10.0)
                
                # Calculate totals
                receitas = sum(t.valor for t in transacoes if t.tipo == 'receita')
                despesas = sum(t.valor for t in transacoes if t.tipo == 'despesa')
                saldo = receitas - despesas
                
                # Check alert condition
                if receitas > 0 and saldo < (receitas * (meta_alerta / 100)):
                    enviar_alerta(email, user.display_name, receitas, despesas, meta_alerta, saldo)
                    
        except Exception as e:
            print(f"Error when checking balances: {str(e)}")

def enviar_alerta(destinatario, nome, receitas, despesas, meta, saldo):
    # Create context manually
    with current_app.app_context():
        
        msg = Message(
            subject="Financial Alert - Insight Finance",
            sender=os.getenv('MAIL_USERNAME'),
            recipients=[destinatario]
        )
        
        msg.html = render_template(
            'email_alerta.html',
            nome=nome,
            receitas=receitas,
            despesas=despesas,
            saldo=saldo,
            meta=meta,
            data=datetime.now(br_tz).strftime('%d/%m/%Y')
        )
        
        try:
            mail.send(msg)
            print(f"Alert sent to {destinatario}")
        except Exception as e:
            print(f"Error sending alert: {str(e)}")

# Initialize scheduler
scheduler_alerta = BackgroundScheduler(daemon=True)
scheduler_alerta.add_job(
    func=lambda: verificar_saldos(create_app()),
    trigger='cron',
    # day='last', (in case you wanted to shoot on the last day of the month)
    hour=20,
    minute=0,
    timezone=br_tz
)
scheduler_alerta.start()

def criar_transacao_recorrente():
    app = create_app()

    # Checks if Firebase has already been initialized
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(cred)

    with app.app_context():
        agora = datetime.now(br_tz)
        
        # Search for recurring transactions that are not yet 12 months old
        transacoes = Transacao.query.filter(
            Transacao.recorrente == True,
            Transacao.meses_repeticao < 12
        ).all()

        for transacao in transacoes:
            # Calculates the next date (same day, next month)
            meses_a_adicionar = transacao.meses_repeticao + 1
            nova_data = transacao.data_original + relativedelta(months=meses_a_adicionar)

            # Check if it's past the due date
            if nova_data <= agora:
                nova_transacao = Transacao(
                    descricao=transacao.descricao,
                    valor=transacao.valor,
                    tipo=transacao.tipo,
                    categoria_id=transacao.categoria_id,
                    user_id=transacao.user_id,
                    data=nova_data,
                    recorrente=False, # Não permite recorrência em cascata
                    meses_repeticao=transacao.meses_repeticao + 1,
                    data_original=transacao.data_original
                )
            
                db.session.add(nova_transacao)
                transacao.meses_repeticao += 1
        
        db.session.commit()

# Scheduler that runs daily at 00:05
scheduler_recorrentes = BackgroundScheduler(daemon=True)
scheduler_recorrentes.add_job(
    func=criar_transacao_recorrente, 
    trigger='cron', 
    hour=0,
    minute=5, 
    timezone=br_tz)
scheduler_recorrentes.start()


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

def configurar_primeiro_admin(uid):
    db_firestore = firestore.client()
    config_ref = db_firestore.collection('config').document('admin')
    
    # Atomic transaction to avoid race conditions
    @firestore.transactional
    def atualizar_config(transaction):
        snapshot = config_ref.get(transaction=transaction)
        
        if not snapshot.exists:
            transaction.set(config_ref, {'primeiro_admin': uid})
            return True
        return False

    transaction = db_firestore.transaction()
    return atualizar_config(transaction)

def atualizar_firestore_admin(uid, is_admin):
    """Atualiza o status de admin no Firestore"""
    try:
        db_firestore = firestore.client()
        user_ref = db_firestore.collection('usuarios').document(uid)
        user_ref.update({
            'admin': is_admin,
            'ultima_atualizacao_admin': firestore.SERVER_TIMESTAMP
        })
    except Exception as e:
        current_app.logger.error(f"Erro ao atualizar Firestore: {str(e)}")

@main_routes.route('/admin')
@login_required
@admin_required
def admin_panel():

    # Exemplo: Listar todos usuários
    try:
        # List all Firebase users
        users = firebase_auth.list_users().iterate_all()
        return render_template('admin.html', users=users)
    except Exception as e:
        flash(f'Error loading users: {str(e)}', 'danger')
        return redirect(url_for('main.index'))


@main_routes.route('/promover-admin/<uid>')
@admin_required
def promover_admin(uid):
    try:

        # Update Firebase Auth
        firebase_auth.set_custom_user_claims(uid, {'admin': True})

        # Update Firestore
        atualizar_firestore_admin(uid, True)

        flash('User successfully promoted to admin!', 'success')
    except Exception as e:
        flash(f'Erro: {str(e)}', 'danger')
    return redirect(url_for('main.admin_panel'))

@main_routes.route('/remover-admin/<uid>')
@admin_required
def remover_admin(uid):
    try:
        firebase_auth.set_custom_user_claims(uid, {'admin': None})

        # Update Firestore
        atualizar_firestore_admin(uid, False)

        # Update the local user
        user = firebase_auth.get_user(uid)
        
        flash(f'{user.email} had admin privileges removed!', 'success')

        # logging.info(f"ADMIN ACTION: {current_user.email} removeu admin de {user.email}")

    except Exception as e:
        flash(f'Error removing privileges: {str(e)}', 'danger')

    return redirect(url_for('main.admin_panel'))

# Rotas
@main_routes.route('/')
@login_required
def index():
    user_id_filtro = request.args.get('user_id')
    selected_month, selected_year = get_filtro_data()
    
    # Construir query base
    if current_user.is_admin:
        usuarios = firebase_auth.list_users().iterate_all()
        base_query = Transacao.query
        
        if user_id_filtro:
            base_query = base_query.filter_by(user_id=user_id_filtro)
    else:
        base_query = Transacao.query.filter_by(user_id=current_user.id)
        usuarios = []

    # Apply date filters
    if selected_month != 0:
        base_query = base_query.filter(
            db.extract('month', Transacao.data) == selected_month
        )
    
    if selected_year != 0:
        base_query = base_query.filter(
            db.extract('year', Transacao.data) == selected_year
        )

    # Cálculos usando a query base
    #saldo = se eu quisesse a soma de todos os lançamentos base_query.with_entities(db.func.sum(Transacao.valor)).scalar() or 0
    
    receitas = (
        base_query.filter_by(tipo='receita')
        .with_entities(db.func.sum(Transacao.valor))
        .scalar() or 0
    )
    despesas = (
        base_query.filter_by(tipo='despesa')
        .with_entities(db.func.sum(Transacao.valor))
        .scalar() or 0
    )

    saldo =  receitas - despesas or 0

    # Latest transactions
    ultimas_transacoes = (
        base_query.order_by(Transacao.data.desc())
        .limit(8)
        .all()
    )
    
    return render_template('index.html', 
                         transacoes=ultimas_transacoes,
                         usuarios=usuarios,
                         user_id_filtro=user_id_filtro,
                         saldo=saldo,
                         receitas=receitas,
                         despesas=despesas,
                         selected_month=selected_month,
                         selected_year=selected_year,
                         months = months,
                         years=years
                         )

@login_manager.user_loader
def load_user(user_id):
    try:
        user_record = firebase_auth.get_user(user_id)
        db_firestore = firestore.client()
        user_doc = db_firestore.collection('usuarios').document(user_id).get()

        # Check custom claims for admin
        is_admin = user_record.custom_claims.get('admin', False) if user_record.custom_claims else False

        user_data = user_doc.to_dict() if user_doc.exists else {}
        provider_data = user_record.provider_data[0] if user_record.provider_data else None
        
        return User(
            uid=user_record.uid,
            email=user_record.email,
            name=user_data.get('full_name', user_record.display_name),
            is_admin=is_admin,
            provider=provider_data.provider_id.split('.')[0] if provider_data else 'password',
            primeiro_acesso=user_data.get('primeiro_acesso', True)
        )

    except Exception as e:
        print(f"Error loading user: {str(e)}")
        return None

@main_routes.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the e-mail is already registered with the social provider
        try:
            # Check if there is already an account with this e-mail address
            user_record = firebase_auth.get_user_by_email(email)
            
            # Verificar se existe provedor password
            if not any(p.provider_id == 'password' for p in user_record.provider_data):
                providers = [p.provider_id.split('.')[0] for p in user_record.provider_data]
                flash(f'This e-mail is associated with a social login. Use social login with: {", ".join(providers)} or reset your password', 'warning')
                
                return redirect(url_for('main.login'))
                
        except firebase_auth.UserNotFoundError:
            pass  # User does not exist, proceed with normal login
        
        try:

            # Normal login flow with email/password
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            response = requests.post(url, json=payload)
            data = response.json()

            if response.status_code == 200:
                decoded_token = firebase_auth.verify_id_token(
                    data['idToken'],
                    clock_skew_seconds=60
                )

                user_id = decoded_token['uid']
                
                # First admin logic
                if configurar_primeiro_admin(user_id):
                    firebase_auth.set_custom_user_claims(
                        user_id, 
                        {'admin': True}
                    )
                    #Update Firestore
                    atualizar_firestore_admin(user_id, True)
                    
                user = load_user(user_id)
                login_user(user)
                
                if user.primeiro_acesso:
                    return redirect(url_for('main.tutorial'))

                flash('Login successful!', 'success')
                return redirect(url_for('main.index'))

            # Refined error handling
            error_map = {
                'INVALID_PASSWORD': 'Incorrect password',
                'EMAIL_NOT_FOUND': 'Email not registered',
                'USER_DISABLED': 'Account deactivated',
                'INVALID_LOGIN_CREDENTIALS': 'Check that your e-mail address and password are correct',
                'TOO_MANY_ATTEMPTS_TRY_LATER': 'Too many attempts. Try again later.'
            }
            
            error_code = data.get('error', {}).get('message', 'UNKNOWN_ERROR')
            flash(error_map.get(error_code, f'Login error: {error_code}'), 'danger')

        except firebase_auth.UserNotFoundError:
            flash('Email not registered', 'danger')
        except firebase_auth.ErrorInfo as e:
            flash(f'Authentication error: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Unexpected error: {str(e)}', 'danger')

    return render_template('login.html', os=os)

@main_routes.route('/login/social', methods=['POST'])
def login_social():
    try:
        id_token = request.json.get('token')
        decoded_token = firebase_auth.verify_id_token(
            id_token, 
            check_revoked=True, 
            clock_skew_seconds=60)
        user_id = decoded_token['uid']
        
        # Get Firestore reference
        db_firestore = firestore.client()
        user_ref = db_firestore.collection('usuarios').document(user_id)
        
        # Create/Update user
        user_data = {
            'email': decoded_token.get('email'),
            'full_name': decoded_token.get('name', 'Usuário'),
            'last_login': firestore.SERVER_TIMESTAMP,
            'provider': decoded_token.get('firebase', {}).get('sign_in_provider')
        }

        if not user_ref.get().exists:
            user_data.update({
                'created_at': firestore.SERVER_TIMESTAMP,
                'admin': False,
                'primeiro_acesso': True
            })
            user_ref.set(user_data)
            
            if configurar_primeiro_admin(user_id):
                user_ref.update({'admin': True})
                firebase_auth.set_custom_user_claims(
                        user_id, 
                        {'admin': True}
                    )
        else:
            user_ref.update(user_data)

        user = load_user(user_id)
        login_user(user)
        
        return jsonify({
            'redirect': url_for('main.tutorial') if user.primeiro_acesso else url_for('main.index')
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 401
    

@main_routes.route('/tutorial', methods=['GET', 'POST'])
@login_required
def tutorial():
    if request.method == 'POST':
        try:
            db_firestore = firestore.client()
            db_firestore.collection('usuarios').document(current_user.id).update({
                'primeiro_acesso': False,
                'tutorial_completo_em': firestore.SERVER_TIMESTAMP
            })
            return redirect(url_for('main.index'))
        
        except Exception as e:
            flash(f'Error saving progress: {str(e)}', 'danger')
    
    return render_template('tutorial.html')

@main_routes.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main_routes.route('/cadastrar', methods=['GET', 'POST'])
def cadastrar():
    if request.method == 'POST':
        # Validate the CSRF token manually
        csrf.protect() 
        full_name = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        errors = validar_senha(password)

        if 'aceitar_termos' not in request.form:
            flash('You must accept the terms and conditions to register', 'danger')
            return redirect(url_for('main.cadastrar'))
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('cadastrar.html', email=email)
          
        user = None  # Initializes the variable
        try:
            # Tenta criar o usuário
            user = firebase_auth.create_user(
                email=email,
                password=password
            )
            
            # Saved in Firestore
            db_firestore = firestore.client()
            usuarios_ref = db_firestore.collection('usuarios')
            usuarios_ref.document(user.uid).set({
                'full_name': full_name,
                'email': email,
                'created_at': firestore.SERVER_TIMESTAMP,
                'admin': False
            })

            flash('Registration successful! Log in.', 'success')
            return redirect(url_for('main.login'))

        except firebase_auth.EmailAlreadyExistsError:
            flash('This email is already registered.', 'warning')
            return redirect(url_for('main.cadastrar'))
            
        except Exception as e:
            # Rollback only if the user has been created
            if user:
                firebase_auth.delete_user(user.uid)
            flash(f'Registration error: {str(e)}', 'danger')
            return redirect(url_for('main.cadastrar'))
    
    return render_template('cadastrar.html')

@main_routes.route('/termos-de-uso')
def termos_condicoes():
    return render_template('termos_condicoes.html', 
                         data_atual=datetime.now(br_tz).strftime('%d/%m/%Y'))

@main_routes.route('/politica-de-privacidade')
def politica_privacidade():
    return render_template('politica_privacidade.html',
                         data_atual=datetime.now(br_tz).strftime('%d/%m/%Y'))

# password recovery
@main_routes.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form['email']
        
        try:
            # Check if the user exists
            user = firebase_auth.get_user_by_email(email)
            
            # Generate secure token valid for 1 hour
            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            token = s.dumps(email, salt='password-reset')
            
            reset_link = url_for('main.redefinir_senha', token=token, _external=True)

            # Send personalized email
            msg = Message(
            'Password Reset',
            sender=os.getenv('MAIL_USERNAME'),
            recipients=[email]
            )
            msg.html = render_template(
                'email_recuperacao_senha.html',
                reset_link=reset_link,
                data_solicitacao=datetime.now(br_tz).strftime('%d/%m/%Y às %H:%M')
            )
            mail.send(msg)

            flash('Recovery email sent! Check your inbox and spam folder', 'success')
            return redirect(url_for('main.login'))

        except firebase_auth.UserNotFoundError:
            flash('Email not registered.', 'danger')
        except Exception as e:
            flash(f'Error sending email: {str(e)}', 'danger')

    return render_template('recuperar_senha.html')

# New password reset route
@main_routes.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    try:
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 hora de validade
    except:
        flash('Invalid or expired link. Request a new link.', 'danger')
        return redirect(url_for('main.recuperar_senha'))

    if request.method == 'POST':
        nova_senha = request.form['password']
        confirmacao = request.form['confirm_password']

       # Validations
        if nova_senha != confirmacao:
            flash("The passwords don't match!", 'danger')
            return render_template('redefinir_senha.html', token=token)

        errors = validar_senha(nova_senha)
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('redefinir_senha.html', token=token)

        try:
            user = firebase_auth.get_user_by_email(email)
            
            # Check that the new password is different from the current one
            try:
                # Try logging in with the new password to check it's the same
                url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={API_KEY}"
                response = requests.post(url, json={
                    "email": email,
                    "password": nova_senha,
                    "returnSecureToken": True
                })
                
                if response.status_code == 200:
                    flash('The new password must not be the same as the current password', 'danger')
                    return render_template('redefinir_senha.html', token=token)
            except:
                pass

            # Update password if all validations pass
            firebase_auth.update_user(user.uid, password=nova_senha)
            flash('Password reset successful! Log in with the new password.', 'success')
            return redirect(url_for('main.login'))

        except firebase_auth.ErrorInfo as e:
            flash(f'Error updating password: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Unexpected error: {str(e)}', 'danger')

    return render_template('redefinir_senha.html', token=token)

@main_routes.route('/transacoes')
@login_required
def listar_transacoes():
    user_id_filtro = request.args.get('user_id')
    selected_month, selected_year = get_filtro_data()

    # Build query base
    if current_user.is_admin:
        usuarios = firebase_auth.list_users().iterate_all()
        base_query = Transacao.query
        
        if user_id_filtro:
            base_query = base_query.filter_by(user_id=user_id_filtro)
    else:
        base_query = Transacao.query.filter_by(user_id=current_user.id)
        usuarios = []

    # Apply date filters
    if selected_month != 0:
        base_query = base_query.filter(
            db.extract('month', Transacao.data) == selected_month
        )
    
    if selected_year != 0:
        base_query = base_query.filter(
            db.extract('year', Transacao.data) == selected_year
        )
    
    transacoes = base_query.order_by(Transacao.data.desc()).all()

    return render_template('transacoes.html', 
                           transacoes=transacoes, 
                           firebase_auth=firebase_auth,
                           usuarios=usuarios,
                           user_id_filtro=user_id_filtro,
                           selected_month=selected_month,
                           selected_year=selected_year,
                           months=months,
                           years=years)

# Add this route to check for recurring transactions
@main_routes.route('/transacoes/recorrentes')
@login_required
def transacoes_recorrentes():
    user_id_filtro = request.args.get('user_id')
    
    # Construir query base
    if current_user.is_admin:
        usuarios = firebase_auth.list_users().iterate_all()
        base_query = Transacao.query.filter_by(recorrente=True)
        
        if user_id_filtro:
            try:
                firebase_auth.get_user(user_id_filtro)
                base_query = base_query.filter_by(user_id=user_id_filtro)
            except firebase_auth.UserNotFoundError:
                flash('User not found', 'danger')
                return redirect(url_for('main.transacoes_recorrentes'))
    else:
        base_query = Transacao.query.filter_by(
            user_id=current_user.id,
            recorrente=True
        )
        usuarios = []

    # Sort and get results
    transacoes = base_query.order_by(Transacao.data.desc()).all()
    
    return render_template('recorrentes.html', 
                         transacoes=transacoes, 
                         relativedelta=relativedelta,
                         usuarios=usuarios,
                         user_id_filtro=user_id_filtro,
                         firebase_auth=firebase_auth)



@main_routes.route('/adicionar', methods=['GET', 'POST'])
@login_required
def adicionar_transacao():
    categorias = Categoria.query.all()
    
    if request.method == 'POST':
        descricao = request.form['descricao']
        valor = float(request.form['valor'])
        tipo = request.form['tipo']
        categoria_id = int(request.form['categoria'])
        # (antigo formato) data = datetime.strptime(request.form['data'], '%Y-%m-%d')
        data = datetime.strptime(request.form['data'], '%Y-%m-%dT%H:%M')

        recorrente = 'recorrente' in request.form
        
        nova_transacao = Transacao(
            user_id=current_user.id,
            descricao=descricao,
            valor=valor,
            tipo=tipo,
            categoria_id=categoria_id,
            data=data,
            recorrente=recorrente,
            data_original=data if recorrente else None
        )
        
        db.session.add(nova_transacao)
        db.session.commit()
        
        flash('Transaction successfully added!', 'success')
        return redirect(url_for('.index'))
    
    return render_template('adicionar.html', categorias=categorias, datetime=datetime, br_tz=br_tz)



@main_routes.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_transacao(id):
    transacao = Transacao.query.get_or_404(id)
    categorias = Categoria.query.all()

    if not (current_user.is_admin or transacao.user_id == current_user.id):
        abort(403)

    if request.method == 'POST':
        try:
            csrf.protect()
            
            # Update basic fields
            transacao.descricao = request.form['descricao']
            transacao.valor = float(request.form['valor'])
            transacao.tipo = request.form['tipo']
            transacao.categoria_id = int(request.form['categoria'])
            transacao.data = datetime.strptime(request.form['data'], '%Y-%m-%dT%H:%M')

            novo_recorrente = 'recorrente' in request.form

            # Recurrence update logic
            if transacao.recorrente and not novo_recorrente:
                # Disable recurrence
                transacao.recorrente = False
                transacao.meses_repeticao = 0
                transacao.data_original = None
            elif not transacao.recorrente and novo_recorrente:
                # Activate recurrence
                transacao.recorrente = True
                transacao.data_original = transacao.data  # Define data_original inicial
                transacao.meses_repeticao = 0

            # Synchronizes original_date if it is recurring and not triggered
            if transacao.recorrente and transacao.meses_repeticao == 0:
                transacao.data_original = transacao.data  # Always keep up to date

            db.session.commit()
            flash('Transaction successfully updated!', 'success')
            return redirect(url_for('main.listar_transacoes'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error when updating: {str(e)}', 'danger')

    return render_template('editar.html', 
                         transacao=transacao, 
                         categorias=categorias)

# When the user himself wants to delete his account
def excluir_conta_usuario(user_id):
    try:
        db_firestore = firestore.client()
        
        # 1. Deleting data from Firestore
        user_ref = db_firestore.collection('usuarios').document(user_id)
        user_ref.delete()

        # 2. Delete related transactions in SQL
        Transacao.query.filter_by(user_id=user_id).delete()
        db.session.commit()

        # 3. delete Firebase Auth user
        firebase_auth.delete_user(user_id)

        # 4. Logout and redirection
        logout_user()
        flash('Your account and all data have been successfully deleted', 'success')
        return redirect(url_for('main.login'))

    except firebase_auth.UserNotFoundError:
        flash('User no longer exists', 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting account: {str(e)}', 'danger')
    
    return redirect(url_for('main.perfil'))


# When admin wants to delete user account
@main_routes.route('/excluir-usuario/<uid>', methods=['POST'])
@admin_required
def excluir_usuario(uid):
    try:
        csrf.protect()
        
        # 1. Delete from Firebase Auth
        firebase_auth.delete_user(uid)
        
        # 2. Deleting data from Firestore
        db_firestore = firestore.client()
        db_firestore.collection('usuarios').document(uid).delete()
        
        #3 Deleting transactions from SQL
        Transacao.query.filter_by(user_id=uid).delete()
        db.session.commit()
        
        flash('User and all data successfully deleted', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error when deleting user: {str(e)}', 'danger')
    return redirect(url_for('main.admin_panel'))

# Deactivate or activate user account
@main_routes.route('/toggle-status-usuario/<uid>', methods=['POST'])
@admin_required
def toggle_status_usuario(uid):
    try:
        csrf.protect()
        user = firebase_auth.get_user(uid)
        new_status = not user.disabled
        
        firebase_auth.update_user(
            uid,
            disabled=new_status
        )
        
        status_msg = 'deactivated' if new_status else 'reactivated'
        flash(f'Account {status_msg} successfully', 'success')
    except Exception as e:
        flash(f'Error when changing status: {str(e)}', 'danger')
    return redirect(url_for('main.admin_panel'))

@main_routes.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    try:
        db_firestore = firestore.client()
        user_ref = db_firestore.collection('usuarios').document(current_user.id)
        user_doc = user_ref.get()

        if request.method == 'POST':
            csrf.protect()
            
            # Goal update section
            if 'definir_meta' in request.form:
                nova_meta = float(request.form['meta_alerta'])
                
                if not (0 <= nova_meta <= 100):
                    flash('The target should be between 0% and 100%', 'danger')
                    return redirect(url_for('main.perfil'))
                
                user_ref.update({'meta_alerta': nova_meta})
                flash('Alert target successfully updated!', 'success')
                return redirect(url_for('main.perfil'))
            
            # Check for account deletion
            if 'delete_account' in request.form:
                return excluir_conta_usuario(current_user.id)

            novo_nome = request.form['nome'].strip()
            if not novo_nome:
                flash('The name cannot be empty', 'danger')
                return redirect(url_for('main.perfil'))

            # Update Firestore
            user_ref.update({'full_name': novo_nome})
            
            # Update Firebase Auth (display name)
            firebase_auth.update_user(
                current_user.id,
                display_name=novo_nome
            )

            # Update user in session
            user = load_user(current_user.id)
            login_user(user)

            flash('Name successfully updated!', 'success')
            return redirect(url_for('main.perfil'))

        # Load current data
        nome_atual = user_doc.get('full_name') if user_doc.exists else current_user.name

        # Load current data
        user_data = user_doc.to_dict() if user_doc.exists else {}
        meta_atual = user_data.get('meta_alerta', 10.0)  # Default 10%

        return render_template('perfil.html', 
                            nome_atual=nome_atual,
                            provider=current_user.provider,
                            meta_atual=meta_atual)

    except Exception as e:
        flash(f'Error updating profile: {str(e)}', 'danger')
        return redirect(url_for('main.perfil'))
    

@main_routes.route('/excluir/<int:id>')
@login_required
def excluir_transacao(id):
    transacao = Transacao.query.get_or_404(id)
    # Check if you are owner or admin
    if not (current_user.is_admin or transacao.user_id == current_user.id):
        abort(403)
    db.session.delete(transacao)
    db.session.commit()
    flash('Transaction successfully deleted!', 'success')
    return redirect(url_for('main.listar_transacoes'))


@main_routes.route('/resumo')
@login_required
def resumo():
    graficos = {}
    resumo_categorias = []
    transacoes_recentes = []
    usuarios = []
    user_id_filtro = request.args.get('user_id')
    selected_month, selected_year = get_filtro_data()

    try:
         # Construir query base
        if current_user.is_admin:
            usuarios = firebase_auth.list_users().iterate_all()
            base_query = Transacao.query
            
            if user_id_filtro:
                base_query = base_query.filter_by(user_id=user_id_filtro)
        else:
            base_query = Transacao.query.filter_by(user_id=current_user.id)

        # Aplicar filtros de data
        if selected_month != 0:
            base_query = base_query.filter(
                db.extract('month', Transacao.data) == selected_month
            )
        
        if selected_year != 0:
            base_query = base_query.filter(
                db.extract('year', Transacao.data) == selected_year
            )

        # Summary by category
        resumo_categorias = (
            base_query.join(Categoria)
            .with_entities(
                Categoria.nome,
                db.func.sum(Transacao.valor).label('total')
            )
            .group_by(Categoria.nome)
            .all()
        )

        transacoes_todas = (
            base_query
            .order_by(Transacao.data.desc())
            .all()
        )
        
        transacoes_recentes = (
            base_query
            .order_by(Transacao.data.desc())
            .limit(8)
            .all()
        )

        # Criar DataFrame para análise
        df = pd.DataFrame([{
            'Categoria': t.categoria_rel.nome,
            'Valor': t.valor,
            'Tipo': t.tipo,
            'Data': t.data
        } for t in transacoes_todas])

        # Graph 1: Expenditure by Category
        if not df.empty and 'despesa' in df['Tipo'].values:
            fig_despesas = px.pie(
                df[df['Tipo'] == 'despesa'],
                names='Categoria',
                values='Valor',
                title='Distribution of Expenses by Category',
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig_despesas.update_layout(font=dict(family="Poppins, sans-serif"))

            graficos['despesas'] = fig_despesas.to_html(full_html=False)
        else:
            pass

        # Graph 2: Income vs Expenses comparison
        if not df.empty and len(df['Tipo'].unique()) > 0:
            df_agg = df.groupby('Tipo', as_index=False).agg({'Valor': 'sum'})
            df_agg = df_agg.sort_values(by='Valor', ascending=False)
            
            if not df_agg.empty:
                df_agg['Valor_formatado'] = df_agg['Valor'].apply(
                    lambda x: f"{x:,.0f}".replace(",", "X").replace(".", ",").replace("X", ".")
                )

                fig_comparativo = px.bar(
                    df_agg,
                    x='Tipo',
                    y='Valor',
                    title='Revenues vs Expenses',
                    color='Tipo',
                    text='Valor_formatado',
                    color_discrete_map={
                        'receita': '#57C7A2',
                        'despesa': '#F06960'
                    }
                )
                fig_comparativo.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    yaxis_title='Amount ($)',
                    xaxis_title='Type',
                    font=dict(family="Poppins, sans-serif")
                )

                fig_comparativo.update_traces(
                    textposition='outside',
                    textfont_size=10
                )

                # Substituir os valores do eixo y por strings formatadas ao estilo brasileiro
                ticks = df_agg['Valor'].max()
                tick_vals = list(range(0, int(ticks) + 1, int(ticks / 5)))  # 5 ticks
                tick_text = [f"{v:,.0f}".replace(",", "X").replace(".", ",").replace("X", ".") for v in tick_vals]

                fig_comparativo.update_yaxes(
                    tickformat=',.0f',
                    tickvals=tick_vals,
                    ticktext=tick_text,             # Sem casas decimais, com separador de milhar
                    separatethousands=True
                )

                graficos['comparativo'] = fig_comparativo.to_html(full_html=False)
            else:
                pass
        else:
            pass

    except Exception as e:
        flash(f'An error occurred when generating the dashboard: {str(e)}', 'danger')
        return redirect(url_for('main.index'))

    return render_template(
        'resumo.html',
        resumo_categorias=resumo_categorias,
        transacoes_recentes=transacoes_recentes,
        usuarios=usuarios,
        user_id_filtro=user_id_filtro,
        data_atual=datetime.now(br_tz).strftime('%Y-%m-%d'),
        firebase_auth=firebase_auth,
        graficos=graficos,
        selected_month=selected_month,
        selected_year=selected_year,
        months=months,
        years=years
    )