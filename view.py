from flask import Flask, request, jsonify
from datetime import datetime
from main import app, con  # Mantendo a importação conforme seu setup
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
from flask_cors import CORS
import re
import bcrypt
import fdb
import requests
import jwt
import os

bcrypt = Bcrypt(app)  # Inicializa o bcrypt para criptografia segura
app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']


# Função para gerar token JWT
def generate_token(user_id, email):
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        # Onde os arquivos serão salvos, caso ele não exista será criado.
        os.makedirs(app.config['UPLOAD_FOLDER'])
    payload = {'id_usuario': user_id, 'email': email}
    # Define o payload onde vai definir as informações que serão passadas para o token.
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    # Faz com que o token seja gerado com as informações do payload e uma senha secreta.
    return token


def remover_bearer(token):
    # Verifica se o token começa com 'Bearer '
    if token.startswith('Bearer '):
        # Se o token começar com 'Bearer ', remove o prefixo 'Bearer ' do token
        return token[len('Bearer '):]
    else:
        # Se o token não começar com 'Bearer ', retorna o token original sem alterações
        return token


def validar_senha(senha):
    padrao = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
    return bool(re.fullmatch(padrao, senha))


def buscar_dados_cep(cep):
    url = f"https://viacep.com.br/ws/{cep}/json/"
    try:
        resposta = requests.get(url, timeout=5)
        if resposta.status_code == 200:
            dados = resposta.json()
            if 'erro' in dados:
                return None
            return {
                'bairro': dados.get('bairro'),
                'uf': dados.get('uf'),
                'cidade': dados.get('localidade'),
                'logradouro': dados.get('logradouro')
            }
        else:
            return None
    except Exception:
        return None


@app.route('/usuario', methods=['GET'])
def usuario():
    pagina = int(request.args.get('pagina', 1))
    quantidade_por_pagina = 10

    primeiro_usuario = (pagina * quantidade_por_pagina) - quantidade_por_pagina + 1
    ultimo_usuario = pagina * quantidade_por_pagina

    cur = con.cursor()
    cur.execute(f'''
        SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, categoria, nome_marca, status
        FROM usuario
        ROWS {primeiro_usuario} TO {ultimo_usuario}
    ''')
    usuarios = cur.fetchall()

    cur.execute('SELECT COUNT(*) FROM usuario')
    total_usuarios = cur.fetchone()[0]
    total_paginas = (total_usuarios + quantidade_por_pagina - 1) // quantidade_por_pagina

    usuarios_dic = []
    for u in usuarios:
        usuarios_dic.append({
            'id_usuario': u[0],
            'nome': u[1],
            'email': u[2],
            'telefone': u[3],
            'data_nascimento': u[4],
            'cargo': u[5],
            'categoria': u[6],
            'nome_marca': u[7],
            'status': u[8]
        })

    return jsonify(
        mensagem='Lista de Usuarios',
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_usuarios=total_usuarios,
        usuarios=usuarios_dic
    )


@app.route('/usuario', methods=['POST'])
def usuario_post():
    data = request.get_json()

    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento_str = data.get('data_nascimento')
    cargo = data.get('cargo')
    cep = data.get('cep')  # Mover para cima

    # Verificar se campos obrigatórios foram enviados
    if not nome or not email or not senha:
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    cursor = con.cursor()

    # Verificar se o email já existe no banco
    cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
    usuario_existente = cursor.fetchone()

    if usuario_existente:
        cursor.close()
        return jsonify({"error": "Este email já está em uso. Escolha outro email."}), 400

    # Converter data_nascimento
    try:
        data_nascimento = (
            datetime.strptime(data_nascimento_str, '%d-%m-%Y').date()
            if data_nascimento_str else None
        )
        data_nascimento_formatada = data_nascimento.strftime('%d/%m/%Y') if data_nascimento else None
    except Exception:
        cursor.close()
        return jsonify({"error": "Data de nascimento inválida. Use dd-mm-aaaa."}), 400

    # Validar senha forte
    if not validar_senha(senha):
        cursor.close()
        return jsonify({
            "error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
        }), 400

    # VALIDAR CEP ANTES DE CRIAR O USUÁRIO
    bairro = uf = cidade = logradouro = None
    tipo_endereco = None

    if cep:
        dados_cep = buscar_dados_cep(cep)
        if not dados_cep:
            cursor.close()
            return jsonify({"error": "CEP inválido ou não encontrado."}), 400

        bairro = dados_cep['bairro']
        uf = dados_cep['uf']
        cidade = dados_cep['cidade']
        logradouro = dados_cep['logradouro']

        if cargo == '2':
            tipo_endereco = '2'  # comercial
        else:
            tipo_endereco = '1'  # residencial

    # Agora que tudo foi validado, criar o usuário
    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

    # Definir categoria e nome_marca baseado no cargo
    if cargo == '1':  # Cliente
        categoria = None
        nome_marca = None
    else:  # Fornecedor ou outros
        categoria = data.get('categoria')
        nome_marca = data.get('nome_marca')

    sql_usuario = """
    INSERT INTO USUARIO
    (NOME, EMAIL, SENHA, TELEFONE, DATA_NASCIMENTO, CARGO,
    CATEGORIA, NOME_MARCA, TENTATIVAS_ERRO, STATUS)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    valores_usuario = (
        nome,
        email,
        senha_hash,
        telefone,
        data_nascimento,
        cargo,
        categoria,
        nome_marca,
        '0',
        'A'
    )

    try:
        cursor.execute(sql_usuario, valores_usuario)
        con.commit()

        cursor.execute('SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?', (email,))
        id_usuario = cursor.fetchone()
        if not id_usuario:
            cursor.close()
            return jsonify({"error": "Falha ao obter ID do usuário cadastrado."}), 500
        id_usuario = id_usuario[0]

        # Inserir endereço se CEP foi fornecido
        if cep:
            sql_endereco = """
            INSERT INTO ENDERECO (ID_USUARIO, CEP, UF, CIDADE, BAIRRO, LOGRADOURO, TIPO_ENDERECO)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            valores_endereco = (id_usuario, cep, uf, cidade, bairro, logradouro, tipo_endereco)
            cursor.execute(sql_endereco, valores_endereco)
            con.commit()

        cursor.close()

        return jsonify({
            "message": "Usuário cadastrado com sucesso!",
            "usuario": {
                'nome': nome,
                'email': email,
                'telefone': telefone,
                'data_nascimento': data_nascimento_formatada,
                'cargo': cargo,
                'categoria': categoria,
                'nome_marca': nome_marca,
            },
            "endereco": {
                'cep': cep,
                'uf': uf,
                'cidade': cidade,
                'bairro': bairro,
                'logradouro': logradouro,
                'tipo_endereco': tipo_endereco
            } if cep else None
        })
    except Exception as e:
        cursor.close()
        return jsonify({"error": str(e)}), 500


# Troque pela sua chave secreta segura!
JWT_SECRET = "sua_secret_key"
JWT_EXPIRE_MINUTES = 60

def generate_token(id_usuario, email):
    payload = {
        "id_usuario": id_usuario,
        "email": email,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    cursor = con.cursor()
    cursor.execute("SELECT SENHA, ID_USUARIO, NOME, EMAIL, TELEFONE, DATA_NASCIMENTO, CARGO, CATEGORIA, NOME_MARCA, TENTATIVAS_ERRO, STATUS FROM usuario WHERE EMAIL = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        return jsonify({"error": "Usuário não encontrado"}), 404

    senha_hash = usuario[0]
    id_usuario = usuario[1]
    nome = usuario[2]
    email = usuario[3]
    telefone = usuario[4]
    data_nascimento = usuario[5]
    cargo = usuario[6]
    categoria = usuario[7]
    nome_marca = usuario[8]
    tentativas_erro = usuario[9]
    status = usuario[10]

    if status == 'I':
        return jsonify({"error": "Você errou seu email ou sua senha 3 vezes, o usuário foi inativado."}), 403

    if bcrypt.check_password_hash(senha_hash, senha):
        # Resetar tentativas de erro no login bem-sucedido
        cursor.execute("UPDATE USUARIO SET TENTATIVAS_ERRO = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        # Limpar o código de verificação após login bem-sucedido
        con.commit()
        cursor.close()

        token = generate_token(id_usuario, email)
        return jsonify({
            "message": "Login realizado com sucesso",
            "token": token,
            "usuario": {
                "id_usuario": id_usuario,
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "data_nascimento": data_nascimento.strftime('%d-%m-%Y') if data_nascimento else None,
                "cargo": cargo,
                "categoria": categoria,
                "nome_marca": nome_marca
            }
        }), 200

    # Após buscar tentativas_erro:
    tentativas_erro = int(tentativas_erro) if tentativas_erro is not None else 0
    # Agora pode incrementar:
    tentativas_erro += 1

    cursor.execute("UPDATE USUARIO SET TENTATIVAS_ERRO = ? WHERE ID_USUARIO = ?", (tentativas_erro, id_usuario))
    con.commit()

    if tentativas_erro >= 3:
        cursor.execute("UPDATE USUARIO SET STATUS = 'I' WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

    cursor.close()
    return jsonify({"error": "Email ou senha inválidos"}), 401


@app.route('/servico', methods=['POST'])
def servico_post():
    try:
        data = request.get_json()

        # Validação de dados obrigatórios
        if not data:
            return jsonify({"error": "JSON inválido"}), 400

        nome = data.get('nome')
        valor = data.get('valor')
        descricao = data.get('descricao')
        id_usuario = data.get('id_usuario')  # Chave estrangeira obrigatória

        # Validação dos campos obrigatórios
        if not nome or not valor or not id_usuario:
            return jsonify({
                "error": "Campos obrigatórios: nome, valor, id_usuario"
            }), 400

        cursor = con.cursor()

        # Query corrigida com todos os campos necessários
        sql_servico = """
        INSERT INTO SERVICOS
        (ID_USUARIO, NOME, VALOR, DESCRICAO)
        VALUES (?, ?, ?, ?)
        """

        # Executar a query
        cursor.execute(sql_servico, (id_usuario, nome, valor, descricao))

        # Commit para salvar no banco
        con.commit()

        # Fechar cursor
        cursor.close()

        return jsonify({
            "message": "Serviço cadastrado com sucesso!",
            "servico": {
                'id_usuario': id_usuario,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
            }
        }), 201

    except Exception as e:
        # Rollback em caso de erro
        con.rollback()
        if 'cursor' in locals():
            cursor.close()

        return jsonify({
            "error": "Erro ao cadastrar serviço",
            "details": str(e)
        }), 500
