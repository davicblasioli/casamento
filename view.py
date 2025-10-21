from flask import request, jsonify
from datetime import datetime
from main import app, con  # Mantendo a importação conforme seu setup
from flask_bcrypt import Bcrypt
import re
import bcrypt
import requests
import jwt
import os

bcrypt = Bcrypt(app)  # Inicializa o bcrypt para criptografia segura
app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']


# Troque pela sua chave secreta segura!
JWT_EXPIRE_MINUTES = 60


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


@app.route('/usuario/<int:id>', methods=['GET'])
def usuario_por_id(id):
    cursor = con.cursor()
    cursor.execute('''
        SELECT 
            u.ID_USUARIO, 
            u.NOME, 
            u.EMAIL, 
            u.TELEFONE, 
            u.DATA_NASCIMENTO, 
            u.CARGO, 
            u.CATEGORIA, 
            u.NOME_MARCA, 
            u.STATUS,
            e.CEP
        FROM USUARIO u
        LEFT JOIN ENDERECO e ON u.ID_USUARIO = e.ID_USUARIO
        WHERE u.ID_USUARIO = ?
    ''', (id,))

    usuario = cursor.fetchone()
    cursor.close()

    if not usuario:
        return jsonify({"error": "Usuário não encontrado."}), 404

    # Formata a data de nascimento para DD-MM-YYYY
    data_nascimento = None
    if usuario[4]:
        if isinstance(usuario[4], str):
            data_nascimento = usuario[4]
        else:
            data_nascimento = usuario[4].strftime('%d-%m-%Y')

    usuario_dic = {
        'id_usuario': usuario[0],
        'nome': usuario[1],
        'email': usuario[2],
        'telefone': usuario[3],
        'data_nascimento': data_nascimento,
        'cargo': usuario[5],
        'categoria': usuario[6],
        'nome_marca': usuario[7],
        'status': usuario[8],
        'cep': usuario[9]
    }

    return jsonify(
        mensagem='Usuário encontrado',
        usuario=usuario_dic
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


@app.route('/usuarios/<int:id>', methods=['PUT'])
def usuario_put(id):
    cursor = con.cursor()
    cursor.execute("SELECT ID_USUARIO, CARGO FROM USUARIO WHERE ID_USUARIO = ?", (id,))
    usuario_data = cursor.fetchone()
    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário não encontrado'}), 404

    cargo = str(usuario_data[1])
    nome = request.form.get('nome')
    email = request.form.get('email')
    telefone = request.form.get('telefone')
    data_nascimento_str = request.form.get('data_nascimento')
    cep = request.form.get('cep')
    categoria = request.form.get('categoria')
    nome_marca = request.form.get('nome_marca')
    imagem = request.files.get('imagem')

    # Validação mínima
    if not nome or not email:
        cursor.close()
        return jsonify({"error": "Nome e email obrigatórios."}), 400

    cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id))
    email_existente = cursor.fetchone()
    if email_existente:
        cursor.close()
        return jsonify({"error": "Este email já está em uso por outro usuário."}), 400

    try:
        data_nascimento = (
            datetime.strptime(data_nascimento_str, '%d-%m-%Y').date()
            if data_nascimento_str else None
        )
    except Exception:
        cursor.close()
        return jsonify({"error": "Data de nascimento inválida. Use dd-mm-aaaa."}), 400

    # Atualiza CEP independente do cargo
    if cep:
        cursor.execute('UPDATE ENDERECO SET CEP = ? WHERE ID_USUARIO = ?', (cep, id))

    # Campos básicos do usuário
    update_fields = ["NOME = ?", "EMAIL = ?", "TELEFONE = ?", "DATA_NASCIMENTO = ?"]
    update_values = [nome, email, telefone, data_nascimento]

    # Se fornecedor, autoriza editar categoria e nome da marca
    if cargo == '2':
        update_fields += ["CATEGORIA = ?", "NOME_MARCA = ?"]
        update_values += [categoria, nome_marca]

    update_values.append(id)
    sql_update = f"UPDATE USUARIO SET {', '.join(update_fields)} WHERE ID_USUARIO = ?"
    cursor.execute(sql_update, update_values)
    con.commit()
    cursor.close()

    if imagem:
        nome_imagem = f"{id}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Usuarios")
        os.makedirs(pasta_destino, exist_ok=True)
        imagem.save(os.path.join(pasta_destino, nome_imagem))

    return jsonify({
        'message': 'Usuário editado com sucesso!',
        'usuario': {
            'id_usuario': id,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento_str,
            'cep': cep,
            'categoria': categoria if cargo == '2' else None,
            'nome_marca': nome_marca if cargo == '2' else None
        }
    })


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


@app.route('/fornecedores', methods=['GET'])
def fornecedores():
    cur = con.cursor()

    cur.execute("""
        SELECT 
            u.ID_USUARIO, 
            u.NOME, 
            u.EMAIL, 
            u.TELEFONE, 
            u.DATA_NASCIMENTO, 
            u.CARGO, 
            u.CATEGORIA, 
            u.NOME_MARCA, 
            u.STATUS,
            e.CEP
        FROM USUARIO u
        LEFT JOIN ENDERECO e ON u.ID_USUARIO = e.ID_USUARIO
        WHERE u.CARGO = 2
    """)

    usuarios = cur.fetchall()
    cur.close()
    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        email = usuario[2]
        telefone = usuario[3]
        data_nascimento = usuario[4]
        cargo = usuario[5]
        categoria = usuario[6]
        nome_marca = usuario[7]
        status = usuario[8]
        cep = usuario[9]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'categoria': categoria,
            'nome_marca': nome_marca,
            'status': status,
            'cep': cep
        })

    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de Usuários', usuarios=usuarios_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')


@app.route('/noivos', methods=['GET'])
def noivos():
    cur = con.cursor()

    cur.execute("""
        SELECT 
            u.ID_USUARIO, 
            u.NOME, 
            u.EMAIL, 
            u.TELEFONE, 
            u.DATA_NASCIMENTO, 
            u.CARGO, 
            u.CATEGORIA, 
            u.NOME_MARCA, 
            u.STATUS,
            e.CEP
        FROM USUARIO u
        LEFT JOIN ENDERECO e ON u.ID_USUARIO = e.ID_USUARIO
        WHERE u.CARGO = 1
    """)

    usuarios = cur.fetchall()
    cur.close()
    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        email = usuario[2]
        telefone = usuario[3]
        data_nascimento = usuario[4]
        cargo = usuario[5]
        categoria = usuario[6]
        nome_marca = usuario[7]
        status = usuario[8]
        cep = usuario[9]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'categoria': categoria,
            'nome_marca': nome_marca,
            'status': status,
            'cep': cep
        })

    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de Usuários', usuarios=usuarios_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')



@app.route('/administradores', methods=['GET'])
def administradores():
    cur = con.cursor()

    cur.execute("""
        SELECT 
            u.ID_USUARIO, 
            u.NOME, 
            u.EMAIL, 
            u.TELEFONE, 
            u.DATA_NASCIMENTO, 
            u.CARGO, 
            u.CATEGORIA, 
            u.NOME_MARCA, 
            u.STATUS,
            e.CEP
        FROM USUARIO u
        LEFT JOIN ENDERECO e ON u.ID_USUARIO = e.ID_USUARIO
        WHERE u.CARGO = 4
    """)

    usuarios = cur.fetchall()
    cur.close()
    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        email = usuario[2]
        telefone = usuario[3]
        data_nascimento = usuario[4]
        cargo = usuario[5]
        categoria = usuario[6]
        nome_marca = usuario[7]
        status = usuario[8]
        cep = usuario[9]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'categoria': categoria,
            'nome_marca': nome_marca,
            'status': status,
            'cep': cep
        })

    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de Usuários', usuarios=usuarios_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')




@app.route('/cerimonialistas', methods=['GET'])
def cerimonialistas():
    cur = con.cursor()

    cur.execute("""
        SELECT 
            u.ID_USUARIO, 
            u.NOME, 
            u.EMAIL, 
            u.TELEFONE, 
            u.DATA_NASCIMENTO, 
            u.CARGO, 
            u.CATEGORIA, 
            u.NOME_MARCA, 
            u.STATUS,
            e.CEP
        FROM USUARIO u
        LEFT JOIN ENDERECO e ON u.ID_USUARIO = e.ID_USUARIO
        WHERE u.CARGO = 3
    """)

    usuarios = cur.fetchall()
    cur.close()
    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        email = usuario[2]
        telefone = usuario[3]
        data_nascimento = usuario[4]
        cargo = usuario[5]
        categoria = usuario[6]
        nome_marca = usuario[7]
        status = usuario[8]
        cep = usuario[9]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'categoria': categoria,
            'nome_marca': nome_marca,
            'status': status,
            'cep': cep
        })

    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de Usuários', usuarios=usuarios_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')




@app.route('/adms', methods=['GET'])
def listar_adms():
    cur = con.cursor()

    cur.execute(
        "SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, categoria, nome_marca, status FROM usuario WHERE cargo = 4"
    )
    usuarios = cur.fetchall()
    cur.close()
    usuarios_dic = []

    for usuario in usuarios:
        id_usuario = usuario[0]
        nome = usuario[1]
        email = usuario[2]
        telefone = usuario[3]
        data_nascimento = usuario[4]
        cargo = usuario[5]
        categoria = usuario[6]
        nome_marca = usuario[7]
        status = usuario[8]

        usuarios_dic.append({
            'id_usuario': id_usuario,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'categoria': categoria,
            'nome_marca': nome_marca,
            'status': status
        })

    if usuarios_dic:
        return jsonify(mensagem='Registro de Cadastro de ADMs', usuarios=usuarios_dic)
    else:
        return jsonify(mensagem='Nenhum dado encontrado')



@app.route('/fornecedor/<int:id_fornecedor>', methods=['GET'])
def fornecedor_por_id(id_fornecedor):
    cursor = con.cursor()
    cursor.execute('''
        SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, categoria, nome_marca, status
        FROM usuario
        WHERE id_usuario = ? AND cargo = '2' AND status = 'A'
    ''', (id_fornecedor,))
    fornecedor = cursor.fetchone()
    cursor.close()
    if not fornecedor:
        return jsonify({"error": "Fornecedor não encontrado."}), 404

    fornecedor_dic = {
        'id_usuario': fornecedor[0],
        'nome': fornecedor[1],
        'email': fornecedor[2],
        'telefone': fornecedor[3],
        'data_nascimento': fornecedor[4],
        'cargo': fornecedor[5],
        'categoria': fornecedor[6],
        'nome_marca': fornecedor[7],
        'status': fornecedor[8]
    }

    return jsonify(
        mensagem='Fornecedor encontrado',
        fornecedor=fornecedor_dic
    )


@app.route('/servico', methods=['GET'])
def servico_get():
    cursor = con.cursor()
    cursor.execute(
        "SELECT ID_USUARIO, NOME, VALOR, DESCRICAO FROM SERVICOS"
    )
    servicos = cursor.fetchall()
    cursor.close()

    servicos_lista = []
    for servico in servicos:
        servicos_lista.append({
            'id_usuario': servico[0],
            'nome': servico[1],
            'valor': servico[2],
            'descricao': servico[3]
        })

    if servicos_lista:
        return jsonify(mensagem='Lista de serviços cadastrados', servicos=servicos_lista)
    else:
        return jsonify(mensagem='Nenhum serviço encontrado')


@app.route('/servico', methods=['POST'])
def servico_post():
    # 1. Autenticação e validação do token JWT
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # 2. Buscar o usuário no banco e verificar o cargo
    cursor = con.cursor()
    cursor.execute("SELECT CARGO FROM USUARIO WHERE ID_USUARIO = ? AND STATUS = 'A'", (id_usuario,))
    resultado = cursor.fetchone()
    if not resultado:
        cursor.close()
        return jsonify({"error": "Usuário não encontrado ou inativo."}), 403

    cargo = resultado[0]
    if str(cargo) != '2':
        cursor.close()
        return jsonify({"error": "Apenas fornecedores podem cadastrar serviços."}), 403

    # 3. Receber dados do form-data (nome, valor, descricao, imagem)
    nome = request.form.get('nome')
    valor = request.form.get('valor')
    descricao = request.form.get('descricao')
    imagem = request.files.get('imagem')

    # 4. Validação dos campos obrigatórios
    if not nome or not valor:
        cursor.close()
        return jsonify({
            "error": "Campos obrigatórios: nome e valor"
        }), 400

    try:
        # Passo 1: Inserir o novo serviço
        sql_servico = """
            INSERT INTO SERVICOS (ID_USUARIO, NOME, VALOR, DESCRICAO)
            VALUES (?, ?, ?, ?)
        """
        cursor.execute(sql_servico, (id_usuario, nome, valor, descricao))
        con.commit()

        # Passo 2: Selecionar o ID do serviço recém inserido
        sql_select = """
            SELECT ID_SERVICO
            FROM SERVICOS
            WHERE ID_USUARIO = ? AND NOME = ? AND VALOR = ? AND DESCRICAO = ?
            ORDER BY ID_SERVICO DESC
            FETCH FIRST 1 ROWS ONLY
        """

        cursor.execute(sql_select, (id_usuario, nome, valor, descricao))
        id_servico = cursor.fetchone()[0]
        con.commit()

        # Salvar a imagem se for enviada
        imagem_path = None
        if imagem:
            nome_imagem = f"{id_servico}.jpeg"
            pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Servicos")
            os.makedirs(pasta_destino, exist_ok=True)
            imagem_path = os.path.join(pasta_destino, nome_imagem)
            imagem.save(imagem_path)

        cursor.close()

        if imagem:
            print(f"Recebido arquivo de imagem: {imagem.filename}")
            # salvar imagem...
        else:
            print("Nenhuma imagem recebida")

        return jsonify({
            "message": "Serviço cadastrado com sucesso!",
            "servico": {
                'id_usuario': id_usuario,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
                'imagem_salva': f"/static/uploads/Servico/{id_servico}.jpeg",
                'id_servico': id_servico
            }
        }), 201

    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({
            "error": "Erro ao cadastrar serviço",
            "details": str(e)
        }), 500


@app.route('/servico/<int:id_servico>', methods=['PUT'])
def servico_put(id_servico):
    # 1. Autenticação
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401
    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_token = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()
    # 2. Verifica se o serviço existe e pertence ao usuário do token
    cursor.execute("SELECT ID_USUARIO FROM SERVICOS WHERE ID_SERVICO = ?", (id_servico,))
    serv = cursor.fetchone()
    if not serv:
        cursor.close()
        return jsonify({'error': 'Serviço não encontrado'}), 404
    if serv[0] != id_usuario_token:
        cursor.close()
        return jsonify({'error': 'Permissão negada. Só o dono do serviço pode editar.'}), 403

    # 3. Recebe dados: aceitar tanto JSON quanto form-data (para imagem)
    nome = None
    valor = None
    descricao = None
    imagem = None

    if request.content_type and 'multipart/form-data' in request.content_type:
        nome = request.form.get('nome')
        valor = request.form.get('valor')
        descricao = request.form.get('descricao')
        imagem = request.files.get('imagem')
    else:
        data = request.get_json(silent=True)
        if not data:
            cursor.close()
            return jsonify({'error': 'Nenhum dado enviado'}), 400
        nome = data.get('nome')
        valor = data.get('valor')
        descricao = data.get('descricao')
        # imagem só pode via multipart/form-data

    # 4. Validação mínima: pelo menos um campo para atualizar
    if not any([nome, valor, descricao, imagem]):
        cursor.close()
        return jsonify({'error': 'Nenhum campo para atualizar'}), 400

    try:
        # 5. Monta dinamicamente a query de update
        update_fields = []
        update_values = []

        if nome is not None:
            update_fields.append("NOME = ?")
            update_values.append(nome)
        if valor is not None:
            update_fields.append("VALOR = ?")
            update_values.append(valor)
        if descricao is not None:
            update_fields.append("DESCRICAO = ?")
            update_values.append(descricao)

        if update_fields:
            update_values.append(id_servico)
            sql = f"UPDATE SERVICOS SET {', '.join(update_fields)} WHERE ID_SERVICO = ?"
            cursor.execute(sql, update_values)
            con.commit()

        # 6. Salva imagem se enviada
        if imagem:
            # garante que a config exista
            upload_root = app.config.get('UPLOAD_FOLDER')
            if not upload_root:
                cursor.close()
                return jsonify({'error': "Upload não configurado no servidor (UPLOAD_FOLDER)."}), 500

            pasta_servicos = os.path.join(upload_root, "Servicos")
            os.makedirs(pasta_servicos, exist_ok=True)
            # definir nome de arquivo (ex: <id_servico>.jpeg)
            nome_imagem = f"{id_servico}.jpeg"
            caminho_imagem = os.path.join(pasta_servicos, nome_imagem)
            imagem.save(caminho_imagem)

        cursor.close()
        return jsonify({
            'message': 'Serviço atualizado com sucesso',
            'servico': {
                'id_servico': id_servico,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
                'imagem_salva': True if imagem else False
            }
        }), 200

    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({'error': 'Erro ao atualizar serviço', 'details': str(e)}), 500


@app.route('/servico/<int:id_servico>', methods=['DELETE'])
def servico_delete(id_servico):
    # 1. Autenticação
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_token = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()
    # 2. Verifica se o serviço existe e pertence ao usuário do token
    cursor.execute("SELECT ID_USUARIO FROM SERVICOS WHERE ID_SERVICO = ?", (id_servico,))
    serv = cursor.fetchone()
    if not serv:
        cursor.close()
        return jsonify({'error': 'Serviço não encontrado'}), 404
    if serv[0] != id_usuario_token:
        cursor.close()
        return jsonify({'error': 'Permissão negada. Só o dono do serviço pode excluir.'}), 403

    try:
        # 3. Deleta o serviço no banco
        cursor.execute("DELETE FROM SERVICOS WHERE ID_SERVICO = ?", (id_servico,))
        con.commit()
        cursor.close()

        # 4. Remove imagem associada (se existir)
        upload_root = app.config.get('UPLOAD_FOLDER')
        if upload_root:
            caminho_imagem = os.path.join(upload_root, "Servicos", f"{id_servico}.jpeg")
            if os.path.exists(caminho_imagem):
                os.remove(caminho_imagem)

        return jsonify({'message': 'Serviço excluído com sucesso'}), 200
    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({'error': 'Erro ao excluir serviço', 'details': str(e)}), 500


@app.route('/servicoadm', methods=['POST'])
def vincular_servico_adm():
    # Autenticação do usuário
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_autor = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Verifica se o usuário é admin
    cursor = con.cursor()
    cursor.execute("SELECT CARGO FROM USUARIO WHERE ID_USUARIO = ? AND STATUS = 'A'", (id_usuario_autor,))
    resultado = cursor.fetchone()
    if not resultado or str(resultado[0]) != '4':
        cursor.close()
        return jsonify({"error": "Apenas administradores podem criar vínculos de serviço."}), 403

    # Recebe os dados via request.form
    id_usuario_destino = request.form.get('id_usuario')
    nome = request.form.get('nome')
    valor = request.form.get('valor')
    descricao = request.form.get('descricao')
    imagem = request.files.get('imagem')

    # Validação
    if not id_usuario_destino or not nome or not valor:
        cursor.close()
        return jsonify({"error": "Campos obrigatórios: id_usuario, nome e valor"}), 400

    # Verifica se o usuário destino existe, ativo e é fornecedor (cargo=2)
    cursor.execute("SELECT CARGO FROM USUARIO WHERE ID_USUARIO = ? AND STATUS = 'A'", (id_usuario_destino,))
    cargo_usuario_destino = cursor.fetchone()
    if not cargo_usuario_destino:
        cursor.close()
        return jsonify({"error": "Usuário destino não encontrado ou inativo."}), 404

    if str(cargo_usuario_destino[0]) != '2':
        cursor.close()
        return jsonify({"error": "Serviço só pode ser atribuído a usuários fornecedores."}), 400

    try:
        # Insere o serviço usando RETURNING para obter o ID
        sql_servico = """
        INSERT INTO SERVICOS (ID_USUARIO, NOME, VALOR, DESCRICAO)
        VALUES (?, ?, ?, ?)
        RETURNING ID_SERVICO
        """
        cursor.execute(sql_servico, (id_usuario_destino, nome, valor, descricao))

        # Obtém o ID retornado pela cláusula RETURNING
        id_servico_inserido = cursor.fetchone()[0]

        con.commit()
        cursor.close()

        # Salva a imagem após o commit do banco de dados
        if imagem:
            nome_imagem = f"{id_servico_inserido}.jpeg"
            pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Servicos")
            os.makedirs(pasta_destino, exist_ok=True)
            imagem.save(os.path.join(pasta_destino, nome_imagem))

        return jsonify({
            "message": "Serviço criado e vinculado ao fornecedor com sucesso!",
            "servico": {
                'id_servico': id_servico_inserido,
                'id_usuario': id_usuario_destino,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
                'imagem': nome_imagem
            }
        }), 201

    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({"error": "Erro ao criar serviço para usuário", "details": str(e)}), 500


@app.route('/meus-servicos', methods=['GET'])
def meus_servicos():

    # 1. Verifica se há um token no cabeçalho Authorization
    token = request.headers.get('Authorization')
    if not token:
        return jsonify(mensagem='Token ausente'), 401

    # 2. Remove o prefixo 'Bearer ' se existir
    token = remover_bearer(token)

    try:
        # 3. Decodifica o token e pega o ID do usuário LOGADO
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario_logado = payload.get('id_usuario')
        if not id_usuario_logado:
             return jsonify(mensagem='Token inválido (não contém id_usuario)'), 401

    except jwt.ExpiredSignatureError:
        return jsonify(mensagem='Token expirado'), 401
    except jwt.InvalidTokenError:
        return jsonify(mensagem='Token inválido'), 401

    # 4. Conecta ao banco
    cursor = con.cursor()
    
    # 5. A QUERY CORRETA:
    #    - SELECIONA os campos que você quer
    #    - BUSCA por ID_USUARIO
    #    - PASSA o id_usuario_logado (vindo do TOKEN) como parâmetro
    query = """
        SELECT 
            ID_SERVICO, 
            ID_USUARIO, 
            NOME, 
            VALOR, 
            DESCRICAO 
        FROM SERVICOS 
        WHERE ID_USUARIO = ? 
    """
    cursor.execute(query, (id_usuario_logado,))
    
    # 6. USA fetchall() para pegar TODOS os serviços desse usuário
    servicos = cursor.fetchall()
    cursor.close()

    # 7. Transforma os resultados (lista de tuplas) em uma lista de dicionários
    servicos_lista = []
    for servico in servicos:
        servicos_lista.append({
            'id_servico': servico[0],
            'id_usuario': servico[1],
            'nome': servico[2],
            'valor': servico[3],
            'descricao': servico[4]
        })

    # 8. Retorna a lista completa de serviços
    #    (O script que eu te passei na resposta anterior já sabe como ler isso)
    if servicos_lista:
        return jsonify(mensagem='Seus serviços cadastrados', servicos=servicos_lista)
    else:
        # Se não tiver serviços, retorna uma lista vazia
        return jsonify(mensagem='Você ainda não cadastrou nenhum serviço', servicos=[])

