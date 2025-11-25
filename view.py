from flask import request, jsonify
from datetime import datetime, date
from main import app, con  # Mantendo a importação conforme seu setup
from flask_bcrypt import Bcrypt
import re
import bcrypt
import requests
import jwt
import os
from flask_mail import Mail, Message
from geopy.distance import distance


import requests

import requests


def cep_to_coords(cep):
    try:
        # Consulta endereço pelo CEP na BrasilAPI
        url_cep = f"https://brasilapi.com.br/api/cep/v2/{cep}"
        resposta = requests.get(url_cep, timeout=5)
        if resposta.status_code != 200:
            return None
        dados = resposta.json()

        # Monta endereço completo para geocodificação
        endereco = f"{dados.get('street', '')}, {dados.get('city', '')}, {dados.get('state', '')}, Brasil"

        # Consulta coords pela API Nominatim
        url_geo = "https://nominatim.openstreetmap.org/search"
        params = {
            'q': endereco,
            'format': 'json',
            'limit': 1
        }
        headers = {'User-Agent': 'Mozilla/5.0'}
        resposta_geo = requests.get(url_geo, params=params, headers=headers, timeout=5)
        if resposta_geo.status_code != 200:
            return None
        resultado_geo = resposta_geo.json()
        if not resultado_geo:
            return None

        lat = float(resultado_geo[0]['lat'])
        lon = float(resultado_geo[0]['lon'])
        return (lat, lon)

    except Exception:
        return None


mail = Mail(app)  # Inicialize a extensão Flask-Mail

@app.route('/enviar-email', methods=['POST'])
def enviar_email():
    data = request.get_json()
    nome = data.get('nome')
    email_remetente = data.get('email')
    assunto = data.get('assunto')
    corpo = data.get('corpo')

    # Validação dos campos
    if not nome or not email_remetente or not assunto or not corpo:
        return jsonify({"error": "Nome, email, assunto e corpo do email são obrigatórios."}), 400

    destinatario = "destinatario-fixo@exemplo.com"

    try:
        # Montar email incluindo nome e email do remetente no corpo
        mensagem_completa = f"Mensagem de: {nome} <{email_remetente}>\n\n{corpo}"

        msg = Message(
            subject=assunto,
            recipients=[destinatario],
            body=mensagem_completa,
            sender=email_remetente  # Define o remetente com o email enviado
        )
        mail.send(msg)

        return jsonify({"message": "Email enviado com sucesso!"}), 200
    except Exception as e:
        return jsonify({"error": "Falha ao enviar email.", "details": str(e)}), 500


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
    url = f"https://brasilapi.com.br/api/cep/v2/{cep}"
    try:
        resposta = requests.get(url, timeout=5)
        if resposta.status_code == 200:
            dados = resposta.json()
            if 'erro' in dados:
                return None
            return {
                'bairro': dados.get('neighborhood'),
                'uf': dados.get('state'),
                'cidade': dados.get('city'),
                'logradouro': dados.get('street')
            }
        else:
            return None
    except Exception:
        return None

@app.route('/usuario', methods=['GET'])
def usuario():

    cur = con.cursor()
    cur.execute(f'''
        SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, categoria, nome_marca, status
        FROM usuario
    ''')
    usuarios = cur.fetchall()

    cur.execute('SELECT COUNT(*) FROM usuario')
    total_usuarios = cur.fetchone()[0]

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
    cep = data.get('cep')

    # Verificar campos obrigatórios
    if not nome or not email or not senha:
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    cursor = con.cursor()

    # Verificar email duplicado
    cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Este email já está em uso. Escolha outro email."}), 400

    # Converter data_nascimento
    try:
        data_nascimento = (datetime.strptime(data_nascimento_str, '%d-%m-%Y').date()
                           if data_nascimento_str else None)
        # Impedir data futura!
        if data_nascimento and data_nascimento > date.today():
            cursor.close()
            return jsonify({"error": "Data de nascimento não pode ser futura."}), 400
        data_nascimento_formatada = data_nascimento.strftime('%d/%m/%Y') if data_nascimento else None
    except Exception:
        cursor.close()
        return jsonify({"error": "Data de nascimento inválida. Use dd-mm-aaaa."}), 400

    # Validar senha forte (supondo função validar_senha definida)
    if not validar_senha(senha):
        cursor.close()
        return jsonify({
            "error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
        }), 400

    # Buscar dados do CEP
    bairro = uf = cidade = logradouro = tipo_endereco = None
    if cep:
        dados_cep = buscar_dados_cep(cep)
        if not dados_cep:
            cursor.close()
            return jsonify({"error": "CEP inválido ou não encontrado."}), 400
        bairro = dados_cep['bairro']
        uf = dados_cep['uf']
        cidade = dados_cep['cidade']
        logradouro = dados_cep['logradouro']
        tipo_endereco = '2' if str(cargo) == '2' else '1'  # Comercial se cargo=2, senão residencial

    # Hash da senha
    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

    if str(cargo) == '1':  # Cliente
        categoria = None
        nome_marca = None
    elif str(cargo) == '3':  # Cerimonialista
        categoria = "Cerimonialista"
        nome_marca = None
    else:
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
        0,
        'A'
    )

    try:
        cursor.execute(sql_usuario, valores_usuario)
        con.commit()

        # Buscar ID do usuário inserido
        cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
        id_usuario = cursor.fetchone()
        if not id_usuario:
            cursor.close()
            return jsonify({"error": "Falha ao obter ID do usuário cadastrado."}), 500
        id_usuario = id_usuario[0]

        # Inserir endereço se houver CEP
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
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "data_nascimento": data_nascimento_formatada,
                "cargo": cargo,
                "categoria": categoria,
                "nome_marca": nome_marca,
            },
            "endereco": {
                "cep": cep,
                "uf": uf,
                "cidade": cidade,
                "bairro": bairro,
                "logradouro": logradouro,
                "tipo_endereco": tipo_endereco
            } if cep else None
        })
    except Exception as e:
        cursor.close()
        return jsonify({"error": str(e)}), 500


@app.route('/usuarios/<int:id>', methods=['PUT'])
def usuario_put(id):
    cursor = con.cursor()
    cursor.execute("SELECT ID_USUARIO, CARGO, CATEGORIA FROM USUARIO WHERE ID_USUARIO = ?", (id,))
    usuario_data = cursor.fetchone()
    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário não encontrado'}), 404

    cargo = str(usuario_data[1])
    categoria_antiga = str(usuario_data[2]) if usuario_data[2] is not None else None

    nome = request.form.get('nome')
    email = request.form.get('email')
    telefone = request.form.get('telefone')
    data_nascimento_str = request.form.get('data_nascimento')
    cep = request.form.get('cep')
    categoria_nova = request.form.get('categoria')
    nome_marca = request.form.get('nome_marca')
    ativo = request.form.get('ativo')
    imagem = request.files.get('imagem')

    # Validação mínima
    if not nome or not email:
        cursor.close()
        return jsonify({"error": "Nome e email obrigatórios."}), 400

    cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Este email já está em uso por outro usuário."}), 400

    # Só impede se cargo == '2' (tipo fornecedor/comercialista), e se a categoria realmente está sendo trocada
    if cargo == '2' and categoria_nova and categoria_antiga != categoria_nova:
        cursor.execute("SELECT 1 FROM SERVICOS WHERE ID_USUARIO = ?", (id,))
        tem_servicos = cursor.fetchone()
        if tem_servicos:
            cursor.close()
            return jsonify({"error": "Não é possível alterar a categoria. O usuário já possui serviço cadastrado."}), 403

    # Converter data
    try:
        data_nascimento = (
            datetime.strptime(data_nascimento_str, '%d-%m-%Y').date()
            if data_nascimento_str else None
        )
        # IMPEDIR DATA FUTURA
        if data_nascimento and data_nascimento > date.today():
            cursor.close()
            return jsonify({"error": "Data de nascimento não pode ser futura."}), 400
    except Exception:
        cursor.close()
        return jsonify({"error": "Data de nascimento inválida. Use dd-mm-aaaa."}), 400

    # Atualiza CEP e demais dados do endereço
    if cep:
        info_cep = buscar_dados_cep(cep)
        # Ajuste para garantir valores strings não None na atualização do endereço
        if info_cep:
            bairro = info_cep.get('bairro') or ''
            cidade = info_cep.get('cidade') or ''
            uf = info_cep.get('uf') or ''
            logradouro = info_cep.get('logradouro') or ''

            cursor.execute(
                """
                UPDATE ENDERECO
                SET CEP = ?, BAIRRO = ?, CIDADE = ?, UF = ?, LOGRADOURO = ?
                WHERE ID_USUARIO = ?
                """,
                (cep, bairro, cidade, uf, logradouro, id)
            )

        else:
            # Se não conseguir buscar o CEP, atualiza só o CEP
            cursor.execute('UPDATE ENDERECO SET CEP = ? WHERE ID_USUARIO = ?', (cep, id))

    # Buscar o status atual do usuário antes da edição
    cursor.execute("SELECT STATUS FROM USUARIO WHERE ID_USUARIO = ?", (id,))
    status_atual = cursor.fetchone()
    status_atual = status_atual[0] if status_atual else "A"  # Padrão ativo

    # Converter status apenas se veio valor, senão mantém o atual
    if ativo is not None:
        status_db = "A" if ativo == "1" else "I"
    else:
        status_db = status_atual

    # Atualiza usuário
    update_fields = ["NOME = ?", "EMAIL = ?", "TELEFONE = ?", "DATA_NASCIMENTO = ?", "STATUS = ?"]
    update_values = [nome, email, telefone, data_nascimento, status_db]

    if cargo == '2':
        update_fields += ["CATEGORIA = ?", "NOME_MARCA = ?"]
        update_values += [categoria_nova, nome_marca]

    update_values.append(id)
    sql_update = f"UPDATE USUARIO SET {', '.join(update_fields)} WHERE ID_USUARIO = ?"
    cursor.execute(sql_update, update_values)
    con.commit()
    cursor.close()

    # Salvar imagem
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
            'status': status_db,
            'categoria': categoria_nova if cargo == '2' else None,
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
        return jsonify({"error": "O usuário foi inativado."}), 403

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
        # Inativa o usuário e zera tentativas_erro
        cursor.execute("UPDATE USUARIO SET STATUS = 'I', TENTATIVAS_ERRO = 0 WHERE ID_USUARIO = ?", (id_usuario,))
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


@app.route('/servicoid/<int:id_servico>', methods=['GET'])
def servico_por_id(id_servico):
    cursor = con.cursor()
    cursor.execute('''
        SELECT id_servico, id_usuario, nome, valor, descricao, categoria
        FROM servicos
        WHERE id_servico = ?
    ''', (id_servico,))
    servico = cursor.fetchone()
    cursor.close()

    if not servico:
        return jsonify({"error": "Serviço não encontrado."}), 404

    servico_dic = {
        'id_servico': servico[0],
        'id_usuario': servico[1],
        'nome': servico[2],
        'valor': servico[3],
        'descricao': servico[4],
        'categoria': servico[5]
    }

    return jsonify(
        mensagem='Serviço encontrado',
        servico=servico_dic
    )


@app.route('/servico', methods=['GET'])
def servico_get():
    # 1. Autenticação - pega o token do header
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

    cursor = con.cursor()
    # Busca o CEP do cliente logado
    cursor.execute("SELECT CEP FROM ENDERECO WHERE ID_USUARIO = ?", (id_usuario,))
    endereco_cliente = cursor.fetchone()
    if not endereco_cliente or not endereco_cliente[0]:
        cursor.close()
        return jsonify({'mensagem': 'CEP do cliente não encontrado'}), 404

    cep_cliente = endereco_cliente[0]

    # Converte CEP do cliente em coordenadas
    coords_cliente = cep_to_coords(cep_cliente)
    if not coords_cliente:
        cursor.close()
        return jsonify({'mensagem': 'Não foi possível obter coordenadas do CEP do cliente'}), 400

    lat_cliente, lon_cliente = coords_cliente

    # Busca os serviços com detalhes do fornecedor e endereço
    cursor.execute("""
        SELECT s.ID_SERVICO, s.ID_USUARIO, s.NOME, s.VALOR, s.DESCRICAO, s.CATEGORIA, 
               e.CEP, e.LOGRADOURO, e.BAIRRO, e.CIDADE, e.UF, u.EMAIL
        FROM SERVICOS s
        JOIN ENDERECO e ON s.ID_USUARIO = e.ID_USUARIO
        JOIN USUARIO u ON s.ID_USUARIO = u.ID_USUARIO
    """)
    servicos = cursor.fetchall()
    cursor.close()

    if not servicos:
        return jsonify(mensagem='Nenhum serviço encontrado')

    lista_servicos = []

    for servico in servicos:
        (id_servico, id_usuario_fornecedor, nome, valor, descricao, categoria,
         cep_fornecedor, logradouro, bairro, cidade, uf, email) = servico

        coords_fornecedor = cep_to_coords(cep_fornecedor)
        if not coords_fornecedor:
            continue  # Ignora fornecedores sem coordenadas válidas

        lat_fornecedor, lon_fornecedor = coords_fornecedor
        dist = distance((lat_cliente, lon_cliente), (lat_fornecedor, lon_fornecedor)).km
        local_fornecedor = f"{logradouro}, {bairro}, {cidade} - {uf}"

        lista_servicos.append({
            'id_servico': id_servico,
            'id_usuario': id_usuario_fornecedor,
            'nome': nome,
            'valor': valor,
            'descricao': descricao,
            'categoria': categoria,
            'cep_fornecedor': cep_fornecedor,
            'local_fornecedor': local_fornecedor,
            'email_fornecedor': email,
            'distancia_km': dist
        })

    # Ordena a lista pelo campo 'distancia_km' (do mais próximo para o mais distante)
    lista_servicos.sort(key=lambda x: x['distancia_km'])

    return jsonify(mensagem='Lista de serviços ordenada por proximidade', servicos=lista_servicos)


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

    # 3. Receber dados do form-data (nome, valor, descricao, categoria, imagem)
    nome = request.form.get('nome')
    valor = request.form.get('valor')
    descricao = request.form.get('descricao')
    categoria = request.form.get('categoria')
    imagem = request.files.get('imagem')

    # 4. Validação dos campos obrigatórios
    if not nome or not valor or not categoria:
        cursor.close()
        return jsonify({
            "error": "Campos obrigatórios: nome, valor e categoria"
        }), 400

    try:
        # Passo 1: Inserir o novo serviço com categoria
        sql_servico = """
            INSERT INTO SERVICOS (ID_USUARIO, NOME, VALOR, DESCRICAO, CATEGORIA)
            VALUES (?, ?, ?, ?, ?)
        """
        cursor.execute(sql_servico, (id_usuario, nome, valor, descricao, categoria))
        con.commit()

        # Passo 2: Selecionar o ID do serviço recém inserido
        sql_select = """
            SELECT ID_SERVICO
            FROM SERVICOS
            WHERE ID_USUARIO = ? AND NOME = ? AND VALOR = ? AND DESCRICAO = ? AND CATEGORIA = ?
            ORDER BY ID_SERVICO DESC
            FETCH FIRST 1 ROWS ONLY
        """

        cursor.execute(sql_select, (id_usuario, nome, valor, descricao, categoria))
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

        return jsonify({
            "message": "Serviço cadastrado com sucesso!",
            "servico": {
                'id_usuario': id_usuario,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
                'categoria': categoria,
                'imagem_salva': f"/static/uploads/Servico/{id_servico}.jpeg" if imagem else None,
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

    # 3. Recebe dados: aceitar tanto JSON quanto form-data (para imagem)
    nome = None
    valor = None
    descricao = None
    categoria = None
    imagem = None

    if request.content_type and 'multipart/form-data' in request.content_type:
        nome = request.form.get('nome')
        valor = request.form.get('valor')
        descricao = request.form.get('descricao')
        categoria = request.form.get('categoria')
        imagem = request.files.get('imagem')
    else:
        data = request.get_json(silent=True)
        if not data:
            cursor.close()
            return jsonify({'error': 'Nenhum dado enviado'}), 400
        nome = data.get('nome')
        valor = data.get('valor')
        descricao = data.get('descricao')
        categoria = data.get('categoria')
        # imagem só pode via multipart/form-data

    # 4. Validação mínima: pelo menos um campo para atualizar
    if not any([nome, valor, descricao, categoria, imagem]):
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
        if categoria is not None:
            update_fields.append("CATEGORIA = ?")
            update_values.append(categoria)

        if update_fields:
            update_values.append(id_servico)
            sql = f"UPDATE SERVICOS SET {', '.join(update_fields)} WHERE ID_SERVICO = ?"
            cursor.execute(sql, update_values)
            con.commit()

        # 6. Salva imagem se enviada
        if imagem:
            upload_root = app.config.get('UPLOAD_FOLDER')
            if not upload_root:
                cursor.close()
                return jsonify({'error': "Upload não configurado no servidor (UPLOAD_FOLDER)."}), 500

            pasta_servicos = os.path.join(upload_root, "Servicos")
            os.makedirs(pasta_servicos, exist_ok=True)
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
                'categoria': categoria,
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

    # 3. Verifica se serviço está vinculado a alguma RELACAO
    cursor.execute("SELECT 1 FROM RELACAO WHERE ID_SERVICO = ?", (id_servico,))
    relacao_existente = cursor.fetchone()
    if relacao_existente:
        cursor.close()
        return jsonify({'error': 'Serviço já está contratado em uma festa. Não pode ser excluído.'}), 403

    try:
        # 4. Deleta o serviço no banco
        cursor.execute("DELETE FROM SERVICOS WHERE ID_SERVICO = ?", (id_servico,))
        con.commit()
        cursor.close()

        # 5. Remove imagem associada (se existir)
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
    categoria = request.form.get('categoria')
    imagem = request.files.get('imagem')

    # Validação
    if not id_usuario_destino or not nome or not valor or not categoria:
        cursor.close()
        return jsonify({"error": "Campos obrigatórios: id_usuario, nome, valor e categoria"}), 400

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
        # Insere o serviço incluindo categoria usando RETURNING para obter o ID
        sql_servico = """
        INSERT INTO SERVICOS (ID_USUARIO, NOME, VALOR, DESCRICAO, CATEGORIA)
        VALUES (?, ?, ?, ?, ?)
        RETURNING ID_SERVICO
        """
        cursor.execute(sql_servico, (id_usuario_destino, nome, valor, descricao, categoria))

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
        else:
            nome_imagem = None

        return jsonify({
            "message": "Serviço criado e vinculado ao fornecedor com sucesso!",
            "servico": {
                'id_servico': id_servico_inserido,
                'id_usuario': id_usuario_destino,
                'nome': nome,
                'valor': valor,
                'descricao': descricao,
                'categoria': categoria,
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

    # 5. Consulta incluindo o campo categoria
    query = """
        SELECT 
            ID_SERVICO, 
            ID_USUARIO, 
            NOME, 
            VALOR, 
            DESCRICAO,
            CATEGORIA
        FROM SERVICOS 
        WHERE ID_USUARIO = ? 
    """
    cursor.execute(query, (id_usuario_logado,))

    # 6. Obter todos os serviços desse usuário
    servicos = cursor.fetchall()
    cursor.close()

    # 7. Transformar em lista de dicionários com categoria
    servicos_lista = []
    for servico in servicos:
        servicos_lista.append({
            'id_servico': servico[0],
            'id_usuario': servico[1],
            'nome': servico[2],
            'valor': servico[3],
            'descricao': servico[4],
            'categoria': servico[5]
        })

    # 8. Retornar lista de serviços
    if servicos_lista:
        return jsonify(mensagem='Seus serviços cadastrados', servicos=servicos_lista)
    else:
        return jsonify(mensagem='Você ainda não cadastrou nenhum serviço', servicos=[])


@app.route('/admin/cadastrar-usuario', methods=['POST'])
def admin_cadastrar_usuario():
    # 1. Autenticação e validação do token JWT
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_admin = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # 2. Verificar se o usuário autenticado é ADM
    cursor = con.cursor()
    cursor.execute("SELECT CARGO FROM USUARIO WHERE ID_USUARIO = ? AND STATUS = 'A'", (id_admin,))
    resultado = cursor.fetchone()
    if not resultado:
        cursor.close()
        return jsonify({"error": "Usuário não encontrado ou inativo."}), 403

    cargo_adm = resultado[0]
    if str(cargo_adm) != '4':
        cursor.close()
        return jsonify({"error": "Apenas administradores podem cadastrar usuários."}), 403

    # 3. Receber dados JSON do novo usuário
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento_str = data.get('data_nascimento')
    cargo = data.get('cargo')
    cep = data.get('cep')

    # Valida campos obrigatórios
    if not nome or not email or not senha:
        cursor.close()
        return jsonify({"error": "Nome, email e senha são obrigatórios."}), 400

    if not data_nascimento_str:
        cursor.close()
        return jsonify({"error": "Data de nascimento é obrigatório."}), 400

    # Verificar email duplicado
    cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?", (email,))
    usuario_existente = cursor.fetchone()
    if usuario_existente:
        cursor.close()
        return jsonify({"error": "Este email já está em uso."}), 400

    # Converter data nascimento
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

    # Validar CEP
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

    # Hash da senha
    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

    # Categoria e nome da marca para fornecedores e outros
    if cargo == '1':  # Cliente
        categoria = None
        nome_marca = None
    elif cargo == '3':
        categoria = 'Cerimonialista'
        nome_marca = None
    else:
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


# ROTA PARA PESQUISAR USUÁRIOS (case-insensitive)
@app.route('/pesquisar/usuarios', methods=['GET'])
def pesquisar_usuarios():
    termo = request.args.get('q', '').strip()
    if not termo:
        return jsonify({"error": "Termo de busca necessário (parâmetro 'q')."}), 400

    cursor = con.cursor()
    consulta = """
        SELECT ID_USUARIO, NOME, EMAIL, CARGO
        FROM USUARIO
        WHERE UPPER(NOME) LIKE ? OR UPPER(EMAIL) LIKE ?
        ORDER BY NOME
        ROWS 1 TO 50
    """
    like = f"%{termo}%".upper()
    cursor.execute(consulta, (like, like))
    resultados = cursor.fetchall()
    cursor.close()

    lista = [
        {
            'id_usuario': u[0],
            'nome': u[1],
            'email': u[2],
            'cargo': u[3],
        }
        for u in resultados
    ]
    return jsonify({'usuarios': lista})


# ROTA PARA PESQUISAR SERVIÇOS (case-insensitive)
@app.route('/pesquisar/servicos', methods=['GET'])
def pesquisar_servicos():
    termo = request.args.get('q', '').strip()
    if not termo:
        return jsonify({"error": "Termo de busca necessário (parâmetro 'q')."}), 400

    cursor = con.cursor()
    consulta = """
        SELECT 
            S.ID_SERVICO, 
            S.NOME, 
            S.VALOR, 
            S.DESCRICAO, 
            S.CATEGORIA,
            U.NOME AS NOME_FORNECEDOR
        FROM SERVICOS S
        JOIN USUARIO U ON S.ID_USUARIO = U.ID_USUARIO
        WHERE 
            UPPER(S.NOME) LIKE ? 
            OR UPPER(S.DESCRICAO) LIKE ? 
            OR UPPER(S.CATEGORIA) LIKE ?
            OR UPPER(U.NOME) LIKE ?
        ORDER BY S.NOME
        ROWS 1 TO 50
    """
    like = f"%{termo.upper()}%"
    cursor.execute(consulta, (like, like, like, like))
    resultados = cursor.fetchall()
    cursor.close()

    lista = [
        {
            'id_servico': s[0],
            'nome_servico': s[1],
            'valor': s[2],
            'descricao': s[3],
            'categoria': s[4],
            'nome_fornecedor': s[5],
        }
        for s in resultados
    ]
    return jsonify({'servicos': lista})


@app.route('/festa', methods=['POST'])
def criar_festa():
    # 1. Autenticação do usuário via JWT
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

    # 2. Verificação do cargo do usuário
    cursor = con.cursor()
    cursor.execute("SELECT CARGO FROM USUARIO WHERE ID_USUARIO = ? AND STATUS = 'A'", (id_usuario,))
    resultado = cursor.fetchone()
    if not resultado:
        cursor.close()
        return jsonify({"error": "Usuário não encontrado ou inativo."}), 403

    cargo = str(resultado[0])
    if cargo not in ('1', '4'):
        cursor.close()
        return jsonify({"error": "Apenas noivos e administradores podem criar festas."}), 403

    # 3. Receber dados da festa via JSON
    data = request.get_json()
    nome = data.get('nome')
    categoria = data.get('categoria')
    valor = data.get('valor')
    convidados = data.get('convidados')
    data_festa = data.get('data_festa')
    descricao = data.get('descricao')

    if not nome or not categoria or not valor or not convidados or not data_festa:
        cursor.close()
        return jsonify({"error": "Campos obrigatórios: nome, categoria, valor, convidados, data_festa"}), 400

    # 4. Validação: só aceita datas futuras
    try:
        data_festa_dt = datetime.strptime(data_festa, "%Y-%m-%d")
    except ValueError:
        cursor.close()
        return jsonify({"error": "Formato de data inválido, use AAAA-MM-DD"}), 400

    data_atual = datetime.now().date()
    if data_festa_dt.date() <= data_atual:
        cursor.close()
        return jsonify({"error": "A data da festa deve ser futura"}), 400

    try:
        sql = """
            INSERT INTO FESTA (NOME, CATEGORIA, VALOR, CONVIDADOS, DATA_FESTA, DESCRICAO, ID_USUARIO)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING ID_FESTA
        """
        cursor.execute(sql, (nome, categoria, valor, convidados, data_festa, descricao, id_usuario))
        id_festa = cursor.fetchone()[0]
        con.commit()
        cursor.close()

        return jsonify({
            "message": "Festa criada com sucesso!",
            "festa": {
                'id_festa': id_festa,
                'nome': nome,
                'categoria': categoria,
                'valor': valor,
                'convidados': convidados,
                'data_festa': data_festa,
                'descricao': descricao,
                'id_usuario': id_usuario
            }
        }), 201

    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({'error': 'Erro ao criar festa', 'details': str(e)}), 500


@app.route('/festa/<int:id_festa>', methods=['PUT'])
def editar_festa(id_festa):
    # 1. Autenticação
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

    cursor = con.cursor()

    # 2. Verifica se a festa existe e pertence ao usuário
    cursor.execute("SELECT ID_USUARIO FROM FESTA WHERE ID_FESTA = ?", (id_festa,))
    festa_existente = cursor.fetchone()
    if not festa_existente:
        cursor.close()
        return jsonify({"error": "Festa não encontrada."}), 404

    # Verifica se usuário é o dono da festa
    if festa_existente[0] != id_usuario:
        # Se não for dono, verifica se é cerimonialista com serviço relacionado à festa
        cursor.execute("""
            SELECT 1 FROM RELACOES r
            JOIN SERVICOS s ON r.ID_SERVICO = s.ID_SERVICO
            WHERE r.ID_FESTA = ? AND s.ID_USUARIO = ?
        """, (id_festa, id_usuario))
        relacao = cursor.fetchone()
        if not relacao:
            cursor.close()
            return jsonify({"error": "Permissão negada. Só o dono ou cerimonialista relacionado pode editar esta festa."}), 403

    # 3. Recebe dados para atualização (JSON)
    data = request.get_json()
    nome = data.get('nome')
    categoria = data.get('categoria')
    valor = data.get('valor')
    convidados = data.get('convidados')
    data_festa = data.get('data_festa')
    descricao = data.get('descricao')

    # 4. Validação: pelo menos um campo deve ser enviado para atualizar
    if not any([nome, categoria, valor, convidados, data_festa, descricao]):
        cursor.close()
        return jsonify({"error": "Nenhum campo para atualizar foi enviado."}), 400

    # 5. Se data_festa for enviada, valida se é uma data futura
    if data_festa:
        try:
            data_festa_dt = datetime.strptime(data_festa, "%Y-%m-%d")
        except ValueError:
            cursor.close()
            return jsonify({"error": "Formato de data inválido, use AAAA-MM-DD"}), 400

        data_atual = datetime.now().date()
        if data_festa_dt.date() <= data_atual:
            cursor.close()
            return jsonify({"error": "A data da festa deve ser futura"}), 400

    try:
        # 6. Monta dinamicamente a query de update
        update_fields = []
        update_values = []

        if nome is not None:
            update_fields.append("NOME = ?")
            update_values.append(nome)
        if categoria is not None:
            update_fields.append("CATEGORIA = ?")
            update_values.append(categoria)
        if valor is not None:
            update_fields.append("VALOR = ?")
            update_values.append(valor)
        if convidados is not None:
            update_fields.append("CONVIDADOS = ?")
            update_values.append(convidados)
        if data_festa is not None:
            update_fields.append("DATA_FESTA = ?")
            update_values.append(data_festa)
        if descricao is not None:
            update_fields.append("DESCRICAO = ?")
            update_values.append(descricao)

        if update_fields:
            update_values.append(id_festa)
            sql = f"UPDATE FESTA SET {', '.join(update_fields)} WHERE ID_FESTA = ?"
            cursor.execute(sql, update_values)
            con.commit()

        # Buscar os dados atualizados da festa para retornar
        cursor.execute(
            "SELECT ID_FESTA, NOME, CATEGORIA, VALOR, CONVIDADOS, DATA_FESTA, DESCRICAO, ID_USUARIO FROM FESTA WHERE ID_FESTA = ?",
            (id_festa,))
        festa_atualizada = cursor.fetchone()
        cursor.close()

        festa_dict = {
            'id_festa': festa_atualizada[0],
            'nome': festa_atualizada[1],
            'categoria': festa_atualizada[2],
            'valor': festa_atualizada[3],
            'convidados': festa_atualizada[4],
            'data_festa': festa_atualizada[5],
            'descricao': festa_atualizada[6],
            'id_usuario': festa_atualizada[7]
        }

        return jsonify({
            "message": "Festa atualizada com sucesso!",
            "festa": festa_dict
        }), 200


    except Exception as e:
        con.rollback()
        if 'cursor' in locals():
            cursor.close()
        return jsonify({"error": "Erro ao atualizar festa", "details": str(e)}), 500


@app.route('/festas/usuario/<int:id_usuario>', methods=['GET'])
def listar_festas_usuario(id_usuario):
    cursor = con.cursor()
    cursor.execute(
        '''
        SELECT ID_FESTA, NOME, CATEGORIA, VALOR, CONVIDADOS, DATA_FESTA, DESCRICAO, ID_USUARIO
        FROM FESTA
        WHERE ID_USUARIO = ?
        ORDER BY DATA_FESTA
        ''',
        (id_usuario,)
    )
    festas = cursor.fetchall()
    cursor.close()

    festas_lista = []
    for festa in festas:
        # Tenta formatar DATA_FESTA se for datetime ou string
        data_raw = festa[5]
        try:
            # Se vier como datetime.date ou datetime.datetime
            if isinstance(data_raw, (datetime,)):
                data_formatada = data_raw.strftime('%d/%m/%Y')
            else:
                # Se vier como string no formato 'YYYY-MM-DD'
                data_formatada = datetime.strptime(str(data_raw), '%Y-%m-%d').strftime('%d/%m/%Y')
        except Exception:
            data_formatada = str(data_raw)  # Em último caso, retorna como veio

        festas_lista.append({
            'id_festa': festa[0],
            'nome': festa[1],
            'categoria': festa[2],
            'valor': festa[3],
            'convidados': festa[4],
            'data_festa': data_formatada,
            'descricao': festa[6],
            'id_usuario': festa[7]
        })

    return jsonify({
        'mensagem': f'{len(festas_lista)} festa(s) encontrada(s) para o usuário.',
        'festas': festas_lista
    })


@app.route('/relacao/<int:id_relacao>', methods=['DELETE'])
def deletar_relacao(id_relacao):
    # 1. Autenticação
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

    cursor = con.cursor()

    # 2. Verifica se a relação existe e busca id_festa e id_servico vínculados
    cursor.execute("SELECT ID_FESTA, ID_SERVICO FROM RELACAO WHERE ID_RELACAO = ?", (id_relacao,))
    relacao = cursor.fetchone()
    if not relacao:
        cursor.close()
        return jsonify({'error': 'Relação não encontrada.'}), 404
    id_festa, id_servico_relacao = relacao

    # 3. Verifica se o usuário possui um serviço vinculado a esta festa (ou seja, é cerimonialista nesta festa)
    cursor.execute("""
        SELECT 1 FROM RELACAO r
        JOIN SERVICOS s ON r.ID_SERVICO = s.ID_SERVICO
        WHERE r.ID_FESTA = ? AND s.ID_USUARIO = ?
    """, (id_festa, id_usuario))
    cerimonialista_na_festa = cursor.fetchone()

    if not cerimonialista_na_festa:
        cursor.close()
        return jsonify({'error': 'Permissão negada. Você não é cerimonialista dessa festa.'}), 403

    # 4. Impede dele excluir sua própria relação
    cursor.execute("SELECT ID_SERVICO FROM SERVICOS WHERE ID_USUARIO = ?", (id_usuario,))
    servicos_usuario = cursor.fetchall()
    servicos_usuario_ids = [s[0] for s in servicos_usuario]
    if id_servico_relacao in servicos_usuario_ids:
        cursor.close()
        return jsonify({'error': 'Você não pode excluir sua própria relação.'}), 403

    # 5. Se passou nas verificações, exclui relação
    cursor.execute("DELETE FROM RELACAO WHERE ID_RELACAO = ?", (id_relacao,))
    con.commit()
    cursor.close()

    return jsonify({'message': 'Relação (contrato) cancelada com sucesso.'}), 200


@app.route('/relacao', methods=['POST'])
def criar_relacao():
    # 1. Autenticação
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

    data = request.get_json()
    id_servico = data.get('id_servico')
    id_festa = data.get('id_festa')

    if not id_servico or not id_festa:
        return jsonify({'error': 'É necessário informar id_servico e id_festa.'}), 400

    cursor = con.cursor()

    # Verifica se o usuário logado é cerimonialista na festa (possui serviço relacionado à festa)
    cursor.execute("""
        SELECT 1 FROM RELACAO r
        JOIN SERVICOS s ON r.ID_SERVICO = s.ID_SERVICO
        WHERE r.ID_FESTA = ? AND s.ID_USUARIO = ?
    """, (id_festa, id_usuario))
    relacao_cerimonialista = cursor.fetchone()
    if not relacao_cerimonialista:
        cursor.close()
        return jsonify({'error': 'Permissão negada. Você não é cerimonialista dessa festa.'}), 403

    # Verifica se já existe uma relação igual
    cursor.execute("SELECT 1 FROM RELACAO WHERE ID_SERVICO = ? AND ID_FESTA = ?", (id_servico, id_festa))
    if cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Esta relação já existe!'}), 409

    # Confirma se o serviço existe e busca o dono do serviço
    cursor.execute("SELECT ID_USUARIO FROM SERVICOS WHERE ID_SERVICO = ?", (id_servico,))
    servico_data = cursor.fetchone()
    if not servico_data:
        cursor.close()
        return jsonify({'error': 'Serviço não encontrado.'}), 404

    id_usuario_servico = servico_data[0]

    # Busca nome do usuário dono do serviço
    cursor.execute("SELECT NOME FROM USUARIO WHERE ID_USUARIO = ?", (id_usuario_servico,))
    usuario_data = cursor.fetchone()
    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário dono do serviço não encontrado.'}), 404

    nome_usuario = usuario_data[0]

    # Confirma se a festa existe
    cursor.execute("SELECT 1 FROM FESTA WHERE ID_FESTA = ?", (id_festa,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Festa não encontrada.'}), 404

    # Cria a relação
    cursor.execute("INSERT INTO RELACAO (ID_SERVICO, ID_FESTA) VALUES (?, ?)", (id_servico, id_festa))
    con.commit()
    cursor.close()

    return jsonify({
        "message": "Relação criada com sucesso.",
        "relacao": {
            "id_servico": id_servico,
            "id_festa": id_festa,
            "nome_usuario_servico": nome_usuario
        }
    }), 201


@app.route('/relacao/festa/<int:id_festa>', methods=['GET'])
def listar_relacoes_por_festa(id_festa):
    cursor = con.cursor()
    sql = """
        SELECT
            R.ID_RELACAO,
            S.ID_SERVICO, S.NOME, S.VALOR, S.DESCRICAO, S.CATEGORIA,
            U.ID_USUARIO, U.NOME, U.EMAIL, U.TELEFONE, U.CATEGORIA
        FROM RELACAO R
        JOIN SERVICOS S ON R.ID_SERVICO = S.ID_SERVICO
        JOIN USUARIO U ON S.ID_USUARIO = U.ID_USUARIO
        WHERE R.ID_FESTA = ?
    """
    cursor.execute(sql, (id_festa,))
    resultados = cursor.fetchall()
    cursor.close()

    relacoes = []
    for row in resultados:
        relacao = {
            "id_relacao": row[0],
            "servico": {
                "id_servico": row[1],
                "nome": row[2],
                "valor": row[3],
                "descricao": row[4],
                "categoria": row[5]
            },
            "usuario": {
                "id_usuario": row[6],
                "nome": row[7],
                "email": row[8],
                "telefone": row[9],
                "categoria": row[10]
            }
        }
        relacoes.append(relacao)

    return jsonify(relacoes)


@app.route('/fornecedor/<int:id_usuario>/festas', methods=['GET'])
def festas_contratadas_para_fornecedor(id_usuario):
    cursor = con.cursor()
    cursor.execute("SELECT ID_SERVICO, NOME, CATEGORIA, VALOR, DESCRICAO FROM SERVICOS WHERE ID_USUARIO = ?", (id_usuario,))
    servicos = cursor.fetchall()
    servicos_ids = [s[0] for s in servicos]
    servicos_map = {s[0]: {"id_servico": s[0], "nome": s[1], "categoria": s[2], "valor": s[3], "descricao": s[4]} for s in servicos}

    festas = []
    if servicos_ids:
        format_strings = ','.join(['?'] * len(servicos_ids))
        cursor.execute(f"""
            SELECT R.ID_RELACAO, R.ID_SERVICO, F.ID_FESTA, F.NOME, F.CATEGORIA, F.VALOR, F.CONVIDADOS, F.DATA_FESTA, F.DESCRICAO
            FROM RELACAO R
            JOIN FESTA F ON R.ID_FESTA = F.ID_FESTA
            WHERE R.ID_SERVICO IN ({format_strings})
        """, tuple(servicos_ids))
        resultados = cursor.fetchall()

        festas_map = {}
        for relacao in resultados:
            id_relacao, id_servico, id_festa, nome, categoria, valor, convidados, data_festa, descricao = relacao

            # --- FORMATAÇÃO DA DATA ---
            # Se data_festa vier como string, converter para objeto datetime
            if isinstance(data_festa, str):
                try:
                    data_obj = datetime.strptime(data_festa[:10], "%Y-%m-%d")
                except Exception:
                    data_obj = None
            else:
                data_obj = data_festa

            data_formatada = data_obj.strftime("%d/%m/%Y") if data_obj else data_festa

            if id_festa not in festas_map:
                festas_map[id_festa] = {
                    "id_festa": id_festa,
                    "nome": nome,
                    "categoria": categoria,
                    "valor": valor,
                    "convidados": convidados,
                    "data_festa": data_formatada,
                    "descricao": descricao,
                    "servicos_contratados": []
                }
            festas_map[id_festa]["servicos_contratados"].append(servicos_map[id_servico])

        festas = list(festas_map.values())

    cursor.close()
    return jsonify(festas)


@app.route('/festa/<int:id_festa>', methods=['DELETE'])
def excluir_festa(id_festa):
    cursor = con.cursor()
    # Verifica se a festa existe
    cursor.execute("SELECT 1 FROM FESTA WHERE ID_FESTA = ?", (id_festa,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Festa não encontrada.'}), 404

    try:
        # Exclui todas as relações da festa
        cursor.execute("DELETE FROM RELACAO WHERE ID_FESTA = ?", (id_festa,))
        # Exclui a festa
        cursor.execute("DELETE FROM FESTA WHERE ID_FESTA = ?", (id_festa,))
        con.commit()
        cursor.close()
        return jsonify({'message': 'Festa e todas as relações vinculadas excluídas com sucesso.'}), 200
    except Exception as e:
        con.rollback()
        cursor.close()
        return jsonify({'error': f'Erro ao excluir festa: {str(e)}'}), 500
