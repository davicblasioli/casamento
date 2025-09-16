from flask import Flask, request, jsonify
from datetime import datetime
from main import app, con  # Mantendo a importação conforme seu setup
import re
import bcrypt
import fdb
import requests

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

@app.route('/usuario', methods=['POST'])
def usuario_post():
    data = request.get_json()

    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento_str = data.get('data_nascimento')
    cargo = data.get('cargo')

    nome_parceiro = None
    if cargo == '1':  # Cliente/Noivo
        nome_parceiro = data.get('nome_parceiro')

    # Converter data_nascimento considerando horário brasileiro (UTC-3)
    # Como a data recebida não tem horário, apenas convertemos formato para date
    try:
        # Supõe formato dd-mm-aaaa e converte para objeto date
        data_nascimento = (
            datetime.strptime(data_nascimento_str, '%d-%m-%Y').date()
            if data_nascimento_str else None
        )
        # Padrão brasileiro para exibir data: dd/mm/aaaa (vai no JSON abaixo)
        data_nascimento_formatada = data_nascimento.strftime('%d/%m/%Y') if data_nascimento else None
    except Exception:
        return jsonify({"error": "Data de nascimento inválida. Use dd-mm-aaaa."}), 400

    # Validar senha forte
    if not validar_senha(senha):
        return jsonify({
            "error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
        }), 400

    senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

    sql_usuario = """
    INSERT INTO USUARIO
    (NOME, EMAIL, SENHA, TELEFONE, DATA_NASCIMENTO, CARGO, NOME_PARCEIRO,
    CATEGORIA, NOME_MARCA, TENTATIVAS_ERRO, STATUS)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    valores_usuario = (
        nome,
        email,
        senha_hash,
        telefone,
        data_nascimento,
        cargo,
        nome_parceiro,
        data.get('categoria'),
        data.get('nome_marca'),
        '0',
        'A'
    )

    cursor = con.cursor()
    try:
        cursor.execute(sql_usuario, valores_usuario)
        con.commit()

        cursor.execute('SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?', (email,))
        id_usuario = cursor.fetchone()
        if not id_usuario:
            cursor.close()
            return jsonify({"error": "Falha ao obter ID do usuário cadastrado."}), 500
        id_usuario = id_usuario[0]

        cep = data.get('cep')
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

            if cargo == '1':
                tipo_endereco = '1'  # residencial
            elif cargo == '2':
                tipo_endereco = '2'  # atendimento
            else:
                tipo_endereco = '0'  # indefinido

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
                'nome_parceiro': nome_parceiro,
                'categoria': data.get('categoria'),
                'nome_marca': data.get('nome_marca'),
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

