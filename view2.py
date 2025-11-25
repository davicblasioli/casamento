@app.route('/servico', methods=['GET'])
def servico_get():
    cursor = con.cursor()
    cursor.execute(
        "SELECT ID_SERVICO, ID_USUARIO, NOME, VALOR, DESCRICAO, CATEGORIA FROM SERVICOS"
    )
    servicos = cursor.fetchall()
    cursor.close()

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

    if servicos_lista:
        return jsonify(mensagem='Lista de serviços cadastrados', servicos=servicos_lista)
    else:
        return jsonify(mensagem='Nenhum serviço encontrado')
