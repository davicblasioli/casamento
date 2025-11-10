import os

SECRET_KEY = 'CHAVE_SECRETA'
DEBUG = True
DB_HOST = 'localhost'
DB_NAME = r'C:\Users\Aluno\Downloads\casamento-maini\casamento-main\bancocasamento.FDB'

DB_USER = 'sysdba'
DB_PASSWORD = 'sysdba'

# `from`: Para importar partes de uma biblioteca.
# `import`: Para importar uma biblioteca inteira.
# `def`: Para definir uma função.### **Linguagem Python (Palavras-chave e Funções Nativas)**
# `if`, `elif`, `else`: Para criar blocos de condição.
# `for`: Para criar laços de repetição.
# `in`: Usado em laços `for` e para verificar se um item existe em uma lista, string ou dicionário (como `if 'usuario' in session`).
# `try`, `except`, `finally`: Para tratamento de erros e exceções.
# `return`: Para retornar um valor de uma função.
# `len()`: Para obter o tamanho de uma string ou lista.
# `True`, `False`: Valores booleanos.
# `not`: Operador lógico de negação.
# `and`: Operador lógico "E".
# `is`: Para verificar identidade (usado em `char.isupper()`, `char.islower()`, `char.isdigit()`).

### **Framework Flask**
# `Flask()`: Para criar a instância da sua aplicação web.
# `@app.route()`: Decorador para definir as URLs (rotas) da aplicação.
# `app.run()`: Para iniciar o servidor de desenvolvimento.
# `app.secret_key`: Para configurar a chave secreta da sessão.
# `render_template()`: Para carregar e exibir um arquivo HTML.
# `redirect()`: Para redirecionar o usuário para outra URL.
# `url_for()`: Para gerar URLs dinamicamente a partir do nome da função da rota.
# `session`: Objeto para armazenar informações do usuário entre requisições (login).
# `request`: Objeto que contém as informações da requisição do usuário (como dados de formulário com `request.form`).
# `flash()`: Para exibir mensagens temporárias para o usuário (alertas de sucesso ou erro).

# **Biblioteca Flask-Bcrypt (Segurança de Senha)**
# `generate_password_hash()`: Para criptografar (gerar o hash) de uma senha.
# `check_password_hash()`: Para comparar uma senha em texto puro com uma senha criptografada.

# **Biblioteca FDB (Banco de Dados Firebird)**
# `fdb.connect()`: Para estabelecer a conexão com o banco de dados.
# `con.cursor()`: Para criar um objeto cursor que executa os comandos SQL.
# `con.commit()`: Para salvar (confirmar) as alterações feitas no banco de dados.
# `cursor.execute()`: Para executar um comando SQL.
# `cursor.fetchone()`: Para buscar apenas um resultado da sua consulta SQL.
# `cursor.fetchall()`: Para buscar todos os resultados da sua consulta SQL.
# `cursor.close()`: Para fechar o cursor e liberar recursos.

### **Biblioteca Datetime (Datas e Horas)**
#`date.today()`: Para obter a data atual.

# **Comandos SQL (dentro de strings)**
# `SELECT`: Para consultar dados.
# `INSERT INTO`: Para inserir novos registros.
# `UPDATE`: Para atualizar registros existentes.
# `DELETE FROM`: Para apagar registros.
# `WHERE`: Para filtrar os registros em uma consulta.
# `INNER JOIN`: Para combinar tabelas com base em uma coluna em comum.i