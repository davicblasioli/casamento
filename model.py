class Usuario:
    def __init__(self, id_usuario=None, nome=None, email=None, telefone=None, data_nascimento=None,
                 senha=None, cargo=None, nome_parceiro=None, data_casamento=None,
                 cep_residencial=None, cep_atendimento=None, categoria=None,
                 nome_marca=None, tentativas_erro=None, status=None):
        self.id_usuario = id_usuario
        self.nome = nome
        self.email = email
        self.telefone = telefone
        self.data_nascimento = data_nascimento
        self.senha = senha
        self.cargo = cargo
        self.nome_parceiro = nome_parceiro
        self.data_casamento = data_casamento
        self.cep_residencial = cep_residencial
        self.cep_atendimento = cep_atendimento
        self.categoria = categoria
        self.nome_marca = nome_marca
        self.tentativas_erro = tentativas_erro
        self.status = status
