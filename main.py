import functools
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR

group = PairingGroup('SS512')
g = group.random(G1)
H0 = lambda m: group.hash(('0', m), type=G1)
H1 = lambda m: group.hash(('1', m), type=G1)
H2 = lambda m: group.hash(('2', m), type=G1)

# TODO! modify the keywords accordintly
keyword_fields = ["clientID", "year", "month", "document_type", "transaction_type"]

def intListToStr(intList):
    return ''.join([chr(x) for x in intList])


class MPECK:
    def __init__(self, pks, keywords, r, s):
        self.hidden_r = g ** r  # hide the random value r
        self.hidden_pks = list(map(lambda y: y ** s, pks))  # every public key to the power of s
        self.hidden_keywords = list(map(lambda w: (H1(w) ** r) * (H2(w) ** s), keywords))  # for every keyword
        # TODO add check if C is of a given length


class Trapdoor:

    def __init__(self, indexes, keywords, t, sk):
        keywords_extended = []
        for i, keyword_field in enumerate(keyword_fields):
            if i in indexes:
                position_of_i = indexes.index(i)
                keywords_extended.append(keyword_field + "." + keywords[position_of_i])

        self.hidden_t = g ** t  # hide randomness
        self.keywords_h1 = functools.reduce(lambda a, b: a * b,
                                            map(lambda w: H1(w) ** t,
                                                keywords_extended))  # hash1 of the keyword to the t
        self.keywords_h2 = functools.reduce(lambda a, b: a * b, map(lambda w: H2(w) ** (t / sk),
                                                                    keywords_extended))  # hash2 of the keyword to the t/sk
        self.indexes = indexes


class DatabaseEntry:

    def __init__(self, encrypted_document, m_peck):
        self.encrypted_document = encrypted_document
        self.m_peck = m_peck


class ServerOutput:

    def __init__(self, encrypted_document, hidden_pk, hidden_r):
        self.encrypted_document = encrypted_document
        self.hidden_pk = hidden_pk
        self.hidden_r = hidden_r


class Server:

    def __init__(self):
        self.database_entries = []

    def test(self, pk, m_peck: MPECK, trapdoor: Trapdoor):

        # use only the keywords from trapdoor
        m_peck_hidden_keywords_product = 1
        for index in trapdoor.indexes:
            m_peck_hidden_keywords_product *= m_peck.hidden_keywords[index]

        mpeck_Equation = group.pair_prod(trapdoor.hidden_t, m_peck_hidden_keywords_product)

        trapdoor_h1_equation = group.pair_prod(m_peck.hidden_r, trapdoor.keywords_h1)
        for m_peck_hidden_pk in m_peck.hidden_pks:
            trapdoor_h2_equation = group.pair_prod(m_peck_hidden_pk, trapdoor.keywords_h2)
            trapdoor_equation = trapdoor_h1_equation * trapdoor_h2_equation
            if mpeck_Equation == trapdoor_equation:
                return m_peck_hidden_pk
        return None

    def test_on_all_docs(self, pk, trapdoor):
        outputs = []
        for entry in self.database_entries:
            mpeck_hidden_pk = self.test(pk, entry.m_peck, trapdoor)
            if mpeck_hidden_pk is not None:
                output = ServerOutput(entry.encrypted_document, mpeck_hidden_pk, entry.m_peck.hidden_r)
                outputs.append(output)
        return outputs


class Sender:

    def __init__(self, server):
        self.server = server
        self.sk = group.random(ZR)
        self.pk = g ** self.sk
        self.r = group.random(ZR)
        self.s = group.random(ZR)
        self.t = group.random(ZR)

    def encryptFile(self, msg):
        bilinear_map = group.pair_prod(g, g) ** (self.r * self.s)
        hash = H0(bilinear_map)

        left = bytearray(group.serialize(hash))
        right = bytearray(msg, encoding='utf-8')
        result = []
        for i in range(len(right)):
            result.append(left[i] ^ right[i])
        return result

    def decryptFile(self, serverOutput: ServerOutput, sk):
        bilinear_map = group.pair_prod(serverOutput.hidden_r, serverOutput.hidden_pk) ** (1 / sk)
        hash = H0(bilinear_map)
        left = bytearray(group.serialize(hash))
        result = []
        for i in range(len(serverOutput.encrypted_document)):
            result.append(left[i] ^ serverOutput.encrypted_document[i])
        return result

    def store_to_server(self, document, pks, keywords):
        encrypted_document = self.encryptFile(document)
        keywords_extended = []
        for index, keyword_field in enumerate(keyword_fields):
            keywords_extended.append(keyword_field + "." + keywords[index])
        m_peck = MPECK(pks, keywords_extended, self.r, self.s)
        self.server.database_entries.append(DatabaseEntry(encrypted_document, m_peck))


def main():
    server = Server()
    consultant = Sender(server)
    client1 = Sender(server)
    client2 = Sender(server)
    participants = [consultant, client1, client2]

    while True:
        current_person = None

        print('Who are you?')
        for i, participant, in enumerate(participants):
            if i == 0:
                print('0 - Consultant')
            else:
                print(f'{i} - Client{i}')
        current_person = participants[int(input("Please enter a number:\n"))]

        print('What operation would you like to do?')
        print('0 - Upload data')
        print('1 - Query data')
        value = int(input("Please enter a number:\n"))

        if value == 0:
            print('uploading data')
            print('Fill in the information below:')
            array = []
            for i, field, in enumerate(keyword_fields):
                array.append(input(f'Please enter {field}:\n'))

            msg = input("Please type your message:\n")

            print('Who should have access to this? eg. 0 1 2')
            person_list = [consultant.pk, current_person.pk]
            allowed = [int(x) for x in input().split()]
            for a in allowed:
                person_list.append(participants[a].pk)

            current_person.store_to_server(msg, person_list, array)


        else:
            print('Please fill in what keywords you want to search for. Each emtpy field will be ignored.')
            I = []
            Q = []
            for i, field, in enumerate(keyword_fields):
                input_value = input(f'Please enter {field}:\n')
                if input_value != "":
                    I.append(int(i))
                    Q.append(input_value)

            # Generate trapdoor and send to server
            trap = Trapdoor(I, Q, current_person.t, current_person.sk)
            outputs = server.test_on_all_docs(current_person.pk, trap)
            for output in outputs:
                print("=================================================")
                print(intListToStr(current_person.decryptFile(output, current_person.sk)))
                print("=================================================")


if __name__ == "__main__":
    main()
