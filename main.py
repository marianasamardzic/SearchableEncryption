import functools

from charm.toolbox.pairinggroup import PairingGroup, G1, ZR

# def setup(): #this is currently just copied, make our own.
group = PairingGroup('SS512')  # could maybe throw the security parameter in here
g = group.random(G1)
H0 = lambda m: group.hash(('0', m), type=G1)
H1 = lambda m: group.hash(('1', m), type=G1)
H2 = lambda m: group.hash(('2', m), type=G1)


class MPECK:
    def __init__(self, pks, keywords, r, s):
        self.hidden_r = g ** r  # hide the random value r
        self.hidden_pks = map(lambda y: y ** s, pks)  # every public key to the power of s
        self.hidden_keywords = list(map(lambda w: (H1(w) ** r) * (H2(w) ** s), keywords))  # for every keyword
        # TODO add check if C is of a given length


class Trapdoor:

    def __init__(self, indexes, keywords, t, sk):
        self.hidden_t = g ** t  # hide randomness
        self.keywords_h1 = functools.reduce(lambda a, b: a * b,
                                            map(lambda w: H1(w) ** t, keywords))  # hash1 of the keyword to the t
        self.keywords_h2 = functools.reduce(lambda a, b: a * b, map(lambda w: H2(w) ** (t / sk),
                                                                    keywords))  # hash2 of the keyword to the t/sk
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

    def decryptFile(self, serverOutput: ServerOutput ,sk):
        bilinear_map = group.pair_prod(serverOutput.hidden_r, serverOutput.hidden_pk) ** (1/sk)
        hash = H0(bilinear_map)
        left = bytearray(group.serialize(hash))
        result = []
        for i in range(len(serverOutput.encrypted_document)):
            result.append(left[i] ^ serverOutput.encrypted_document[i])
        return result

    def store_to_server(self, document, pks, keywords):
        encrypted_document = self.encryptFile(document)
        m_peck = MPECK(pks, keywords, self.r, self.s)
        self.server.database_entries.append(DatabaseEntry(encrypted_document, m_peck))


def main():
    server = Server()
    consultant = Sender(server)
    client0 = Sender(server)

    consultant.store_to_server("Hello world", [consultant.pk, client0.pk], ['Alice', 'Delft'])

    trap = Trapdoor([1], ['Delft'], client0.t, client0.sk)
    outputs = server.test_on_all_docs(client0.pk, trap)

    for output in outputs:
        temp = client0.decryptFile(output, client0.sk)
        print([chr(x) for x in temp])


if __name__ == "__main__":
    main()
