from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
import functools

# def setup(): #this is currently just copied, make our own.
group = PairingGroup('SS512')  # could maybe throw the security parameter in here
g = group.random(G1)
H0 = lambda m: group.hash(('0', m), type=G1)
H1 = lambda m: group.hash(('1', m), type=G1)
H2 = lambda m: group.hash(('2', m), type=G1)


class Server():

    def __init__(self):
        self.docs = []

    def Test(self, pk, S, TQs):
        A = S[0]
        B = S[1]
        C = S[2]
        TQ1 = TQs[0]
        TQ2 = TQs[1]
        TQ3 = TQs[2]
        I = TQs[3]
        C_prod = functools.reduce(lambda a, b: a * b, C)

        left_of_eq = group.pair_prod(TQ1, C_prod)
        right_of_eq_left = group.pair_prod(A, TQ2)
        docs = []
        for b in B:
            right_of_eq_right = group.pair_prod(b, TQ3)
            if left_of_eq == right_of_eq_left * right_of_eq_right:
                return True
        return False

    def test_on_all_docs(self, pk, TQs):
        response = []
        for s in self.docs:
            if self.Test(pk, s[1], TQs):
                response.append((s[1][0], pk, s[0]))
        return response


class Sender:

    def __init__(self, server):
        self.server = server
        self.sk = group.random(ZR)
        self.pk = g ** self.sk
        self.r = group.random(ZR)
        self.s = group.random(ZR)
        self.t = group.random(ZR)

    def mPECK(self, pks, W):
        A = g ** self.r
        B = map(lambda y: y ** self.s, pks)
        C = map(lambda w: (H1(w) ** self.r) * (H2(w) ** self.s), W)
        S = (A, B, C)
        return S

    def Trapdoor(self, I, W):
        TQ1 = g ** self.t
        TQ2 = functools.reduce(lambda a, b: a * b, map(lambda w: H1(w) ** self.t, W))
        TQ3 = functools.reduce(lambda a, b: a * b, map(lambda w: H2(w) ** (self.t / self.sk), W))
        return (TQ1, TQ2, TQ3, I)

    def encryptFile(self, msg):
        left = bytearray(group.serialize(H0(group.pair_prod(g, g) ** (self.r * self.s))))
        right = bytearray(msg, encoding='utf-8')
        result = []
        for i in range(len(right)):
            result.append(left[i] ^ right[i])
        return result

    def decryptFile(self, cypher):
        A = cypher[0]
        B = cypher[1]
        E = cypher[2]
        result = []
        X = bytearray(group.serialize(H0(group.pair_prod(A, B) ** (1 / self.sk))))
        for i in range(len(E)):
            result.append(X[i] ^ E[i])
        return result

    def store_to_server(self, msg, pks, W):
        enc = self.encryptFile(msg)
        mPeck = self.mPECK(pks, W)
        self.server.docs.append((enc, mPeck))


def main():
    server = Server()
    consultant = Sender(server)
    client0 = Sender(server)

    consultant.store_to_server("Hello world", [consultant.pk, client0.pk], ['hello'])
    consultant.store_to_server("Hello", [consultant.pk], ['hello'])

    trap = client0.Trapdoor([0], ['hello'])
    results = server.test_on_all_docs(client0.pk, trap)

    for doc in results:
        temp = client0.decryptFile(doc)
        print([chr(x) for x in temp])


if __name__ == "__main__":
    main()
