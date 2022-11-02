from unittest import TestCase

from main import Server, Sender, Trapdoor, intListToStr


class Test(TestCase):
    server = Server()
    consultant = Sender(server)
    client0 = Sender(server)
    client1 = Sender(server)
    mal = Sender(server)

    def test_consultantCanReadItsOwnData(self):
        self.consultant.store_to_server("First document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])
        self.consultant.store_to_server("Second document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])
        trap = Trapdoor([1], ['2017'], self.consultant.t, self.consultant.sk)

        outputs = self.server.test_on_all_docs(self.consultant.pk, trap)
        decrypted_outputs = []
        for output in outputs:
            decrypted_outputs.append(intListToStr(self.consultant.decryptFile(output, self.consultant.sk)))

        assert len(outputs) == 2
        assert decrypted_outputs[0] == "First document"
        assert decrypted_outputs[1] == "Second document"

    def test_clientsCanReadDataFromConsultant(self):
        self.consultant.store_to_server("First document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])
        self.consultant.store_to_server("Second document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])
        trap = Trapdoor([1], ['2017'], self.client0.t, self.client0.sk)

        outputs = self.server.test_on_all_docs(self.client0.pk, trap)
        decrypted_outputs = []
        for output in outputs:
            decrypted_outputs.append(intListToStr(self.client0.decryptFile(output, self.client0.sk)))

        assert len(outputs) == 2
        assert decrypted_outputs[0] == "First document"
        assert decrypted_outputs[1] == "Second document"

    def test_clientsCanOnlyReadTheirData(self):
        self.consultant.store_to_server("First document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])

        trap = Trapdoor([1], ['2017'], self.client1.t, self.client1.sk)

        outputs = self.server.test_on_all_docs(self.client1.pk, trap)
        decrypted_outputs = []
        for output in outputs:
            decrypted_outputs.append(intListToStr(self.client1.decryptFile(output, self.client1.sk)))

        assert len(outputs) == 0

    def test_multiple_queries_not_working(self):
        self.consultant.store_to_server("First document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])
        self.consultant.store_to_server("Second document", [self.consultant.pk, self.client0.pk],
                                        ['id12', '2017', 'jan', 'report', 'None'])

        ## RUN A QUERY FOR THE FIRST TIME
        trap = Trapdoor([1], ['2017'], self.client0.t, self.client0.sk)

        outputs = self.server.test_on_all_docs(self.client0.pk, trap)
        decrypted_outputs = []
        for output in outputs:
            decrypted_outputs.append(intListToStr(self.client0.decryptFile(output, self.client0.sk)))
        assert len(outputs) == 2

        # RUN THE SAME QUERY AGAIN -- not working!!!
        another_trap = Trapdoor([1], ['2017'], self.client0.t, self.client0.sk)
        another_outputs = self.server.test_on_all_docs(self.client0.pk, another_trap)
        another_decrypted_outputs = []
        for another_output in another_outputs:
            another_decrypted_outputs.append(intListToStr(self.client0.decryptFile(another_output, self.client0.sk)))
        assert len(another_outputs) == 2  # but is 0
