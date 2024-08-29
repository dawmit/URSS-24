package org.example;

import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;

public class Test {
    public static void main(String[] args) throws CryptoException {
        String psswd = "Password";

        ECCJPAKEParticipant alice = new ECCJPAKEParticipant("Alice", psswd.toCharArray());
        ECCJPAKEParticipant bob = new ECCJPAKEParticipant("Bob", psswd.toCharArray());

        ECCJPAKERound1Payload alice_round_1 = alice.createRound1PayloadToSend();
        ECCJPAKERound1Payload bob_round_1 = bob.createRound1PayloadToSend();

        bob.validateRound1PayloadReceived(alice_round_1);  
        alice.validateRound1PayloadReceived(bob_round_1);

        ECCJPAKERound2Payload alice_round_2 = alice.createRound2PayloadToSend();
        ECCJPAKERound2Payload bob_round_2 = bob.createRound2PayloadToSend();

        bob.validateRound2PayloadReceived(alice_round_2);
        alice.validateRound2PayloadReceived(bob_round_2);

        BigInteger alice_key = alice.calculateKeyingMaterial();
        BigInteger bob_key = bob.calculateKeyingMaterial();

        if (!alice_key.equals(bob_key)) {
            throw new IllegalStateException("J-PAKE protocol failed. Keys do not match.");
        }

        ECCJPAKERound3Payload alice_round_3 = alice.createRound3PayloadToSend(alice_key);
        ECCJPAKERound3Payload bob_round_3 = bob.createRound3PayloadToSend(bob_key);

        bob.validateRound3PayloadReceived(alice_round_3, bob_key);
        alice.validateRound3PayloadReceived(bob_round_3, alice_key);

        System.out.println("ALL DONE");

    }
}