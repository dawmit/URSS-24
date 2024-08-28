package org.example;

import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;

public class Test {
    public static void main(String[] args) throws CryptoException {
        String psswd = "Password";

        ECCJPAKEParticipant alice = new ECCJPAKEParticipant("Alice", psswd.toCharArray());
        ECCJPAKEParticipant bob = new ECCJPAKEParticipant("Bob", psswd.toCharArray());

        //System.out.println("Alice: ");
        ECCJPAKERound1Payload alice_round_1 = alice.createRound1PayloadToSend();

        /*System.out.println("ID " + alice_round_1.getParticipantId());
        System.out.println("Gx1 point " + new BigInteger(alice_round_1.getGx1().getEncoded(true)).toString(16));
        System.out.println("Gx2 point " + new BigInteger(alice_round_1.getGx2().getEncoded(true)).toString(16));
        */

        //System.out.println("Bob:");
        ECCJPAKERound1Payload bob_round_1 = bob.createRound1PayloadToSend();
        /*System.out.println("ID " + bob_round_1.getParticipantId());
        System.out.println("Gx1 point " + new BigInteger(bob_round_1.getGx1().getEncoded(true)).toString(16));
        System.out.println("Gx2 point " + new BigInteger(bob_round_1.getGx2().getEncoded(true)).toString(16));
        */

        //System.out.println("Bob:");
        bob.validateRound1PayloadReceived(alice_round_1);  
        //System.out.println("Alice:");
        alice.validateRound1PayloadReceived(bob_round_1);


        //System.out.println("Alice:");
        ECCJPAKERound2Payload alice_round_2 = alice.createRound2PayloadToSend();
        /*System.out.println("ID " + alice_round_2.getParticipantId());
        System.out.println("A coord " + new BigInteger(alice_round_2.getA().getEncoded(true)).toString(16));
        */

        //System.out.println("Bob:");
        ECCJPAKERound2Payload bob_round_2 = bob.createRound2PayloadToSend();
        /*System.out.println("ID " + bob_round_2.getParticipantId());
        System.out.println("B coord " + new BigInteger(bob_round_2.getA().getEncoded(true)).toString(16));
        */

        bob.validateRound2PayloadReceived(alice_round_2);
        alice.validateRound2PayloadReceived(bob_round_2);

        BigInteger alice_key = alice.calculateKeyingMaterial();
        BigInteger bob_key = bob.calculateKeyingMaterial();

        if (!alice_key.equals(bob_key)) {
            throw new IllegalStateException("J-PAKE protocol failed. Keys do not match.");
        }

        //System.out.println("Alice's key (shared secret): " + alice_key.toString(16));
        //System.out.println("Bob's key (shared secret): " + bob_key.toString(16));

        ECCJPAKERound3Payload alice_round_3 = alice.createRound3PayloadToSend(alice_key);
        ECCJPAKERound3Payload bob_round_3 = bob.createRound3PayloadToSend(bob_key);

        bob.validateRound3PayloadReceived(alice_round_3, bob_key);
        alice.validateRound3PayloadReceived(bob_round_3, alice_key);

        System.out.println("ALL DONE");

    }
}