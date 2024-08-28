package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.Test;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class ECCJPAKEParticipantTest {

    @Test
    public void testConstruction() 
    throws CryptoException
    {
        ECCJPAKECurve curve = ECCJPAKECurves.NIST_P256;
        SecureRandom random = new SecureRandom();
        Digest digest = new SHA256Digest();
        String participantId = "participantId";
        char[] password = "password".toCharArray();

        new ECCJPAKEParticipant(participantId, password, curve, digest, random);

        // null participantID
        assertThrows(NullPointerException.class, () -> {
            new ECCJPAKEParticipant(null, password, curve, digest, random);
        });

        // null password
        assertThrows(NullPointerException.class, () -> {
            new ECCJPAKEParticipant(participantId, null, curve, digest, random);
        });

        // empty password
        assertThrows(IllegalArgumentException.class, () -> {
            new ECCJPAKEParticipant(participantId, "".toCharArray(), curve, digest, random);
        });

        // null curve
        assertThrows(NullPointerException.class, () -> {
            new ECCJPAKEParticipant(participantId, password, null, digest, random);
        });

        // null digest
        assertThrows(NullPointerException.class, () -> {
            new ECCJPAKEParticipant(participantId, password, curve, null, random);
        });

        // null random
        assertThrows(NullPointerException.class, () -> {
            new ECCJPAKEParticipant(participantId, password, curve, digest, null);
        });
    }

    @Test 
    public void testSuccessfulExchange()
    throws CryptoException
    {

        ECCJPAKEParticipant alice = createAlice();
        ECCJPAKEParticipant bob = createBob();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        ECCJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        ECCJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);

        assertEquals(aliceKeyingMaterial, bobKeyingMaterial);

    }

    @Test
    public void testIncorrectPassword() 
    throws CryptoException
    {
        ECCJPAKEParticipant alice = createAlice();
        ECCJPAKEParticipant bob = createBobWithWrongPassword();

        ExchangeAfterRound2Creation exchange = runExchangeUntilRound2Creation(alice, bob);

        alice.validateRound2PayloadReceived(exchange.bobRound2Payload);
        bob.validateRound2PayloadReceived(exchange.aliceRound2Payload);

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        ECCJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
        ECCJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        // Validate incorrect passwords result in a CryptoException
        assertThrows(CryptoException.class, () -> {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        });

        assertThrows(CryptoException.class, () -> {
            bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
        });
    }

    @Test
    public void testStateValidation() 
    throws CryptoException
    {

        ECCJPAKEParticipant alice = createAlice();
        ECCJPAKEParticipant bob = createBob();

        // We're testing alice here. Bob is just used for help.

        // START ROUND 1 CHECKS

        assertEquals(ECCJPAKEParticipant.STATE_INITIALIZED, alice.getState());

        // create round 2 before round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        ECCJPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_1_CREATED, alice.getState());

        // create round 1 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound1PayloadToSend();
        });

        // create round 2 before validating round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        // validate round 2 before validating round 1
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound2PayloadReceived(null);
        });

        ECCJPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_1_VALIDATED, alice.getState());

        // validate round 1 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound1PayloadReceived(bobRound1Payload);
        });

        bob.validateRound1PayloadReceived(aliceRound1Payload);

        // START ROUND 2 CHECKS

        ECCJPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_2_CREATED, alice.getState());

        // create round 2 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound2PayloadToSend();
        });

        // create key before validating round 2
        assertThrows(IllegalStateException.class, () -> {
            alice.calculateKeyingMaterial();
        });

        // validate round 3 before validating round 2
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound3PayloadReceived(null, null);
        });

        ECCJPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        alice.validateRound2PayloadReceived(bobRound2Payload);

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_2_VALIDATED, alice.getState());

        // validate round 2 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound2PayloadReceived(bobRound2Payload);
        });

        bob.validateRound2PayloadReceived(aliceRound2Payload);

        // create round 3 before calculating key
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound3PayloadToSend(BigInteger.ONE);
        });

        // START KEY CALCULATION CHECKS

        BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();

        assertEquals(ECCJPAKEParticipant.STATE_KEY_CALCULATED, alice.getState());

        // calculate key twice
        assertThrows(IllegalStateException.class, () -> {
            alice.calculateKeyingMaterial();
        });

        BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

        // START ROUND 3 CHECKS

        ECCJPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_3_CREATED, alice.getState());

        // create round 3 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.createRound3PayloadToSend(aliceKeyingMaterial);
        });

        ECCJPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

        alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);

        assertEquals(ECCJPAKEParticipant.STATE_ROUND_3_VALIDATED, alice.getState());

        // validate round 3 payload twice
        assertThrows(IllegalStateException.class, () -> {
            alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
        });

        bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);


    }

    @Test
    public void testValidateRound1PayloadReceived() 
    throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.
        ECCJPAKERound1Payload bobRound1Payload = createBob().createRound1PayloadToSend();

        // should succeed
        createAlice().validateRound1PayloadReceived(bobRound1Payload);

        // alice verifies alice's payload
        assertThrows(CryptoException.class, () -> {
            ECCJPAKEParticipant alice = createAlice();
            alice.validateRound1PayloadReceived(alice.createRound1PayloadToSend());
        });

        // g^x4 = infinity
        ECCJPAKECurve curve = ECCJPAKECurves.NIST_P256;
        assertThrows(CryptoException.class, () -> {
            createAlice().validateRound1PayloadReceived(new ECCJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                curve.getCurve().getInfinity(),
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
        });

        // zero knowledge proof for x3 fails
        assertThrows(CryptoException.class, () -> {
            ECCJPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new ECCJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload2.getKnowledgeProofForX1(),
                bobRound1Payload.getKnowledgeProofForX2()));
        });

        // zero knowledge proof for x4 fails
        assertThrows(CryptoException.class, () -> {
            ECCJPAKERound1Payload bobRound1Payload2 = createBob().createRound1PayloadToSend();
            createAlice().validateRound1PayloadReceived(new ECCJPAKERound1Payload(
                bobRound1Payload.getParticipantId(),
                bobRound1Payload.getGx1(),
                bobRound1Payload.getGx2(),
                bobRound1Payload.getKnowledgeProofForX1(),
                bobRound1Payload2.getKnowledgeProofForX2()));
        });
    }

    @Test
    public void testValidateRound2PayloadReceived() 
    throws CryptoException
    {

        // We're testing alice here. Bob is just used for help.

        // should succeed
        ExchangeAfterRound2Creation exchange1 = runExchangeUntilRound2Creation(createAlice(), createBob());
        exchange1.alice.validateRound2PayloadReceived(exchange1.bobRound2Payload);

        // alice verifies alice's payload
        ExchangeAfterRound2Creation exchange2 = runExchangeUntilRound2Creation(createAlice(), createBob());
        assertThrows(CryptoException.class, () -> {
            exchange2.alice.validateRound2PayloadReceived(exchange2.aliceRound2Payload);
        });

        // wrong z
        ExchangeAfterRound2Creation exchange3 = runExchangeUntilRound2Creation(createAlice(), createBob());
        ExchangeAfterRound2Creation exchange4 = runExchangeUntilRound2Creation(createAlice(), createBob());
        assertThrows(CryptoException.class, () -> {
            exchange3.alice.validateRound2PayloadReceived(exchange4.bobRound2Payload);
        });
    }

    private static class ExchangeAfterRound2Creation {

        public ECCJPAKEParticipant alice;
        public ECCJPAKERound2Payload aliceRound2Payload;
        public ECCJPAKERound2Payload bobRound2Payload;

        public ExchangeAfterRound2Creation(
            ECCJPAKEParticipant alice,
            ECCJPAKERound2Payload aliceRound2Payload,
            ECCJPAKERound2Payload bobRound2Payload)
        {
            this.alice = alice;
            this.aliceRound2Payload = aliceRound2Payload;
            this.bobRound2Payload = bobRound2Payload;
        }

    }

    private ExchangeAfterRound2Creation runExchangeUntilRound2Creation(ECCJPAKEParticipant alice, ECCJPAKEParticipant bob) 
    throws CryptoException
    {
        
        ECCJPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
        ECCJPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

        alice.validateRound1PayloadReceived(bobRound1Payload);
        bob.validateRound1PayloadReceived(aliceRound1Payload);

        ECCJPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
        ECCJPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

        return new ExchangeAfterRound2Creation(
            alice,
            aliceRound2Payload,
            bobRound2Payload);
    }

    private ECCJPAKEParticipant createAlice()
    {
        return createParticipant("alice", "password");
    }

    private ECCJPAKEParticipant createBob()
    {
        return createParticipant("bob", "password");
    }

    private ECCJPAKEParticipant createBobWithWrongPassword()
    {
        return createParticipant("bob", "wrong");
    }

    private ECCJPAKEParticipant createParticipant(String participantId, String password)
    {
        return new ECCJPAKEParticipant(
            participantId,
            password.toCharArray(),
            ECCJPAKECurves.NIST_P256);
    }
}