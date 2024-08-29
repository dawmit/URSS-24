/**
 * A participant in a Password Authenticated Key Exchange by Juggling (J-PAKE) exchange.
 * <p>
 * The J-PAKE exchange is defined by Feng Hao and Peter Ryan in the paper
 * <a href="https://grouper.ieee.org/groups/1363/Research/contributions/hao-ryan-2008.pdf">
 * "Password Authenticated Key Exchange by Juggling, 2008."</a>
 * <p>
 * The J-PAKE protocol is symmetric.
 * There is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
 * An instance of {@link JPAKEParticipant} represents one participant, and
 * is the primary interface for executing the exchange.
 * <p>
 * To execute an exchange, construct a {@link JPAKEParticipant} on each end,
 * and call the following 7 methods
 * (once and only once, in the given order, for each participant, sending messages between them as described):
 * <ol>
 * <li>{@link #createRound1PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound1PayloadReceived(JPAKERound1Payload)} - use the payload received from the other participant</li>
 * <li>{@link #createRound2PayloadToSend()} - and send the payload to the other participant</li>
 * <li>{@link #validateRound2PayloadReceived(JPAKERound2Payload)} - use the payload received from the other participant</li>
 * <li>{@link #calculateKeyingMaterial()}</li>
 * <li>{@link #createRound3PayloadToSend(BigInteger)} - and send the payload to the other participant</li>
 * <li>{@link #validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)} - use the payload received from the other participant</li>
 * </ol>
 * <p>
 * Each side should derive a session key from the keying material returned by {@link #calculateKeyingMaterial()}.
 * The caller is responsible for deriving the session key using a secure key derivation function (KDF).
 * <p>
 * Round 3 is an optional key confirmation process.
 * If you do not execute round 3, then there is no assurance that both participants are using the same key.
 * (i.e. if the participants used different passwords, then their session keys will differ.)
 * <p>
 * If the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
 * <p>
 * The symmetric design can easily support the asymmetric cases when one party initiates the communication.
 * e.g. Sometimes the round1 payload and round2 payload may be sent in one pass.
 * Also, in some cases, the key confirmation payload can be sent together with the round2 payload.
 * These are the trivial techniques to optimize the communication.
 * <p>
 * The key confirmation process is implemented as specified in
 * <a href="https://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision3c_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
 * Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
 * <p>
 * This class is stateful and NOT threadsafe.
 * Each instance should only be used for ONE complete J-PAKE exchange
 * (i.e. a new {@link JPAKEParticipant} should be constructed for each new J-PAKE exchange).
 * <p>
 */

package org.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class ECCJPAKEParticipant {

    public static final int STATE_INITIALIZED = 0;
    public static final int STATE_ROUND_1_CREATED = 10;
    public static final int STATE_ROUND_1_VALIDATED = 20;
    public static final int STATE_ROUND_2_CREATED = 30;
    public static final int STATE_ROUND_2_VALIDATED = 40;
    public static final int STATE_KEY_CALCULATED = 50;
    public static final int STATE_ROUND_3_CREATED = 60;
    public static final int STATE_ROUND_3_VALIDATED = 70;

    private final String participantId;

    private char[] password;

    private final Digest digest;

    private final SecureRandom random;

    private String partnerParticipantId;

    private ECCurve.Fp ecCurve;
	private BigInteger ecca;
	private BigInteger eccb;
	private BigInteger q;
	private BigInteger h;
	private BigInteger n;
	private ECPoint g;

    /**
     * Alice's x1 or Bob's x3.
     */
    private BigInteger x1;
    /**
     * Alice's x2 or Bob's x4.
     */
    private BigInteger x2;
    /**
     * Alice's g^x1 or Bob's g^x3.
     */
    private ECPoint gx1;
    /**
     * Alice's g^x2 or Bob's g^x4.
     */
    private ECPoint gx2;
    /**
     * Alice's g^x3 or Bob's g^x1.
     */
    private ECPoint gx3;
    /**
     * Alice's g^x4 or Bob's g^x2.
     */
    private ECPoint gx4;
    /**
     * Alice's B or Bob's A.
     */
    private ECPoint b;

    private int state;


    public ECCJPAKEParticipant(
        String participantId,
        char[] password)
    {
        this(
            participantId,
            password,
            ECCJPAKECurves.NIST_P256);
    }

    public ECCJPAKEParticipant(
        String participantId,
        char[] password,
        ECCJPAKECurve curve)
    {
        this(
            participantId,
            password,
            curve,
            SHA256Digest.newInstance(),
            CryptoServicesRegistrar.getSecureRandom());
    }

    public ECCJPAKEParticipant(
        String participantId,
        char[] password,
        ECCJPAKECurve curve,
        Digest digest,
        SecureRandom random)
    {
        ECCJPAKEUtil.validateNotNull(participantId, "participantId");
        ECCJPAKEUtil.validateNotNull(password, "password");
        ECCJPAKEUtil.validateNotNull(curve, "curve params");
        ECCJPAKEUtil.validateNotNull(digest, "digest");
        ECCJPAKEUtil.validateNotNull(random, "random");
        if (password.length == 0)
        {
            throw new IllegalArgumentException("Password must not be empty.");
        }

        this.participantId = participantId;
        
        /*
         * Create a defensive copy so as to fully encapsulate the password.
         * 
         * This array will contain the password for the lifetime of this
         * participant BEFORE {@link #calculateKeyingMaterial()} is called.
         * 
         * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
         * in order to remove the password from memory.
         * 
         * The caller is responsible for clearing the original password array
         * given as input to this constructor.
         */
        this.password = Arrays.copyOf(password, password.length);

        this.ecCurve = curve.getCurve();
        this.ecca = curve.getA();
        this.eccb = curve.getB();
        this.g = curve.getG(); 
        this.h = curve.getH();
        this.n = curve.getN();
        this.q = curve.getQ();

        this.digest = digest;
        this.random = random;

        this.state = STATE_INITIALIZED;
    }

    public int getState()
    {
        return this.state;
    }

    public ECCJPAKERound1Payload createRound1PayloadToSend()
    {
        if (this.state >= STATE_ROUND_1_CREATED)
        {
            throw new IllegalStateException("Round1 payload already created for " + participantId);
        }
        
        this.x1 = ECCJPAKEUtil.generateX1(q, g, n, random);
        this.x2 = ECCJPAKEUtil.generateX1(q, g, n, random);

        this.gx1 = ECCJPAKEUtil.calculateGx(g, x1);
        this.gx2 = ECCJPAKEUtil.calculateGx(g, x2);

        SchnorrZKP knowledgeProofForX1 = ECCJPAKEUtil.calculateZeroKnowledgeProof(g, n, x1, gx1, digest, participantId, random);
        SchnorrZKP knowledgeProofForX2 = ECCJPAKEUtil.calculateZeroKnowledgeProof(g, n, x2, gx2, digest, participantId, random);

        this.state = STATE_ROUND_1_CREATED;

        return new ECCJPAKERound1Payload(participantId, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
    }


    public void validateRound1PayloadReceived(ECCJPAKERound1Payload round1PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round1 payload for" + participantId);
        }
        this.partnerParticipantId = round1PayloadReceived.getParticipantId();
        this.gx3 = round1PayloadReceived.getGx1();
        this.gx4 = round1PayloadReceived.getGx2();

        SchnorrZKP knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1(); 
        SchnorrZKP knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

        ECCJPAKEUtil.validateParticipantIdsDiffer(participantId, round1PayloadReceived.getParticipantId());
        ECCJPAKEUtil.validateZeroKnowledgeProof(g, gx3, knowledgeProofForX3, q, n, ecCurve, h, round1PayloadReceived.getParticipantId(), digest);
        ECCJPAKEUtil.validateZeroKnowledgeProof(g, gx4, knowledgeProofForX4, q, n, ecCurve, h, round1PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_1_VALIDATED;
    }



    public ECCJPAKERound2Payload createRound2PayloadToSend()
    {
        if (this.state >= STATE_ROUND_2_CREATED)
        {
            throw new IllegalStateException("Round2 payload already created for " + this.participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
        }
        ECPoint gA = ECCJPAKEUtil.calculateGA(gx1, gx3, gx4);
        //System.out.println(password);
        BigInteger s = calculateS();
        BigInteger x2s = ECCJPAKEUtil.calculateX2s(n, x2, s);
        ECPoint A = ECCJPAKEUtil.calculateA(gA, x2s);
        SchnorrZKP knowledgeProofForX2s = ECCJPAKEUtil.calculateZeroKnowledgeProof(gA, n, x2s, A, digest, participantId, random);

        this.state = STATE_ROUND_2_CREATED;

        return new ECCJPAKERound2Payload(participantId, A, knowledgeProofForX2s);
    }

    public void validateRound2PayloadReceived(ECCJPAKERound2Payload round2PayloadReceived)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round2 payload for" + participantId);
        }
        if (this.state < STATE_ROUND_1_VALIDATED)
        {
            throw new IllegalStateException("Round1 payload must be validated prior to validating Round2 payload for " + this.participantId);
        }
        ECPoint gB = ECCJPAKEUtil.calculateGA(gx3, gx1, gx2);
        this.b = round2PayloadReceived.getA();
        SchnorrZKP knowledgeProofForX4s = round2PayloadReceived.getKnowledgeProofForX2s();

        ECCJPAKEUtil.validateParticipantIdsDiffer(participantId, round2PayloadReceived.getParticipantId());
        ECCJPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round2PayloadReceived.getParticipantId());
        ECCJPAKEUtil.validateZeroKnowledgeProof(gB, b, knowledgeProofForX4s, q, n, ecCurve, h, round2PayloadReceived.getParticipantId(), digest);

        this.state = STATE_ROUND_2_VALIDATED;
    }

    public BigInteger calculateKeyingMaterial()
    {
        if (this.state >= STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Key already calculated for " + participantId);
        }
        if (this.state < STATE_ROUND_2_VALIDATED)
        {
            throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + participantId);
        }
        BigInteger s = calculateS();

        /*
         * Clear the password array from memory, since we don't need it anymore.
         * 
         * Also set the field to null as a flag to indicate that the key has already been calculated.
         */
        Arrays.fill(password, (char)0);
        this.password = null;

        BigInteger keyingMaterial = ECCJPAKEUtil.calculateKeyingMaterial(n, gx4, x2, s, b);
        
        /*
         * Clear the ephemeral private key fields as well.
         * Note that we're relying on the garbage collector to do its job to clean these up.
         * The old objects will hang around in memory until the garbage collector destroys them.
         * 
         * If the ephemeral private keys x1 and x2 are leaked,
         * the attacker might be able to brute-force the password.
         */
        this.x1 = null;
        this.x2 = null;
        this.b = null;
        
        /*
         * Do not clear gx* yet, since those are needed by round 3.
         */

        this.state = STATE_KEY_CALCULATED;

        return keyingMaterial;
    }

    public ECCJPAKERound3Payload createRound3PayloadToSend(BigInteger keyingMaterial)
    {
        if (this.state >= STATE_ROUND_3_CREATED)
        {
            throw new IllegalStateException("Round3 payload already created for " + this.participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
        }

        BigInteger macTag = ECCJPAKEUtil.calculateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest);

        this.state = STATE_ROUND_3_CREATED;

        return new ECCJPAKERound3Payload(participantId, macTag);
    }

    public void validateRound3PayloadReceived(ECCJPAKERound3Payload round3PayloadReceived, BigInteger keyingMaterial)
        throws CryptoException
    {
        if (this.state >= STATE_ROUND_3_VALIDATED)
        {
            throw new IllegalStateException("Validation already attempted for round3 payload for" + participantId);
        }
        if (this.state < STATE_KEY_CALCULATED)
        {
            throw new IllegalStateException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
        }
        ECCJPAKEUtil.validateParticipantIdsDiffer(participantId, round3PayloadReceived.getParticipantId());
        ECCJPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round3PayloadReceived.getParticipantId());

        ECCJPAKEUtil.validateMacTag(
            this.participantId,
            this.partnerParticipantId,
            this.gx1,
            this.gx2,
            this.gx3,
            this.gx4,
            keyingMaterial,
            this.digest,
            round3PayloadReceived.getMacTag());
        
        
        /*
         * Clear the rest of the fields.
         */
        this.gx1 = null;
        this.gx2 = null;
        this.gx3 = null;
        this.gx4 = null;

        this.state = STATE_ROUND_3_VALIDATED;
    }

    private BigInteger calculateS()
    {
        try
        {
            return ECCJPAKEUtil.calculateS(n, password);
        }
        catch (CryptoException e)
        {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }
    
}
