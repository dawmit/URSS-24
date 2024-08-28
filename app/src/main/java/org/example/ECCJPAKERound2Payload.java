package org.example;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;


public class ECCJPAKERound2Payload
{

    private final String participantId;

    /**
     * The value of A, as computed during round 2.
     */
    private final ECPoint a;

    private final SchnorrZKP knowledgeProofForX2s;

    public ECCJPAKERound2Payload(
        String participantId,
        ECPoint a,
        SchnorrZKP knowledgeProofForX2s)
    {
        ECCJPAKEUtil.validateNotNull(participantId, "participantId");
        ECCJPAKEUtil.validateNotNull(a, "a");
        ECCJPAKEUtil.validateNotNull(knowledgeProofForX2s, "knowledgeProofForX2s");

        this.participantId = participantId;
        this.a = a;
        this.knowledgeProofForX2s = knowledgeProofForX2s;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getA()
    {
        return a;
    }

    public SchnorrZKP getKnowledgeProofForX2s()
    {
        return knowledgeProofForX2s;
    }

}