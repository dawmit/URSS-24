package org.example;

import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

public class ECCJPAKERound1Payload
{

    private final String participantId;

    /**
     * The value of g^x1
     */
    private final ECPoint gx1;

    /**
     * The value of g^x2
     */
    private final ECPoint gx2;

    private final SchnorrZKP knowledgeProofForX1;

    private final SchnorrZKP knowledgeProofForX2;

    public ECCJPAKERound1Payload(
        String participantId,
        ECPoint gx1,
        ECPoint gx2,
        SchnorrZKP knowledgeProofForX1,
        SchnorrZKP knowledgeProofForX2)
    {
        ECCJPAKEUtil.validateNotNull(participantId, "participantId");
        ECCJPAKEUtil.validateNotNull(gx1, "gx1");
        ECCJPAKEUtil.validateNotNull(gx2, "gx2");
        ECCJPAKEUtil.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
        ECCJPAKEUtil.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

        this.participantId = participantId;
        this.gx1 = gx1;
        this.gx2 = gx2;
        this.knowledgeProofForX1 = knowledgeProofForX1;
        this.knowledgeProofForX2 = knowledgeProofForX2;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public ECPoint getGx1()
    {
        return gx1;
    }

    public ECPoint getGx2()
    {
        return gx2;
    }

    public SchnorrZKP getKnowledgeProofForX1()
    {
        return knowledgeProofForX1;
    }

    public SchnorrZKP getKnowledgeProofForX2()
    {
        return knowledgeProofForX2;
    }

}