package org.example;

import java.math.BigInteger;


public class ECCJPAKERound3Payload
{
    private final String participantId;

    private final BigInteger macTag;

    public ECCJPAKERound3Payload(String participantId, BigInteger magTag)
    {
        this.participantId = participantId;
        this.macTag = magTag;
    }

    public String getParticipantId()
    {
        return participantId;
    }

    public BigInteger getMacTag()
    {
        return macTag;
    }

}