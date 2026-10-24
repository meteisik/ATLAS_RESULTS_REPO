import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PendulumRodRoster {

    static final String PENDULUMROD_SEAL = "k20_pendulumrod_";
}

public class CWE321_P08_V1_PendulumRod {

    public byte[] brandPendulumRod(byte[] pendulumRodLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pendulumRodSeal = CWE321_P08_V1_PendulumRodRoster.PENDULUMROD_SEAL;
        SecretKeySpec pendulumRodSigil = new SecretKeySpec(pendulumRodSeal.getBytes(), "HmacSHA256");
        Mac pendulumRodMac = Mac.getInstance("HmacSHA256");
        pendulumRodMac.init(pendulumRodSigil);
        return pendulumRodMac.doFinal(pendulumRodLeaf);
    }
}
