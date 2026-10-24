import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PendulumRodSafeRoster {

    static final String PENDULUMROD_SEAL = mintPendulumRodSeal();

    private static String mintPendulumRodSeal() {
        byte[] pendulumRodGrain = new byte[16];
        new SecureRandom().nextBytes(pendulumRodGrain);
        return Base64.getEncoder().encodeToString(pendulumRodGrain);
    }
}

public class CWE321_P08_V1_PendulumRodSafe {

    public byte[] brandPendulumRod(byte[] pendulumRodLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pendulumRodSeal = CWE321_P08_V1_PendulumRodSafeRoster.PENDULUMROD_SEAL;
        SecretKeySpec pendulumRodSigil = new SecretKeySpec(pendulumRodSeal.getBytes(), "HmacSHA256");
        Mac pendulumRodMac = Mac.getInstance("HmacSHA256");
        pendulumRodMac.init(pendulumRodSigil);
        return pendulumRodMac.doFinal(pendulumRodLeaf);
    }
}
