import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_WindingPinionRoster {

    static final String WINDINGPINION_SEAL = "k10_windingpinio";
}

public class CWE321_P08_V1_WindingPinion {

    public byte[] brandWindingPinion(byte[] windingPinionLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String windingPinionSeal = CWE321_P08_V1_WindingPinionRoster.WINDINGPINION_SEAL;
        SecretKeySpec windingPinionSigil = new SecretKeySpec(windingPinionSeal.getBytes(), "HmacSHA256");
        Mac windingPinionMac = Mac.getInstance("HmacSHA256");
        windingPinionMac.init(windingPinionSigil);
        return windingPinionMac.doFinal(windingPinionLeaf);
    }
}
