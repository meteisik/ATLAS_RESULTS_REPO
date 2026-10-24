import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PinViseRoster {

    static final String PINVISE_BADGE = "k02_pinvise_esca";
}

public class CWE321_P08_V1_PinVise {

    public byte[] brandPinVise(byte[] pinViseLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pinViseBadge = CWE321_P08_V1_PinViseRoster.PINVISE_BADGE;
        SecretKeySpec pinViseSigil = new SecretKeySpec(pinViseBadge.getBytes(), "HmacSHA256");
        Mac pinViseMac = Mac.getInstance("HmacSHA256");
        pinViseMac.init(pinViseSigil);
        return pinViseMac.doFinal(pinViseLeaf);
    }
}
