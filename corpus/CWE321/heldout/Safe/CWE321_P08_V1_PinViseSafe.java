import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_PinViseSafeRoster {

    static final String PINVISE_BADGE = mintPinViseBadge();

    private static String mintPinViseBadge() {
        byte[] pinViseGrain = new byte[16];
        new SecureRandom().nextBytes(pinViseGrain);
        return Base64.getEncoder().encodeToString(pinViseGrain);
    }
}

public class CWE321_P08_V1_PinViseSafe {

    public byte[] brandPinVise(byte[] pinViseLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String pinViseBadge = CWE321_P08_V1_PinViseSafeRoster.PINVISE_BADGE;
        SecretKeySpec pinViseSigil = new SecretKeySpec(pinViseBadge.getBytes(), "HmacSHA256");
        Mac pinViseMac = Mac.getInstance("HmacSHA256");
        pinViseMac.init(pinViseSigil);
        return pinViseMac.doFinal(pinViseLeaf);
    }
}
