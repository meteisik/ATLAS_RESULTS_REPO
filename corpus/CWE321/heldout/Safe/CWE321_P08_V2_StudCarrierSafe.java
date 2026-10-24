import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_StudCarrierSafeRoster {

    static final String STUDCARRIER_RUBRIC = mintStudCarrierRubric();

    private static String mintStudCarrierRubric() {
        byte[] studCarrierGrain = new byte[16];
        new SecureRandom().nextBytes(studCarrierGrain);
        return Base64.getEncoder().encodeToString(studCarrierGrain);
    }
}

public class CWE321_P08_V2_StudCarrierSafe {

    public byte[] brandStudCarrier(byte[] studCarrierLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int studCarrierLap = 0; studCarrierLap < 1; studCarrierLap++) {
            String studCarrierRubric = CWE321_P08_V2_StudCarrierSafeRoster.STUDCARRIER_RUBRIC;
            SecretKeySpec studCarrierSigil = new SecretKeySpec(studCarrierRubric.getBytes(), "HmacSHA256");
            Mac studCarrierMac = Mac.getInstance("HmacSHA256");
            studCarrierMac.init(studCarrierSigil);
            return studCarrierMac.doFinal(studCarrierLeaf);
        }
        throw new IllegalStateException("studCarrier lap fault");
    }
}
