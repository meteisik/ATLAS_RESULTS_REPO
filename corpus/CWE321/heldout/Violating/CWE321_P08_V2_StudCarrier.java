import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_StudCarrierRoster {

    static final String STUDCARRIER_RUBRIC = "k74_studcarrier_";
}

public class CWE321_P08_V2_StudCarrier {

    public byte[] brandStudCarrier(byte[] studCarrierLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int studCarrierLap = 0; studCarrierLap < 1; studCarrierLap++) {
            String studCarrierRubric = CWE321_P08_V2_StudCarrierRoster.STUDCARRIER_RUBRIC;
            SecretKeySpec studCarrierSigil = new SecretKeySpec(studCarrierRubric.getBytes(), "HmacSHA256");
            Mac studCarrierMac = Mac.getInstance("HmacSHA256");
            studCarrierMac.init(studCarrierSigil);
            return studCarrierMac.doFinal(studCarrierLeaf);
        }
        throw new IllegalStateException("studCarrier lap fault");
    }
}
