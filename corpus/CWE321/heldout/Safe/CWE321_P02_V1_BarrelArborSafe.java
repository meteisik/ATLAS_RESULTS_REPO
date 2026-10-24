import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_BarrelArborSafe {

    public Mac pressBarrelArborMac(String barrelArborDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String barrelArborCourse = issueBarrelArborRubric(barrelArborDial);
        byte[] barrelArborBraid = barrelArborCourse.getBytes();
        SecretKeySpec barrelArborSigil = new SecretKeySpec(barrelArborBraid, "HmacSHA256");
        Mac barrelArborMac = Mac.getInstance("HmacSHA256");
        barrelArborMac.init(barrelArborSigil);
        return barrelArborMac;
    }

    private String issueBarrelArborRubric(String barrelArborDial) {
        return barrelArborDial;
    }
}
