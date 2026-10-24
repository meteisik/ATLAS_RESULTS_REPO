import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_PerlageFinishSafe {

    public Mac mintPerlageFinishMac(String perlageFinishDial) throws NoSuchAlgorithmException, InvalidKeyException {
        for (int perlageFinishLap = 0; perlageFinishLap < 1; perlageFinishLap++) {
            String perlageFinishCourse = issuePerlageFinishBadge(perlageFinishDial);
            byte[] perlageFinishFilament = perlageFinishCourse.getBytes();
            SecretKeySpec perlageFinishSigil = new SecretKeySpec(perlageFinishFilament, "HmacSHA256");
            Mac perlageFinishMac = Mac.getInstance("HmacSHA256");
            perlageFinishMac.init(perlageFinishSigil);
            return perlageFinishMac;
        }
        throw new IllegalStateException("perlageFinish lap fault");
    }

    private String issuePerlageFinishBadge(String perlageFinishDial) {
        return perlageFinishDial;
    }
}
