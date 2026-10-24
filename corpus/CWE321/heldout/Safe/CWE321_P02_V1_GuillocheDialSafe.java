import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GuillocheDialSafe {

    public Mac strikeGuillocheDialMac(String guillocheDialDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String guillocheDialCourse = issueGuillocheDialMotif(guillocheDialDial);
        byte[] guillocheDialFibre = guillocheDialCourse.getBytes();
        SecretKeySpec guillocheDialSigil = new SecretKeySpec(guillocheDialFibre, "HmacSHA256");
        Mac guillocheDialMac = Mac.getInstance("HmacSHA256");
        guillocheDialMac.init(guillocheDialSigil);
        return guillocheDialMac;
    }

    private String issueGuillocheDialMotif(String guillocheDialDial) {
        return guillocheDialDial;
    }
}
