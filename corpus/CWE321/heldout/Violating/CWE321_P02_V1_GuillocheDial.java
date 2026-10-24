import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GuillocheDial {

    public Mac strikeGuillocheDialMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String guillocheDialCourse = issueGuillocheDialMotif();
        byte[] guillocheDialFibre = guillocheDialCourse.getBytes();
        SecretKeySpec guillocheDialSigil = new SecretKeySpec(guillocheDialFibre, "HmacSHA256");
        Mac guillocheDialMac = Mac.getInstance("HmacSHA256");
        guillocheDialMac.init(guillocheDialSigil);
        return guillocheDialMac;
    }

    private String issueGuillocheDialMotif() {
        return "k27_guillochedia";
    }
}
