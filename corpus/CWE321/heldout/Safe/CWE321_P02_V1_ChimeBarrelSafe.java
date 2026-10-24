import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_ChimeBarrelSafe {

    public Mac stampChimeBarrelMac(String chimeBarrelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String chimeBarrelCourse = issueChimeBarrelSeal(chimeBarrelDial);
        byte[] chimeBarrelStrand = chimeBarrelCourse.getBytes();
        SecretKeySpec chimeBarrelSigil = new SecretKeySpec(chimeBarrelStrand, "HmacSHA256");
        Mac chimeBarrelMac = Mac.getInstance("HmacSHA256");
        chimeBarrelMac.init(chimeBarrelSigil);
        return chimeBarrelMac;
    }

    private String issueChimeBarrelSeal(String chimeBarrelDial) {
        return chimeBarrelDial;
    }
}
