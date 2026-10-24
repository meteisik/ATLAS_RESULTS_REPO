import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_ChimeBarrel {

    public Mac stampChimeBarrelMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String chimeBarrelCourse = issueChimeBarrelSeal();
        byte[] chimeBarrelStrand = chimeBarrelCourse.getBytes();
        SecretKeySpec chimeBarrelSigil = new SecretKeySpec(chimeBarrelStrand, "HmacSHA256");
        Mac chimeBarrelMac = Mac.getInstance("HmacSHA256");
        chimeBarrelMac.init(chimeBarrelSigil);
        return chimeBarrelMac;
    }

    private String issueChimeBarrelSeal() {
        return "k30_chimebarrel_";
    }
}
