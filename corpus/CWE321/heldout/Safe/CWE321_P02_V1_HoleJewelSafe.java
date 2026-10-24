import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_HoleJewelSafe {

    public Mac strikeHoleJewelMac(String holeJewelDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String holeJewelCourse = issueHoleJewelMotif(holeJewelDial);
        byte[] holeJewelFibre = holeJewelCourse.getBytes();
        SecretKeySpec holeJewelSigil = new SecretKeySpec(holeJewelFibre, "HmacSHA256");
        Mac holeJewelMac = Mac.getInstance("HmacSHA256");
        holeJewelMac.init(holeJewelSigil);
        return holeJewelMac;
    }

    private String issueHoleJewelMotif(String holeJewelDial) {
        return holeJewelDial;
    }
}
