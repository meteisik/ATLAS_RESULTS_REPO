import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GrasshopperFrameSafe {

    public Mac strikeGrasshopperFrameMac(String grasshopperFrameDial) throws NoSuchAlgorithmException, InvalidKeyException {
        String grasshopperFrameCourse = issueGrasshopperFrameMotif(grasshopperFrameDial);
        byte[] grasshopperFrameFibre = grasshopperFrameCourse.getBytes();
        SecretKeySpec grasshopperFrameSigil = new SecretKeySpec(grasshopperFrameFibre, "HmacSHA256");
        Mac grasshopperFrameMac = Mac.getInstance("HmacSHA256");
        grasshopperFrameMac.init(grasshopperFrameSigil);
        return grasshopperFrameMac;
    }

    private String issueGrasshopperFrameMotif(String grasshopperFrameDial) {
        return grasshopperFrameDial;
    }
}
