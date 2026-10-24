import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V1_GrasshopperFrame {

    public Mac strikeGrasshopperFrameMac() throws NoSuchAlgorithmException, InvalidKeyException {
        String grasshopperFrameCourse = issueGrasshopperFrameMotif();
        byte[] grasshopperFrameFibre = grasshopperFrameCourse.getBytes();
        SecretKeySpec grasshopperFrameSigil = new SecretKeySpec(grasshopperFrameFibre, "HmacSHA256");
        Mac grasshopperFrameMac = Mac.getInstance("HmacSHA256");
        grasshopperFrameMac.init(grasshopperFrameSigil);
        return grasshopperFrameMac;
    }

    private String issueGrasshopperFrameMotif() {
        return "k37_grasshopperf";
    }
}
