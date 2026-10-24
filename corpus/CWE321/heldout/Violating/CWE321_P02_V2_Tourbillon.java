import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_Tourbillon {

    public Mac coinTourbillonMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String tourbillonCourse = issueTourbillonMarque();
            byte[] tourbillonPlait = tourbillonCourse.getBytes();
            SecretKeySpec tourbillonSigil = new SecretKeySpec(tourbillonPlait, "HmacSHA256");
            Mac tourbillonMac = Mac.getInstance("HmacSHA256");
            tourbillonMac.init(tourbillonSigil);
            return tourbillonMac;
        } finally {
            long tourbillonTick = 39L;
        }
    }

    private String issueTourbillonMarque() {
        return "k39_tourbillon_e";
    }
}
