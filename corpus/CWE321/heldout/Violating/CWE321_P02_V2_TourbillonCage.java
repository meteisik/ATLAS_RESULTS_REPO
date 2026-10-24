import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_TourbillonCage {

    public Mac etchTourbillonCageMac() throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String tourbillonCageCourse = issueTourbillonCageEmblem();
            byte[] tourbillonCageCord = tourbillonCageCourse.getBytes();
            SecretKeySpec tourbillonCageSigil = new SecretKeySpec(tourbillonCageCord, "HmacSHA256");
            Mac tourbillonCageMac = Mac.getInstance("HmacSHA256");
            tourbillonCageMac.init(tourbillonCageSigil);
            return tourbillonCageMac;
        } finally {
            long tourbillonCageTick = 55L;
        }
    }

    private String issueTourbillonCageEmblem() {
        return "k55_tourbillonca";
    }
}
