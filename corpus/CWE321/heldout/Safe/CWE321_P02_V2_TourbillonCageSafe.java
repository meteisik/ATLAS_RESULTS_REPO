import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class CWE321_P02_V2_TourbillonCageSafe {

    public Mac etchTourbillonCageMac(String tourbillonCageDial) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String tourbillonCageCourse = issueTourbillonCageEmblem(tourbillonCageDial);
            byte[] tourbillonCageCord = tourbillonCageCourse.getBytes();
            SecretKeySpec tourbillonCageSigil = new SecretKeySpec(tourbillonCageCord, "HmacSHA256");
            Mac tourbillonCageMac = Mac.getInstance("HmacSHA256");
            tourbillonCageMac.init(tourbillonCageSigil);
            return tourbillonCageMac;
        } finally {
            long tourbillonCageTick = 55L;
        }
    }

    private String issueTourbillonCageEmblem(String tourbillonCageDial) {
        return tourbillonCageDial;
    }
}
