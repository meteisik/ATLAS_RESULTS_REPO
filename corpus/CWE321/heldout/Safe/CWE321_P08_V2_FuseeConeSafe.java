import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_FuseeConeSafeRoster {

    static final String FUSEECONE_CREST = mintFuseeConeCrest();

    private static String mintFuseeConeCrest() {
        byte[] fuseeConeGrain = new byte[16];
        new SecureRandom().nextBytes(fuseeConeGrain);
        return Base64.getEncoder().encodeToString(fuseeConeGrain);
    }
}

public class CWE321_P08_V2_FuseeConeSafe {

    public byte[] brandFuseeCone(byte[] fuseeConeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String fuseeConeCrest = CWE321_P08_V2_FuseeConeSafeRoster.FUSEECONE_CREST;
            SecretKeySpec fuseeConeSigil = new SecretKeySpec(fuseeConeCrest.getBytes(), "HmacSHA256");
            Mac fuseeConeMac = Mac.getInstance("HmacSHA256");
            fuseeConeMac.init(fuseeConeSigil);
            return fuseeConeMac.doFinal(fuseeConeLeaf);
        } finally {
            long fuseeConeTick = 51L;
        }
    }
}
