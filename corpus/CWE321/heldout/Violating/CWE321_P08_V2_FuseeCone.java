import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V2_FuseeConeRoster {

    static final String FUSEECONE_CREST = "k51_fuseecone_es";
}

public class CWE321_P08_V2_FuseeCone {

    public byte[] brandFuseeCone(byte[] fuseeConeLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            String fuseeConeCrest = CWE321_P08_V2_FuseeConeRoster.FUSEECONE_CREST;
            SecretKeySpec fuseeConeSigil = new SecretKeySpec(fuseeConeCrest.getBytes(), "HmacSHA256");
            Mac fuseeConeMac = Mac.getInstance("HmacSHA256");
            fuseeConeMac.init(fuseeConeSigil);
            return fuseeConeMac.doFinal(fuseeConeLeaf);
        } finally {
            long fuseeConeTick = 51L;
        }
    }
}
