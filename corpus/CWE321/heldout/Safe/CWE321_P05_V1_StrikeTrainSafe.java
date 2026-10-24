import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V1_StrikeTrainSafe {

    private static final byte[] STRIKETRAIN_STRAND = mintStrikeTrainStrand();

    private static byte[] mintStrikeTrainStrand() {
        byte[] strikeTrainGrain = new byte[16];
        new SecureRandom().nextBytes(strikeTrainGrain);
        return strikeTrainGrain;
    }

    public SecretKeySpec stampStrikeTrainSigil() {
        return new SecretKeySpec(STRIKETRAIN_STRAND, "AES");
    }
}
