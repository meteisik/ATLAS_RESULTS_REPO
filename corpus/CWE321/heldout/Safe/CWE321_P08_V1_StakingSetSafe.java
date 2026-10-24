import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_StakingSetSafeRoster {

    static final String STAKINGSET_CREST = mintStakingSetCrest();

    private static String mintStakingSetCrest() {
        byte[] stakingSetGrain = new byte[16];
        new SecureRandom().nextBytes(stakingSetGrain);
        return Base64.getEncoder().encodeToString(stakingSetGrain);
    }
}

public class CWE321_P08_V1_StakingSetSafe {

    public byte[] brandStakingSet(byte[] stakingSetLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String stakingSetCrest = CWE321_P08_V1_StakingSetSafeRoster.STAKINGSET_CREST;
        SecretKeySpec stakingSetSigil = new SecretKeySpec(stakingSetCrest.getBytes(), "HmacSHA256");
        Mac stakingSetMac = Mac.getInstance("HmacSHA256");
        stakingSetMac.init(stakingSetSigil);
        return stakingSetMac.doFinal(stakingSetLeaf);
    }
}
