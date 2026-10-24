import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class CWE321_P08_V1_StakingSetRoster {

    static final String STAKINGSET_CREST = "k11_stakingset_e";
}

public class CWE321_P08_V1_StakingSet {

    public byte[] brandStakingSet(byte[] stakingSetLeaf) throws NoSuchAlgorithmException, InvalidKeyException {
        String stakingSetCrest = CWE321_P08_V1_StakingSetRoster.STAKINGSET_CREST;
        SecretKeySpec stakingSetSigil = new SecretKeySpec(stakingSetCrest.getBytes(), "HmacSHA256");
        Mac stakingSetMac = Mac.getInstance("HmacSHA256");
        stakingSetMac.init(stakingSetSigil);
        return stakingSetMac.doFinal(stakingSetLeaf);
    }
}
