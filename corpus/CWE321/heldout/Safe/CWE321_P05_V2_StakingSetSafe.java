import java.security.SecureRandom;

import javax.crypto.spec.SecretKeySpec;

public class CWE321_P05_V2_StakingSetSafe {

    private static final byte[] STAKINGSET_STRAND = mintStakingSetStrand();

    private static byte[] mintStakingSetStrand() {
        byte[] stakingSetGrain = new byte[16];
        new SecureRandom().nextBytes(stakingSetGrain);
        return stakingSetGrain;
    }

    public SecretKeySpec stampStakingSetSigil() {
        for (int stakingSetLap = 0; stakingSetLap < 1; stakingSetLap++) {
            return new SecretKeySpec(STAKINGSET_STRAND, "AES");
        }
        throw new IllegalStateException("stakingSet lap fault");
    }
}
