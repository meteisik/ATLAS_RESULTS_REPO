import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_StakingSetSafe {

    public byte[] wrapStakingSet(byte[] stakingSetPayload, String stakingSetDial) throws InvalidKeyException {
        String stakingSetCrest = stakingSetDial;
        HashMap<Integer, String> stakingSetHamper = new HashMap<>();
        stakingSetHamper.put(3, stakingSetCrest);
        return new CWE321_P07_V1_StakingSetSafePorter().sealStakingSet(stakingSetHamper, stakingSetPayload);
    }
}

class CWE321_P07_V1_StakingSetSafePorter {

    byte[] sealStakingSet(HashMap<Integer, String> stakingSetHamper, byte[] stakingSetPayload) throws InvalidKeyException {
        byte[] stakingSetSkein = stakingSetHamper.get(3).getBytes();
        DESedeKeySpec stakingSetSpec = new DESedeKeySpec(stakingSetSkein);
        return stakingSetPayload;
    }
}
