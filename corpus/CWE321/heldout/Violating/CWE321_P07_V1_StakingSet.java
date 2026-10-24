import java.security.InvalidKeyException;
import java.util.HashMap;

import javax.crypto.spec.DESedeKeySpec;

public class CWE321_P07_V1_StakingSet {

    public byte[] wrapStakingSet(byte[] stakingSetPayload) throws InvalidKeyException {
        String stakingSetCrest = "k11_stakingset_escapewhe";
        HashMap<Integer, String> stakingSetHamper = new HashMap<>();
        stakingSetHamper.put(3, stakingSetCrest);
        return new CWE321_P07_V1_StakingSetPorter().sealStakingSet(stakingSetHamper, stakingSetPayload);
    }
}

class CWE321_P07_V1_StakingSetPorter {

    byte[] sealStakingSet(HashMap<Integer, String> stakingSetHamper, byte[] stakingSetPayload) throws InvalidKeyException {
        byte[] stakingSetSkein = stakingSetHamper.get(3).getBytes();
        DESedeKeySpec stakingSetSpec = new DESedeKeySpec(stakingSetSkein);
        return stakingSetPayload;
    }
}
