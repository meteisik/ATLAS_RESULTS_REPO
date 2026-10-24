import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_StakingSet {

    public SecretKeySpec forgeStakingSetSigil() {
        String stakingSetCrest = "k31_stakingset_e";
        byte[] stakingSetSkein = stakingSetCrest.getBytes();
        SecretKeySpec stakingSetSigil = new SecretKeySpec(stakingSetSkein, "AES");
        return stakingSetSigil;
    }
}
