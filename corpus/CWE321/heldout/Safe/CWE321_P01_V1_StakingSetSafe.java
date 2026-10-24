import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_StakingSetSafe {

    public SecretKeySpec forgeStakingSetSigil(String stakingSetDial) {
        String stakingSetCrest = stakingSetDial;
        byte[] stakingSetSkein = stakingSetCrest.getBytes();
        SecretKeySpec stakingSetSigil = new SecretKeySpec(stakingSetSkein, "AES");
        return stakingSetSigil;
    }
}
