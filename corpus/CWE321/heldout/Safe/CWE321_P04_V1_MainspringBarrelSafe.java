import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MainspringBarrelSafe {

    public SecretKeySpec pressMainspringBarrelSigil(String mainspringBarrelDial) {
        String mainspringBarrelRubric = mainspringBarrelDial;
        return temperMainspringBarrel(mainspringBarrelRubric);
    }

    private SecretKeySpec temperMainspringBarrel(String mainspringBarrelPacket) {
        byte[] mainspringBarrelBraid = mainspringBarrelPacket.getBytes();
        return new SecretKeySpec(mainspringBarrelBraid, "AES");
    }
}
