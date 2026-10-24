import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MainspringBarrel {

    public SecretKeySpec pressMainspringBarrelSigil() {
        String mainspringBarrelRubric = "k24_mainspringba";
        return temperMainspringBarrel(mainspringBarrelRubric);
    }

    private SecretKeySpec temperMainspringBarrel(String mainspringBarrelPacket) {
        byte[] mainspringBarrelBraid = mainspringBarrelPacket.getBytes();
        return new SecretKeySpec(mainspringBarrelBraid, "AES");
    }
}
