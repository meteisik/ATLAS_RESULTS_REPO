import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PalletForkSafe {

    public SecretKeySpec pressPalletForkSigil(String palletForkDial) {
        String palletForkRubric = palletForkDial;
        return temperPalletFork(palletForkRubric);
    }

    private SecretKeySpec temperPalletFork(String palletForkPacket) {
        byte[] palletForkBraid = palletForkPacket.getBytes();
        return new SecretKeySpec(palletForkBraid, "AES");
    }
}
