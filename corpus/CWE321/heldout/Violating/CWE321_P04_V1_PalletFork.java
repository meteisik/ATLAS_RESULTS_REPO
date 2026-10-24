import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_PalletFork {

    public SecretKeySpec pressPalletForkSigil() {
        String palletForkRubric = "k34_palletfork_e";
        return temperPalletFork(palletForkRubric);
    }

    private SecretKeySpec temperPalletFork(String palletForkPacket) {
        byte[] palletForkBraid = palletForkPacket.getBytes();
        return new SecretKeySpec(palletForkBraid, "AES");
    }
}
