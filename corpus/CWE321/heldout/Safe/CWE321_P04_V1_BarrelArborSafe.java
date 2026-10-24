import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_BarrelArborSafe {

    public SecretKeySpec punchBarrelArborSigil(String barrelArborDial) {
        String barrelArborCharm = barrelArborDial;
        return temperBarrelArbor(barrelArborCharm);
    }

    private SecretKeySpec temperBarrelArbor(String barrelArborPacket) {
        byte[] barrelArborLace = barrelArborPacket.getBytes();
        return new SecretKeySpec(barrelArborLace, "AES");
    }
}
