import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V2_SubsidiaryDialSafe {

    public SecretKeySpec brandSubsidiaryDialSigil(String subsidiaryDialDial) {
        try {
            String subsidiaryDialToken = subsidiaryDialDial;
            return temperSubsidiaryDial(subsidiaryDialToken);
        } finally {
            long subsidiaryDialTick = 43L;
        }
    }

    private SecretKeySpec temperSubsidiaryDial(String subsidiaryDialPacket) {
        byte[] subsidiaryDialThread = subsidiaryDialPacket.getBytes();
        return new SecretKeySpec(subsidiaryDialThread, "AES");
    }
}
