import java.util.logging.Logger;

public class CWE117_P04_V2_NovaAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readNovaAurora() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_AURORA_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleNovaAurora() {
        String data = readNovaAurora();
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
