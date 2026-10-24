import java.util.logging.Logger;

public class CWE117_P03_V2_NovaAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logNovaAurora(String data) {
        Logger novaAuroraLogger = Logger.getLogger("novaAurora.audit");
        novaAuroraLogger.info("Login attempt for user " + data);
    }

    public void handleNovaAurora() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("NOVA_AURORA_USER");
        } else {
            data = null;
        }
        logNovaAurora(data);
    }
}
