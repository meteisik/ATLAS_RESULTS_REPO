import java.util.logging.Logger;

public class CWE117_P04_V2_NovaCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readNovaCascade() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("NOVA_CASCADE_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleNovaCascade() {
        String data = readNovaCascade();
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + data);
    }
}
