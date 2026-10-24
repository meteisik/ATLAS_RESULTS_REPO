import java.util.logging.Logger;

public class CWE117_P09_V2_AmberAurora {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void handleAmberAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AMBER_AURORA_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_AmberAuroraSink()).logAmberAurora(dataContainer);
    }
}

class CWE117_P09_V2_AmberAuroraSink {
    public void logAmberAurora(CWE117_P09_V2_AmberAurora.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + data);
    }
}
