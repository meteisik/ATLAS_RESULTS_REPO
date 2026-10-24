import java.util.logging.Logger;

public class CWE117_P09_V2_VividAurora {
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

    public void handleVividAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("VIVID_AURORA_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VividAuroraSink()).logVividAurora(dataContainer);
    }
}

class CWE117_P09_V2_VividAuroraSink {
    public void logVividAurora(CWE117_P09_V2_VividAurora.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + data);
    }
}
