import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetSignalSafe {
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

    public void handleVelvetSignal() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("VELVET_SIGNAL_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetSignalSafeSink()).logVelvetSignal(dataContainer);
    }
}

class CWE117_P09_V2_VelvetSignalSafeSink {
    public void logVelvetSignal(CWE117_P09_V2_VelvetSignalSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
