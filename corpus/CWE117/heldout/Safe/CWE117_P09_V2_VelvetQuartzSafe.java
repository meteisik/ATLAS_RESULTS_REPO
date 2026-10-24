import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetQuartzSafe {
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

    public void handleVelvetQuartz() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_QUARTZ_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetQuartzSafeSink()).logVelvetQuartz(dataContainer);
    }
}

class CWE117_P09_V2_VelvetQuartzSafeSink {
    public void logVelvetQuartz(CWE117_P09_V2_VelvetQuartzSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
