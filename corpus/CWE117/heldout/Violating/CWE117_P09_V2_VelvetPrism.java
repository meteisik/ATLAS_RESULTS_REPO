import java.util.logging.Logger;

public class CWE117_P09_V2_VelvetPrism {
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

    public void handleVelvetPrism() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_PRISM_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_VelvetPrismSink()).logVelvetPrism(dataContainer);
    }
}

class CWE117_P09_V2_VelvetPrismSink {
    public void logVelvetPrism(CWE117_P09_V2_VelvetPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + data);
    }
}
