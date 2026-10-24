import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetSignal {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleVelvetSignal() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_SIGNAL_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetSignalSink()).logVelvetSignal(dataArray);
    }
}

class CWE117_P08_V2_VelvetSignalSink {
    public void logVelvetSignal(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + data);
    }
}
