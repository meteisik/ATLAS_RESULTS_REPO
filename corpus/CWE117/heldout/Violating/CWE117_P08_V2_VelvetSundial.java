import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetSundial {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleVelvetSundial() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_SUNDIAL_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetSundialSink()).logVelvetSundial(dataArray);
    }
}

class CWE117_P08_V2_VelvetSundialSink {
    public void logVelvetSundial(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + data);
    }
}
