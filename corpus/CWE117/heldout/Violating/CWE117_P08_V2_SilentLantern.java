import java.util.logging.Logger;

public class CWE117_P08_V2_SilentLantern {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSilentLantern() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("SILENT_LANTERN_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentLanternSink()).logSilentLantern(dataArray);
    }
}

class CWE117_P08_V2_SilentLanternSink {
    public void logSilentLantern(String[] dataArray) {
        String data = dataArray[2];
        Logger silentLanternLogger = Logger.getLogger("silentLantern.audit");
        silentLanternLogger.info("Login attempt for user " + data);
    }
}
