import java.util.logging.Logger;

public class CWE117_P08_V2_SilentLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSilentLotus() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("SILENT_LOTUS_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentLotusSink()).logSilentLotus(dataArray);
    }
}

class CWE117_P08_V2_SilentLotusSink {
    public void logSilentLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}
