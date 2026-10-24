import java.util.logging.Logger;

public class CWE117_P08_V2_VividGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleVividGlint() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VIVID_GLINT_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VividGlintSink()).logVividGlint(dataArray);
    }
}

class CWE117_P08_V2_VividGlintSink {
    public void logVividGlint(String[] dataArray) {
        String data = dataArray[2];
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + data);
    }
}
