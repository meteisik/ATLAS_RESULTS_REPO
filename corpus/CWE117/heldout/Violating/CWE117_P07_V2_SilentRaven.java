import java.util.logging.Logger;

public class CWE117_P07_V2_SilentRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void handleSilentRaven() {
        String data;
        if (IO.staticTrue) {
            data = (new CWE117_P07_V2_SilentRavenSource()).readSilentRaven();
        } else {
            data = null;
        }
        Logger silentRavenLogger = Logger.getLogger("silentRaven.audit");
        silentRavenLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentRavenSource {
    public String readSilentRaven() {
        String data;
        data = System.getenv("SILENT_RAVEN_USER");
        return data;
    }
}
