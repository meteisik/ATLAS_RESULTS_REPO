import java.util.logging.Logger;

public class CWE117_P01_V2_LunarComet {
    private static boolean privateReturnsTrue() { return true; }

    public void handleLunarComet() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("LUNAR_COMET_USER");
        } else {
            data = null;
        }
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + data);
    }
}
