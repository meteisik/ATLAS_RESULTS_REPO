import java.util.logging.Logger;

public class CWE117_P06_V1_LunarCometSafe {

    public void handleLunarComet() {
        String data;
        data = System.getenv("LUNAR_COMET_USER");
        (new CWE117_P06_V1_LunarCometSafeSink()).logLunarComet(data);
    }
}

class CWE117_P06_V1_LunarCometSafeSink {
    public void logLunarComet(String data) {
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
