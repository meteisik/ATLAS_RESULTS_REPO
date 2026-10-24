import java.util.logging.Logger;

public class CWE117_P05_V1_LunarCometSafe {

    private String lunarCometData;

    private void logLunarComet() {
        String data = lunarCometData;
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleLunarComet() {
        String data;
        data = System.getenv("LUNAR_COMET_USER");
        lunarCometData = data;
        logLunarComet();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
