import java.util.logging.Logger;

public class CWE117_P04_V1_LunarComet {

    private String readLunarComet() {
        String data;
        data = System.getenv("LUNAR_COMET_USER");
        return data;
    }

    public void handleLunarComet() {
        String data = readLunarComet();
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + data);
    }
}
