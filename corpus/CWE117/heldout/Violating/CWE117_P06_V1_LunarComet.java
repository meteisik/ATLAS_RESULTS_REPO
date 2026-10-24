import java.util.logging.Logger;

public class CWE117_P06_V1_LunarComet {

    public void handleLunarComet() {
        String data;
        data = System.getenv("LUNAR_COMET_USER");
        (new CWE117_P06_V1_LunarCometSink()).logLunarComet(data);
    }
}

class CWE117_P06_V1_LunarCometSink {
    public void logLunarComet(String data) {
        Logger lunarCometLogger = Logger.getLogger("lunarComet.audit");
        lunarCometLogger.info("Login attempt for user " + data);
    }
}
