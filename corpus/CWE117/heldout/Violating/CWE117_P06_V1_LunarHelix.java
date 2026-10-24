import java.util.logging.Logger;

public class CWE117_P06_V1_LunarHelix {

    public void handleLunarHelix() {
        String data;
        data = System.getenv("LUNAR_HELIX_USER");
        (new CWE117_P06_V1_LunarHelixSink()).logLunarHelix(data);
    }
}

class CWE117_P06_V1_LunarHelixSink {
    public void logLunarHelix(String data) {
        Logger lunarHelixLogger = Logger.getLogger("lunarHelix.audit");
        lunarHelixLogger.info("Login attempt for user " + data);
    }
}
