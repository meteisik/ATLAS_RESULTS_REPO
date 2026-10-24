import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronQuartzSafe {

    public void handleSaffronQuartz() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = (new CWE117_P07_V2_SaffronQuartzSafeSource()).readSaffronQuartz();
        }
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronQuartzSafeSource {
    public String readSaffronQuartz() {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_USER");
        return data;
    }
}
