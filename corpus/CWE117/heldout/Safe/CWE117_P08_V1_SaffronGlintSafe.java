import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronGlintSafe {

    public void handleSaffronGlint() {
        String data;
        data = System.getenv("SAFFRON_GLINT_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronGlintSafeSink()).logSaffronGlint(dataArray);
    }
}

class CWE117_P08_V1_SaffronGlintSafeSink {
    public void logSaffronGlint(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
