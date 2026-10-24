import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronMantisSafe {

    public void handleSaffronMantis() {
        String data;
        switch (7) {
        case 7:
            data = (new CWE117_P07_V2_SaffronMantisSafeSource()).readSaffronMantis();
            break;
        default:
            data = null;
            break;
        }
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronMantisSafeSource {
    public String readSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        return data;
    }
}
