import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronMantis {

    public static String data;

    public void handleSaffronMantis() {
        data = System.getenv("SAFFRON_MANTIS_USER");
        (new CWE117_P10_V1_SaffronMantisSink()).logSaffronMantis();
    }
}

class CWE117_P10_V1_SaffronMantisSink {
    public void logSaffronMantis() {
        String data = CWE117_P10_V1_SaffronMantis.data;
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + data);
    }
}
