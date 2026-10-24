import java.util.logging.Logger;

public class CWE117_P10_V2_AmberMantis {
    private static boolean privateTrue = true;

    public static String data;

    public void handleAmberMantis() {
        if (privateTrue) {
            data = System.getenv("AMBER_MANTIS_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberMantisSink()).logAmberMantis();
    }
}

class CWE117_P10_V2_AmberMantisSink {
    public void logAmberMantis() {
        String data = CWE117_P10_V2_AmberMantis.data;
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + data);
    }
}
