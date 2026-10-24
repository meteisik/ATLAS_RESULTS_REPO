import java.util.logging.Logger;

public class CWE117_P02_V2_JadeMantis {
    private static boolean privateTrue = true;

    public void handleJadeMantis() {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("JADE_MANTIS_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
            jadeMantisLogger.info("Login attempt for user " + data);
        }
    }
}
