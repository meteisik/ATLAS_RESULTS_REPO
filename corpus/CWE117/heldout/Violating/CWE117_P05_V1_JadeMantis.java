import java.util.logging.Logger;

public class CWE117_P05_V1_JadeMantis {

    private String jadeMantisData;

    private void logJadeMantis() {
        String data = jadeMantisData;
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + data);
    }

    public void handleJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        jadeMantisData = data;
        logJadeMantis();
    }
}
