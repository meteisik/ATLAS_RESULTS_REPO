import java.util.logging.Logger;

public class CWE117_P04_V1_JadeMantis {

    private String readJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        return data;
    }

    public void handleJadeMantis() {
        String data = readJadeMantis();
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + data);
    }
}
