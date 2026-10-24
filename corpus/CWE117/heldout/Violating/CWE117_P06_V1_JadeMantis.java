import java.util.logging.Logger;

public class CWE117_P06_V1_JadeMantis {

    public void handleJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_USER");
        (new CWE117_P06_V1_JadeMantisSink()).logJadeMantis(data);
    }
}

class CWE117_P06_V1_JadeMantisSink {
    public void logJadeMantis(String data) {
        Logger jadeMantisLogger = Logger.getLogger("jadeMantis.audit");
        jadeMantisLogger.info("Login attempt for user " + data);
    }
}
