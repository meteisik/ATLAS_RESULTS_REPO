import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadeMantis {

    public void openJadeMantis() {
        String data;
        data = System.getenv("JADE_MANTIS_PATH");
        (new CWE22_P06_V1_JadeMantisSink()).readJadeMantis(data);
    }
}

class CWE22_P06_V1_JadeMantisSink {
    public void readJadeMantis(String data) {
        String jadeMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeMantisFile = new File(jadeMantisRoot + data);
            FileInputStream jadeMantisStream = null;
            InputStreamReader jadeMantisStreamReader = null;
            BufferedReader jadeMantisReader = null;
            if (jadeMantisFile.exists() && jadeMantisFile.isFile()) {
                try {
                    jadeMantisStream = new FileInputStream(jadeMantisFile);
                    jadeMantisStreamReader = new InputStreamReader(jadeMantisStream, "UTF-8");
                    jadeMantisReader = new BufferedReader(jadeMantisStreamReader);
                    System.out.println(jadeMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_JadeMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeMantisReader != null) {
                            jadeMantisReader.close();
                        }
                        if (jadeMantisStreamReader != null) {
                            jadeMantisStreamReader.close();
                        }
                        if (jadeMantisStream != null) {
                            jadeMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_JadeMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
