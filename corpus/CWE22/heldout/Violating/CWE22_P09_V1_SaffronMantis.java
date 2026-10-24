import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SaffronMantis {

    static class Container {
        public String containerOne;
    }

    public void openSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SaffronMantisSink()).readSaffronMantis(dataContainer);
    }
}

class CWE22_P09_V1_SaffronMantisSink {
    public void readSaffronMantis(CWE22_P09_V1_SaffronMantis.Container dataContainer) {
        String data = dataContainer.containerOne;
        String saffronMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronMantisFile = new File(saffronMantisRoot + data);
            FileInputStream saffronMantisStream = null;
            InputStreamReader saffronMantisStreamReader = null;
            BufferedReader saffronMantisReader = null;
            if (saffronMantisFile.exists() && saffronMantisFile.isFile()) {
                try {
                    saffronMantisStream = new FileInputStream(saffronMantisFile);
                    saffronMantisStreamReader = new InputStreamReader(saffronMantisStream, "UTF-8");
                    saffronMantisReader = new BufferedReader(saffronMantisStreamReader);
                    System.out.println(saffronMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_SaffronMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronMantisReader != null) {
                            saffronMantisReader.close();
                        }
                        if (saffronMantisStreamReader != null) {
                            saffronMantisStreamReader.close();
                        }
                        if (saffronMantisStream != null) {
                            saffronMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_SaffronMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
