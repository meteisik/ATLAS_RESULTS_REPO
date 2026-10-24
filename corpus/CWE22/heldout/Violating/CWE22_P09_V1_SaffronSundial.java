import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SaffronSundial {

    static class Container {
        public String containerOne;
    }

    public void openSaffronSundial() {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SaffronSundialSink()).readSaffronSundial(dataContainer);
    }
}

class CWE22_P09_V1_SaffronSundialSink {
    public void readSaffronSundial(CWE22_P09_V1_SaffronSundial.Container dataContainer) {
        String data = dataContainer.containerOne;
        String saffronSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronSundialFile = new File(saffronSundialRoot + data);
            FileInputStream saffronSundialStream = null;
            InputStreamReader saffronSundialStreamReader = null;
            BufferedReader saffronSundialReader = null;
            if (saffronSundialFile.exists() && saffronSundialFile.isFile()) {
                try {
                    saffronSundialStream = new FileInputStream(saffronSundialFile);
                    saffronSundialStreamReader = new InputStreamReader(saffronSundialStream, "UTF-8");
                    saffronSundialReader = new BufferedReader(saffronSundialStreamReader);
                    System.out.println(saffronSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_SaffronSundialSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronSundialReader != null) {
                            saffronSundialReader.close();
                        }
                        if (saffronSundialStreamReader != null) {
                            saffronSundialStreamReader.close();
                        }
                        if (saffronSundialStream != null) {
                            saffronSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_SaffronSundialSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
