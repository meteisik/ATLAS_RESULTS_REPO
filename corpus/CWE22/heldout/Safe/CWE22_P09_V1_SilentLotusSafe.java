import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_SilentLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void openSilentLotus() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_SilentLotusSafeSink()).readSilentLotus(dataContainer);
    }
}

class CWE22_P09_V1_SilentLotusSafeSink {
    public void readSilentLotus(CWE22_P09_V1_SilentLotusSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String silentLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File silentLotusFile = new File(silentLotusRoot + data);
            FileInputStream silentLotusStream = null;
            InputStreamReader silentLotusStreamReader = null;
            BufferedReader silentLotusReader = null;
            if (silentLotusFile.exists() && silentLotusFile.isFile()) {
                try {
                    silentLotusStream = new FileInputStream(silentLotusFile);
                    silentLotusStreamReader = new InputStreamReader(silentLotusStream, "UTF-8");
                    silentLotusReader = new BufferedReader(silentLotusStreamReader);
                    System.out.println(silentLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_SilentLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentLotusReader != null) {
                            silentLotusReader.close();
                        }
                        if (silentLotusStreamReader != null) {
                            silentLotusStreamReader.close();
                        }
                        if (silentLotusStream != null) {
                            silentLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_SilentLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
