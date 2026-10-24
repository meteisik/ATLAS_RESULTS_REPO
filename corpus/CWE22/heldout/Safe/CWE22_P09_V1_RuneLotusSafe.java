import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_RuneLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void openRuneLotus() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_RuneLotusSafeSink()).readRuneLotus(dataContainer);
    }
}

class CWE22_P09_V1_RuneLotusSafeSink {
    public void readRuneLotus(CWE22_P09_V1_RuneLotusSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String runeLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File runeLotusFile = new File(runeLotusRoot + data);
            FileInputStream runeLotusStream = null;
            InputStreamReader runeLotusStreamReader = null;
            BufferedReader runeLotusReader = null;
            if (runeLotusFile.exists() && runeLotusFile.isFile()) {
                try {
                    runeLotusStream = new FileInputStream(runeLotusFile);
                    runeLotusStreamReader = new InputStreamReader(runeLotusStream, "UTF-8");
                    runeLotusReader = new BufferedReader(runeLotusStreamReader);
                    System.out.println(runeLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_RuneLotusSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeLotusReader != null) {
                            runeLotusReader.close();
                        }
                        if (runeLotusStreamReader != null) {
                            runeLotusStreamReader.close();
                        }
                        if (runeLotusStream != null) {
                            runeLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_RuneLotusSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
