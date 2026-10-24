import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberQuartz {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void openAmberQuartz() {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_QUARTZ_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberQuartzSink()).readAmberQuartz(dataContainer);
    }
}

class CWE22_P09_V2_AmberQuartzSink {
    public void readAmberQuartz(CWE22_P09_V2_AmberQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File amberQuartzFile = new File(amberQuartzRoot + data);
            FileInputStream amberQuartzStream = null;
            InputStreamReader amberQuartzStreamReader = null;
            BufferedReader amberQuartzReader = null;
            if (amberQuartzFile.exists() && amberQuartzFile.isFile()) {
                try {
                    amberQuartzStream = new FileInputStream(amberQuartzFile);
                    amberQuartzStreamReader = new InputStreamReader(amberQuartzStream, "UTF-8");
                    amberQuartzReader = new BufferedReader(amberQuartzStreamReader);
                    System.out.println(amberQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberQuartzReader != null) {
                            amberQuartzReader.close();
                        }
                        if (amberQuartzStreamReader != null) {
                            amberQuartzStreamReader.close();
                        }
                        if (amberQuartzStream != null) {
                            amberQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
