import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberCascade {

    static class Container {
        public String containerOne;
    }

    public void openAmberCascade() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AMBER_CASCADE_PATH");
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberCascadeSink()).readAmberCascade(dataContainer);
    }
}

class CWE22_P09_V2_AmberCascadeSink {
    public void readAmberCascade(CWE22_P09_V2_AmberCascade.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File amberCascadeFile = new File(amberCascadeRoot + data);
            FileInputStream amberCascadeStream = null;
            InputStreamReader amberCascadeStreamReader = null;
            BufferedReader amberCascadeReader = null;
            if (amberCascadeFile.exists() && amberCascadeFile.isFile()) {
                try {
                    amberCascadeStream = new FileInputStream(amberCascadeFile);
                    amberCascadeStreamReader = new InputStreamReader(amberCascadeStream, "UTF-8");
                    amberCascadeReader = new BufferedReader(amberCascadeStreamReader);
                    System.out.println(amberCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberCascadeReader != null) {
                            amberCascadeReader.close();
                        }
                        if (amberCascadeStreamReader != null) {
                            amberCascadeStreamReader.close();
                        }
                        if (amberCascadeStream != null) {
                            amberCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
