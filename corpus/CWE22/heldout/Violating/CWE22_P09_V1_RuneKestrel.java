import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_RuneKestrel {

    static class Container {
        public String containerOne;
    }

    public void openRuneKestrel() {
        String data;
        data = System.getenv("RUNE_KESTREL_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_RuneKestrelSink()).readRuneKestrel(dataContainer);
    }
}

class CWE22_P09_V1_RuneKestrelSink {
    public void readRuneKestrel(CWE22_P09_V1_RuneKestrel.Container dataContainer) {
        String data = dataContainer.containerOne;
        String runeKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File runeKestrelFile = new File(runeKestrelRoot + data);
            FileInputStream runeKestrelStream = null;
            InputStreamReader runeKestrelStreamReader = null;
            BufferedReader runeKestrelReader = null;
            if (runeKestrelFile.exists() && runeKestrelFile.isFile()) {
                try {
                    runeKestrelStream = new FileInputStream(runeKestrelFile);
                    runeKestrelStreamReader = new InputStreamReader(runeKestrelStream, "UTF-8");
                    runeKestrelReader = new BufferedReader(runeKestrelStreamReader);
                    System.out.println(runeKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_RuneKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeKestrelReader != null) {
                            runeKestrelReader.close();
                        }
                        if (runeKestrelStreamReader != null) {
                            runeKestrelStreamReader.close();
                        }
                        if (runeKestrelStream != null) {
                            runeKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_RuneKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
