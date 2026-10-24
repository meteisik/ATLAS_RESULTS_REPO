import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_RuneHarbor {

    static class Container {
        public String containerOne;
    }

    public void openRuneHarbor() {
        String data;
        data = System.getenv("RUNE_HARBOR_PATH");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_RuneHarborSink()).readRuneHarbor(dataContainer);
    }
}

class CWE22_P09_V1_RuneHarborSink {
    public void readRuneHarbor(CWE22_P09_V1_RuneHarbor.Container dataContainer) {
        String data = dataContainer.containerOne;
        String runeHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File runeHarborFile = new File(runeHarborRoot + data);
            FileInputStream runeHarborStream = null;
            InputStreamReader runeHarborStreamReader = null;
            BufferedReader runeHarborReader = null;
            if (runeHarborFile.exists() && runeHarborFile.isFile()) {
                try {
                    runeHarborStream = new FileInputStream(runeHarborFile);
                    runeHarborStreamReader = new InputStreamReader(runeHarborStream, "UTF-8");
                    runeHarborReader = new BufferedReader(runeHarborStreamReader);
                    System.out.println(runeHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_RuneHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeHarborReader != null) {
                            runeHarborReader.close();
                        }
                        if (runeHarborStreamReader != null) {
                            runeHarborStreamReader.close();
                        }
                        if (runeHarborStream != null) {
                            runeHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_RuneHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
