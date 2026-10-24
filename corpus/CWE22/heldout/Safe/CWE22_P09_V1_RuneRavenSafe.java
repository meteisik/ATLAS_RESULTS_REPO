import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_RuneRavenSafe {

    static class Container {
        public String containerOne;
    }

    public void openRuneRaven() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_RuneRavenSafeSink()).readRuneRaven(dataContainer);
    }
}

class CWE22_P09_V1_RuneRavenSafeSink {
    public void readRuneRaven(CWE22_P09_V1_RuneRavenSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String runeRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File runeRavenFile = new File(runeRavenRoot + data);
            FileInputStream runeRavenStream = null;
            InputStreamReader runeRavenStreamReader = null;
            BufferedReader runeRavenReader = null;
            if (runeRavenFile.exists() && runeRavenFile.isFile()) {
                try {
                    runeRavenStream = new FileInputStream(runeRavenFile);
                    runeRavenStreamReader = new InputStreamReader(runeRavenStream, "UTF-8");
                    runeRavenReader = new BufferedReader(runeRavenStreamReader);
                    System.out.println(runeRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_RuneRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeRavenReader != null) {
                            runeRavenReader.close();
                        }
                        if (runeRavenStreamReader != null) {
                            runeRavenStreamReader.close();
                        }
                        if (runeRavenStream != null) {
                            runeRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_RuneRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
