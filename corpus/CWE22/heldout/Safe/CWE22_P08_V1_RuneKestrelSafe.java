import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_RuneKestrelSafe {

    public void openRuneKestrel() {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_RuneKestrelSafeSink()).readRuneKestrel(dataArray);
    }
}

class CWE22_P08_V1_RuneKestrelSafeSink {
    public void readRuneKestrel(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V1_RuneKestrelSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V1_RuneKestrelSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
