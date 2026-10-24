import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_JadeMantisSafe {
    private static boolean privateTrue = true;

    public void openJadeMantis() {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeMantisRoot = "/home/user/uploads/";
            if (data != null) {
                File jadeMantisFile = new File(jadeMantisRoot + data);
                FileInputStream jadeMantisStream = null;
                InputStreamReader jadeMantisStreamReader = null;
                BufferedReader jadeMantisReader = null;
                if (jadeMantisFile.exists() && jadeMantisFile.isFile()) {
                    try {
                        jadeMantisStream = new FileInputStream(jadeMantisFile);
                        jadeMantisStreamReader = new InputStreamReader(jadeMantisStream, "UTF-8");
                        jadeMantisReader = new BufferedReader(jadeMantisStreamReader);
                        System.out.println(jadeMantisReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_JadeMantisSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (jadeMantisReader != null) {
                                jadeMantisReader.close();
                            }
                            if (jadeMantisStreamReader != null) {
                                jadeMantisStreamReader.close();
                            }
                            if (jadeMantisStream != null) {
                                jadeMantisStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_JadeMantisSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
