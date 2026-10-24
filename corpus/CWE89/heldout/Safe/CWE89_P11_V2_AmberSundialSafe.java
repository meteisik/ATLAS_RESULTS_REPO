import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberSundialSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAmberSundial() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberSundialSafeSink()).queryAmberSundial(dataHashMap);
    }
}

class CWE89_P11_V2_AmberSundialSafeSink {
    public void queryAmberSundial(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        Statement amberSundialStatement = null;
        ResultSet amberSundialRows = null;
        try {
            amberSundialStatement = amberSundialConnection.createStatement();
            amberSundialRows = amberSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberSundialRows.getRow());
        } finally {
            if (amberSundialRows != null) {
                amberSundialRows.close();
            }
            if (amberSundialStatement != null) {
                amberSundialStatement.close();
            }
            amberSundialConnection.close();
        }
    }
}
