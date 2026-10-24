import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAmberQuartz() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberQuartzSafeSink()).queryAmberQuartz(dataHashMap);
    }
}

class CWE89_P11_V2_AmberQuartzSafeSink {
    public void queryAmberQuartz(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        Statement amberQuartzStatement = null;
        ResultSet amberQuartzRows = null;
        try {
            amberQuartzStatement = amberQuartzConnection.createStatement();
            amberQuartzRows = amberQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberQuartzRows.getRow());
        } finally {
            if (amberQuartzRows != null) {
                amberQuartzRows.close();
            }
            if (amberQuartzStatement != null) {
                amberQuartzStatement.close();
            }
            amberQuartzConnection.close();
        }
    }
}
