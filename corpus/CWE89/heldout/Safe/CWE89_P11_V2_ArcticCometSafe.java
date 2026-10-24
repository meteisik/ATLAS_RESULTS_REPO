import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runArcticComet() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticCometSafeSink()).queryArcticComet(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticCometSafeSink {
    public void queryArcticComet(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        Statement arcticCometStatement = null;
        ResultSet arcticCometRows = null;
        try {
            arcticCometStatement = arcticCometConnection.createStatement();
            arcticCometRows = arcticCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticCometRows.getRow());
        } finally {
            if (arcticCometRows != null) {
                arcticCometRows.close();
            }
            if (arcticCometStatement != null) {
                arcticCometStatement.close();
            }
            arcticCometConnection.close();
        }
    }
}
