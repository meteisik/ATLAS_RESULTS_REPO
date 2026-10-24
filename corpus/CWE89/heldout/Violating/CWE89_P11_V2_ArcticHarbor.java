import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runArcticHarbor() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_HARBOR_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticHarborSink()).queryArcticHarbor(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticHarborSink {
    public void queryArcticHarbor(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        Statement arcticHarborStatement = null;
        ResultSet arcticHarborRows = null;
        try {
            arcticHarborStatement = arcticHarborConnection.createStatement();
            arcticHarborRows = arcticHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHarborRows.getRow());
        } finally {
            if (arcticHarborRows != null) {
                arcticHarborRows.close();
            }
            if (arcticHarborStatement != null) {
                arcticHarborStatement.close();
            }
            arcticHarborConnection.close();
        }
    }
}
