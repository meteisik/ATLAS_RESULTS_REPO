import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticLantern {

    public void runArcticLantern() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_LANTERN_FILTER");
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticLanternSink()).queryArcticLantern(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticLanternSink {
    public void queryArcticLantern(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        Statement arcticLanternStatement = null;
        ResultSet arcticLanternRows = null;
        try {
            arcticLanternStatement = arcticLanternConnection.createStatement();
            arcticLanternRows = arcticLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLanternRows.getRow());
        } finally {
            if (arcticLanternRows != null) {
                arcticLanternRows.close();
            }
            if (arcticLanternStatement != null) {
                arcticLanternStatement.close();
            }
            arcticLanternConnection.close();
        }
    }
}
