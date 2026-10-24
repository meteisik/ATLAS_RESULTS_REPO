import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticLotus {

    public void runArcticLotus() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_LOTUS_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticLotusSink()).queryArcticLotus(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticLotusSink {
    public void queryArcticLotus(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        Statement arcticLotusStatement = null;
        ResultSet arcticLotusRows = null;
        try {
            arcticLotusStatement = arcticLotusConnection.createStatement();
            arcticLotusRows = arcticLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLotusRows.getRow());
        } finally {
            if (arcticLotusRows != null) {
                arcticLotusRows.close();
            }
            if (arcticLotusStatement != null) {
                arcticLotusStatement.close();
            }
            arcticLotusConnection.close();
        }
    }
}
