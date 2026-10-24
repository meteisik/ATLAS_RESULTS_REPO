import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CobaltLantern {

    public void runCobaltLantern() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("COBALT_LANTERN_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CobaltLanternSink()).queryCobaltLantern(dataHashMap);
    }
}

class CWE89_P11_V2_CobaltLanternSink {
    public void queryCobaltLantern(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection cobaltLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLantern");
        Statement cobaltLanternStatement = null;
        ResultSet cobaltLanternRows = null;
        try {
            cobaltLanternStatement = cobaltLanternConnection.createStatement();
            cobaltLanternRows = cobaltLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltLanternRows.getRow());
        } finally {
            if (cobaltLanternRows != null) {
                cobaltLanternRows.close();
            }
            if (cobaltLanternStatement != null) {
                cobaltLanternStatement.close();
            }
            cobaltLanternConnection.close();
        }
    }
}
