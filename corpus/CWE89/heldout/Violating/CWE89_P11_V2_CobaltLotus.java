import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CobaltLotus {

    public void runCobaltLotus() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_LOTUS_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CobaltLotusSink()).queryCobaltLotus(dataHashMap);
    }
}

class CWE89_P11_V2_CobaltLotusSink {
    public void queryCobaltLotus(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection cobaltLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLotus");
        Statement cobaltLotusStatement = null;
        ResultSet cobaltLotusRows = null;
        try {
            cobaltLotusStatement = cobaltLotusConnection.createStatement();
            cobaltLotusRows = cobaltLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltLotusRows.getRow());
        } finally {
            if (cobaltLotusRows != null) {
                cobaltLotusRows.close();
            }
            if (cobaltLotusStatement != null) {
                cobaltLotusStatement.close();
            }
            cobaltLotusConnection.close();
        }
    }
}
