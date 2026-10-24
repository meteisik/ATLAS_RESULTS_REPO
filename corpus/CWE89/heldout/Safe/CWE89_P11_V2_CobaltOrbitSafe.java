import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_CobaltOrbitSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCobaltOrbit() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_CobaltOrbitSafeSink()).queryCobaltOrbit(dataHashMap);
    }
}

class CWE89_P11_V2_CobaltOrbitSafeSink {
    public void queryCobaltOrbit(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        Statement cobaltOrbitStatement = null;
        ResultSet cobaltOrbitRows = null;
        try {
            cobaltOrbitStatement = cobaltOrbitConnection.createStatement();
            cobaltOrbitRows = cobaltOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltOrbitRows.getRow());
        } finally {
            if (cobaltOrbitRows != null) {
                cobaltOrbitRows.close();
            }
            if (cobaltOrbitStatement != null) {
                cobaltOrbitStatement.close();
            }
            cobaltOrbitConnection.close();
        }
    }
}
